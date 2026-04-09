package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// 定义全局版本号变量（默认值设为 dev，编译时会被覆盖）
var Version = "dev"

func main() {
	// 确保用户输入了子命令
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// 根据子命令分发逻辑
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("未知的子命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("使用方法: h2tunnel <子命令> [参数]")
	fmt.Println("\n子命令:")
	fmt.Println("  server    启动 HTTP/2 隧道服务端")
	fmt.Println("  client    启动 HTTP/2 隧道客户端")
	fmt.Println("  version   查看当前版本号")
	fmt.Println("\n示例:")
	fmt.Println("  h2tunnel server -h")
	fmt.Println("  h2tunnel client -h")
}

// ==========================================
// 服务端逻辑 (Server)
// ==========================================
func runServer(args []string) {
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := serverCmd.String("listen", ":8443", "服务端监听地址 (如 :8443 或 0.0.0.0:8443)")
	tlsCert := serverCmd.String("cert", "", "TLS 证书文件路径 (为空则启动 h2c 明文模式)")
	tlsKey := serverCmd.String("key", "", "TLS 私钥文件路径")
	path := serverCmd.String("path", "/tunnel", "代理路径，需与客户端一致")
	allowLocal := serverCmd.Bool("local-only", true, "安全选项：是否只允许转发到服务端的 127.0.0.1 (强烈建议开启)")

	serverCmd.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		tunnelHandler(w, r, *allowLocal)
	})

	if *tlsCert != "" && *tlsKey != "" {
		server := &http.Server{
			Addr:    *listenAddr,
			Handler: mux,
		}
		log.Printf("[H2 Server] 🟢 启动标准 HTTP/2 隧道 (TLS 加密), 监听: %s, 路径: %s\n", *listenAddr, *path)
		log.Fatal(server.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		h2s := &http2.Server{}
		server := &http.Server{
			Addr:    *listenAddr,
			Handler: h2c.NewHandler(mux, h2s),
		}
		log.Printf("[H2C Server] 🟡 启动明文 HTTP/2 隧道 (无加密), 监听: %s, 路径: %s\n", *listenAddr, *path)
		log.Printf("[H2C Server] ⚠️ 警告：明文传输通常仅用于配合 Nginx 等前置反代使用\n")
		log.Fatal(server.ListenAndServe())
	}
}

// tunnelHandler 处理核心的隧道转发逻辑
func tunnelHandler(w http.ResponseWriter, r *http.Request, allowLocal bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.Header.Get("X-Target")
	if target == "" {
		http.Error(w, "Missing X-Target header", http.StatusBadRequest)
		return
	}

	// 安全限制
	if allowLocal && !strings.HasPrefix(target, "127.0.0.1:") && !strings.HasPrefix(target, "localhost:") {
		log.Printf("[Reject] 拒绝连接到非本地目标: %s\n", target)
		http.Error(w, "Target forbidden", http.StatusForbidden)
		return
	}

	log.Printf("[Connect] 收到隧道请求 -> 目标: %s\n", target)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[Error] 拨号目标 %s 失败: %v\n", target, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Println("[Error] 客户端/中间件不支持 HTTP 流式传输")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					errChan <- writeErr
					return
				}
				flusher.Flush()
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		_, err := io.Copy(targetConn, r.Body)
		errChan <- err
	}()

	<-errChan
	log.Printf("[Disconnect] 隧道已释放 -> 目标: %s\n", target)
}
// ==========================================
// 客户端逻辑 (Client)
// ==========================================
func runClient(args []string) {
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := clientCmd.String("listen", "127.0.0.1:2222", "本地监听的 TCP 地址 (如 127.0.0.1:2222)")
	serverUrl := clientCmd.String("server", "http://127.0.0.1:8443", "远端 H2/H2C 服务端 URL (需携带 http:// 或 https://)")
	path := clientCmd.String("path", "/tunnel", "请求路径，需与服务端一致")
	targetAddr := clientCmd.String("target", "127.0.0.1:22", "要求远端服务器代理访问的最终目标 TCP 地址")
	insecure := clientCmd.Bool("insecure", true, "是否跳过 TLS 证书校验 (适用于自签证书)")
	
	// 🌟 新增：支持自定义 SNI 和 Host
	customHost := clientCmd.String("host", "", "自定义伪装的 SNI / Host 域名 (用于突破 CDN 或前置反代)")

	clientCmd.Parse(args)

	// 处理完整的请求 URL
	reqUrl := strings.TrimRight(*serverUrl, "/") + *path
	isHTTPS := strings.HasPrefix(reqUrl, "https://")

	// 定制 HTTP/2 Transport
	transport := &http2.Transport{}
	if isHTTPS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: *insecure,
		}
		// 🌟 核心：如果在命令行指定了 host，则覆盖 TLS 握手时的 SNI
		if *customHost != "" {
			tlsConfig.ServerName = *customHost
		}
		transport.TLSClientConfig = tlsConfig
	} else {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	httpClient := &http.Client{Transport: transport}

	// 启动本地 TCP 监听
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("[Client Error] 无法监听本地端口 %s: %v\n", *listenAddr, err)
	}
	defer listener.Close()

	log.Printf("[Client] 🚀 客户端已启动，监听本地: %s\n", *listenAddr)
	log.Printf("[Client] 🔗 隧道目标: %s\n", reqUrl)
	log.Printf("[Client] 🎯 最终目标: %s\n", *targetAddr)
	if *customHost != "" {
		log.Printf("[Client] 🎭 伪装 Host/SNI: %s\n", *customHost)
	}

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("[Client Error] 接收连接失败: %v\n", err)
			continue
		}
		go handleClientConn(localConn, httpClient, reqUrl, *targetAddr, *customHost)
	}
}

func handleClientConn(localConn net.Conn, httpClient *http.Client, reqUrl string, target string, customHost string) {
	defer localConn.Close()
	log.Printf("[Client] 🟢 接收到本地连接，正在打通隧道...\n")

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
	if err != nil {
		log.Printf("[Client Error] 创建请求失败: %v\n", err)
		return
	}

	// 🌟 核心：强制修改 HTTP/2 请求的 Host 头部
	if customHost != "" {
		req.Host = customHost
	}

	// 设定伪装 UA，并传递目标路由信息
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("X-Target", target)

	// 上行链路：Local TCP -> Pipe -> HTTP Request Body
	go func() {
		io.Copy(pw, localConn)
		pw.Close() // TCP 端断开时，关闭 Pipe 写入端，通知服务端 EOF
	}()

	// 发起 HTTP/2 请求
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[Client Error] 隧道请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Client Error] 服务端拒绝连接, 状态码: %d\n", resp.StatusCode)
		return
	}

	log.Printf("[Client] ✅ 隧道已建立，开始传输数据\n")

	// 下行链路：HTTP Response Body -> Local TCP
	io.Copy(localConn, resp.Body)
	log.Printf("[Client] 🔴 隧道连接已断开\n")
}