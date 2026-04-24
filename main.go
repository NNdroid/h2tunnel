package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Version = "dev"
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

type ServerConfig struct {
	ListenAddr    string
	TLSCert       string
	TLSKey        string
	Path          string
	LocalOnly     bool
	LogLevel      string
	EnableH3      bool
	ExpectedToken string
}

type ClientConfig struct {
	ListenAddr string
	ServerUrl  string
	Path       string
	TargetAddr string
	Insecure   bool
	CustomHost string
	ServerName string
	UseH3      bool
	UseWT      bool
	UseMasque  bool
	UseUDP     bool
	UseGRPC    bool
	LogLevel   string
	Token      string
}

func initLogger(levelStr string) {
	var level zapcore.Level
	switch strings.ToLower(levelStr) {
	case "fatal": level = zapcore.FatalLevel
	case "debug": level = zapcore.DebugLevel
	case "info":  level = zapcore.InfoLevel
	case "warn":  level = zapcore.WarnLevel
	case "error": level = zapcore.ErrorLevel
	default:      level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)
	zlog = zap.New(core).Sugar()
}

// proxyStream 稳健的双向代理引擎
func proxyStream(sessionID string, network string, targetConn net.Conn, tunnelReader io.Reader, tunnelWriter io.Writer, flusher http.Flusher) {
	zlog.Debugf("[%s] 🔄 代理引擎启动 | Network: %s | 目标地址: %s", sessionID, network, targetConn.RemoteAddr())

	// 处理两种 UDP 模式
	if network == "udp" || network == "masque-udp" {
		errChan := make(chan error, 2)
		
		// 1. 目标 -> 隧道 (Downstream)
		go func() {
			var txBytes int64
			// 从池子里借一块 64KB 内存
			bufPtr := udpBufPool.Get().(*[]byte)
			buf := *bufPtr
			defer udpBufPool.Put(bufPtr) // 用完还回去
			for {
				n, err := targetConn.Read(buf)
				if n > 0 {
					txBytes += int64(n)
					var errW error
					// 根据协议类型选择不同的封包方式
					if network == "masque-udp" {
						errW = writeUDPCapsule(tunnelWriter, buf[:n])
					} else {
						errW = writeUDPPacket(tunnelWriter, buf[:n])
					}
					
					if errW != nil {
						zlog.Errorf("[%s] ❌ [%s 目标->隧道] 写入失败: %v", sessionID, network, errW)
						errChan <- errW
						return
					}
					if flusher != nil { flusher.Flush() }
				}
				if err != nil {
					zlog.Debugf("[%s] 🏁 [%s 目标->隧道] 读取结束: %v (共下发 %d bytes)", sessionID, network, err, txBytes)
					errChan <- err
					return
				}
			}
		}()
		
		// 2. 隧道 -> 目标 (Upstream)
		go func() {
			var rxBytes int64
			// 从池子里借一块 64KB 内存
			bufPtr := udpBufPool.Get().(*[]byte)
			buf := *bufPtr
			defer udpBufPool.Put(bufPtr) // 用完还回去
			for {
				var n int
				var err error
				// 根据协议类型选择不同的解包方式
				if network == "masque-udp" {
					n, err = readUDPCapsule(tunnelReader, buf)
				} else {
					n, err = readUDPPacket(tunnelReader, buf)
				}

				if err != nil {
					zlog.Debugf("[%s] 🏁 [%s 隧道->目标] 读取结束: %v (共上传 %d bytes)", sessionID, network, err, rxBytes)
					errChan <- err
					return
				}
				rxBytes += int64(n)
				if _, errW := targetConn.Write(buf[:n]); errW != nil {
					zlog.Errorf("[%s] ❌ [%s 隧道->目标] 写入目标失败: %v", sessionID, network, errW)
					errChan <- errW
					return
				}
			}
		}()
		
		err := <-errChan
		zlog.Infof("[%s] ⏹️ %s 代理生命周期结束: %v", sessionID, strings.ToUpper(network), err)

	} else {
		// 启用padding
		tunnelReader := &PaddingReader{r: tunnelReader}
		tunnelWriter := &PaddingWriter{w: tunnelWriter}
		// TCP 模式：引入 WaitGroup 保证双向生命周期完整
		var wg sync.WaitGroup
		wg.Add(2)

		// 1. 目标 -> 隧道 (Downstream / 下行)
		go func() {
			defer wg.Done()
			bufPtr := tcpBufPool.Get().(*[]byte)
			buf := *bufPtr
			defer tcpBufPool.Put(bufPtr)
			var nTotal int64
			
			// ⚠️ 弃用 io.Copy，手写循环以保证每次读取后立刻 Flush!
			for {
				n, err := targetConn.Read(buf)
				if n > 0 {
					nTotal += int64(n)
					_, errW := tunnelWriter.Write(buf[:n])
					if flusher != nil { flusher.Flush() } // 关键修复：立刻把数据推给客户端！
					if errW != nil {
						zlog.Warnf("[%s] ❌ [TCP 目标->隧道] 写入 HTTP 流失败: %v", sessionID, errW)
						break
					}
				}
				if err != nil {
					if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
						zlog.Warnf("[%s] ⚠️ [TCP 目标->隧道] 异常断开: %v (共下发 %d bytes)", sessionID, err, nTotal)
					} else {
						zlog.Debugf("[%s] ⬇️ [TCP 目标->隧道] 传输完成 (共下发 %d bytes)", sessionID, nTotal)
					}
					break
				}
			}
			
			// 下行结束（目标断开或网络错误），强行切断目标连接，防止上行死锁
			targetConn.Close()
		}()

		// 2. 隧道 -> 目标 (Upstream / 上行)
		go func() {
			defer wg.Done()
			n, err := io.Copy(targetConn, tunnelReader)
			
			if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				zlog.Warnf("[%s] ⚠️ [TCP 隧道->目标] 异常断开: %v (共上传 %d bytes)", sessionID, err, n)
				targetConn.Close() // 异常断开，全关
			} else {
				zlog.Debugf("[%s] ⬆️ [TCP 隧道->目标] 传输完成 (共上传 %d bytes)", sessionID, n)
				
				// 客户端主动发完数据（如 DNS 41 bytes 请求），触发半关闭
				if tc, ok := targetConn.(*net.TCPConn); ok {
					zlog.Debugf("[%s] 🔌 触发 TCP CloseWrite", sessionID)
					tc.CloseWrite()
				} else if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
					zlog.Debugf("[%s] 🔌 触发通用 CloseWrite", sessionID)
					cw.CloseWrite()
				}
			}
		}()

		// ⚠️ 必须等上下行协程全部退出，当前代理生命周期才算真正结束！
		wg.Wait()
		zlog.Infof("[%s] ⏹️ TCP 代理生命周期正常结束", sessionID)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "server": runServer(os.Args[2:])
	case "client": runClient(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("未知子命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("使用方法: h2tunnel <子命令> [参数]")
	fmt.Println("\n子命令:")
	fmt.Println("  server    启动隧道服务端")
	fmt.Println("  client    启动隧道客户端")
	fmt.Println("  version   查看当前版本号")
}