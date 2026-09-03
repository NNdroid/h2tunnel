package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// =========================================
// 客户端 UDP 会话恢复（datagram resume）
//
// 与 executeResumableTunnel（stream/TCP）的差异：
//   - UDP 是数据报模型，不做 seq 重放。断线重拨同 session id 的 HTTP 流
//     后，服务端复用同一个 UDP socket（tunnelSession.datagram=true），
//     新流上继续收发后续 UDP 包，已发出/已收到的包不重放。
//   - 上行：本地 UDP 包经 frameW（writeUDPPacket / writeUDPCapsule）
//     封装成 wire 帧写入流 body。
//   - 下行：从流 body 用 frameR 解出 UDP 包写回本地 UDP socket。
//   - 流断（读错误/写失败）不结束会话，回到外层 attempts 循环用
//     同一 session id 重拨。
// =========================================

const (
	udpResumeMaxAttempts = 16              // 单次 UDP 会话生命周期内的最大重建次数
	udpResumeBackoffMax  = 5 * time.Second // 重建 backoff 上限
)

// udpSession 一个逻辑 UDP 会话：承载某个 clientAddr → 目标 UDP 地址的转发。
// 上行数据经 upstream 通道灌入当前活跃流的 write goroutine；
// 下行由读循环解出写回本地 UDP socket。流断后重建，会话不中断。
type udpSession struct {
	sessionID  string
	cfg        ClientConfig
	reqUrl     string
	httpClient *http.Client
	localConn  *net.UDPConn
	clientAddr *net.UDPAddr

	// 数据面封装：masque-udp 用 capsule，其余用 datagram packet。
	frameW func(io.Writer, []byte) error
	frameR func(io.Reader, []byte) (int, error)

	// upstream 上行队列：本地 UDP 收包协程放入，流写协程消费。
	upstream chan []byte
	// done 关闭时通知当前流的读写循环退出（会话结束）。
	done     chan struct{}
	doneOnce sync.Once
}

// newUDPSession 为单个 UDP clientAddr 建立逻辑会话并启动断线续传循环。
func newUDPSession(sessionID string, cfg ClientConfig, reqUrl string, httpClient *http.Client, localConn *net.UDPConn, clientAddr *net.UDPAddr) *udpSession {
	s := &udpSession{
		sessionID:  sessionID,
		cfg:        cfg,
		reqUrl:     reqUrl,
		httpClient: httpClient,
		localConn:  localConn,
		clientAddr: clientAddr,
		upstream:   make(chan []byte, 200),
		done:       make(chan struct{}),
	}
	if cfg.usesMasque() {
		s.frameW = writeUDPCapsule
		s.frameR = readUDPCapsule
	} else {
		s.frameW = writeUDPPacket
		s.frameR = readUDPPacket
	}
	return s
}

func (s *udpSession) close() {
	s.doneOnce.Do(func() { close(s.done) })
}

// enqueue 把本地 UDP 收到的包入上行队列；会话已结束则丢弃。
func (s *udpSession) enqueue(pkt []byte) {
	select {
	case <-s.done:
		return
	case s.upstream <- pkt:
	default:
		zlog.Warnf("[UDP-Resume:%s] 上行队列溢出，丢弃来自 %s 的包", s.sessionID, s.clientAddr)
	}
}

// run 启动会话主循环：持续建流 → 续传，直到本地 socket 关闭或超过最大重试。
func (s *udpSession) run() {
	defer s.close()
	for attempt := 1; attempt <= udpResumeMaxAttempts; attempt++ {
		if s.isDone() {
			return
		}
		err := s.runOneStream()
		if err == nil {
			return // 正常结束（对端关闭）
		}
		if s.isDone() {
			return
		}
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > udpResumeBackoffMax {
			delay = udpResumeBackoffMax
		}
		zlog.Infof("[UDP-Resume:%s] 🔁 流断，第 %d 次重拨（同 session 续传），等待 %v: %v",
			s.sessionID, attempt, delay, err)
		select {
		case <-s.done:
			return
		case <-time.After(delay):
		}
	}
	zlog.Warnf("[UDP-Resume:%s] 超过最大重试次数 (%d)，会话终止", s.sessionID, udpResumeMaxAttempts)
}

func (s *udpSession) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// runOneStream 建立一条 HTTP 流并在其上续传。返回 nil 表示正常结束；
// 返回 err 表示流中断（应重拨）。
func (s *udpSession) runOneStream() error {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := buildResumeUDPRequest(ctx, pr, s.sessionID, s.reqUrl, s.cfg)
	var resp *http.Response
	var err error
	if rt, ok := s.httpClient.Transport.(http.RoundTripper); ok && s.cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = s.httpClient.Do(req)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务端拒绝: HTTP %d", resp.StatusCode)
	}
	zlog.Infof("[UDP-Resume:%s] ✅ 隧道就绪", s.sessionID)

	var wg sync.WaitGroup
	wg.Add(2)

	// 上行：消费 upstream 队列 → frameW 封装 → 写流 body。
	go func() {
		defer wg.Done()
		defer pw.Close()
		for {
			select {
			case <-s.done:
				return
			case pkt, ok := <-s.upstream:
				if !ok {
					return
				}
				if err := s.frameW(pw, pkt); err != nil {
					zlog.Debugf("[UDP-Resume:%s] 上行写失败: %v", s.sessionID, err)
					return
				}
			}
		}
	}()

	// 下行：读流 body → frameR 解包 → 写回本地 UDP socket。
	go func() {
		defer wg.Done()
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer udpBufPool.Put(bufPtr)
		for {
			n, rErr := s.frameR(resp.Body, buf)
			if rErr != nil {
				zlog.Debugf("[UDP-Resume:%s] 下行读结束: %v", s.sessionID, rErr)
				return
			}
			if _, wErr := s.localConn.WriteToUDP(buf[:n], s.clientAddr); wErr != nil {
				zlog.Debugf("[UDP-Resume:%s] 本地 UDP 写失败: %v", s.sessionID, wErr)
				return
			}
		}
	}()

	wg.Wait()
	return errors.New("stream closed") // 流结束 → 触发重拨
}

// buildResumeUDPRequest 构造 UDP resume 请求：
//   - masque-udp：CONNECT /.well-known/masque/udp/<host>/<port>/, Protocol: connect-udp
//   - h2/h3/grpc：POST cfg.Path，X-Network=udp，X-Target=<target>
//
// 帧数据面：masque 用 capsule，其余用 datagram packet（不含 seq）。
func buildResumeUDPRequest(ctx context.Context, body io.Reader, sessID, reqUrl string, cfg ClientConfig) *http.Request {
	var method, reqURL string
	if cfg.usesMasque() {
		method = http.MethodConnect
		host, port, _ := net.SplitHostPort(cfg.TargetAddr)
		if host == "" {
			host, port = cfg.TargetAddr, "53"
		}
		u, _ := url.Parse(reqUrl)
		u.Path = fmt.Sprintf("/.well-known/masque/udp/%s/%s/", url.PathEscape(host), url.PathEscape(port))
		reqURL = u.String()
	} else {
		method = http.MethodPost
		reqURL = reqUrl
	}

	req, _ := http.NewRequestWithContext(ctx, method, reqURL, body)
	req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	req.Header.Set("X-Session-ID", sessID)
	// ===== resume/2 握手头：版本 / 能力 / 参数（datagram 也走 A 层协商）=====
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	req.Header.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		req.Header.Set("X-Resume-Role", "backup")
	}
	SetXNetwork(req.Header, "udp")
	SetXTarget(req.Header, cfg.TargetAddr)
	if cfg.CustomHost != "" {
		req.Host = cfg.CustomHost
	}
	SetXAuth(req.Header, cfg)
	setTunnelRequestHeaders(req.Header)

	if cfg.usesMasque() {
		req.Header.Set("Protocol", "connect-udp")
		req.Header.Set("Capsule-Protocol", "?1")
		// http3.Transport 需要显式声明 HTTP/3，否则 CONNECT 目标路径可能被改写为空
		req.Proto = "HTTP/3"
	}
	if cfg.usesGRPC() {
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}
	return req
}

// clientUDPResumeSession 管理器：一个 UDP 会话对应一个活跃 HTTP 流。
// 供 runStreamUDPClient / runMasqueUDPClient 复用同一套断线续传逻辑。

// connectResumeUDP 建立一个新的 UDP resume 会话，返回其实例与入队函数。
// sessionID 需在调用方生成（newClientSessionID）。httpClient 为空时返回 nil
// （无可用主线路，调用方应优雅丢弃该 UDP 会话）。
func connectResumeUDP(sessionID string, cfg ClientConfig, reqUrl string, httpClient *http.Client, localConn *net.UDPConn, clientAddr *net.UDPAddr) *udpSession {
	if httpClient == nil {
		zlog.Warnf("[UDP-Resume:%s] 无可用主线路客户端，放弃 UDP 会话", sessionID)
		return nil
	}
	s := newUDPSession(sessionID, cfg, reqUrl, httpClient, localConn, clientAddr)
	go s.run()
	return s
}

// validateResumeUDPID 供测试/日志确认 session id 非空。
func validateResumeUDPID(id string) string {
	if id == "" {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return id
}
