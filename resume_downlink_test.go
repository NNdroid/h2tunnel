package h2tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// TestBuildResumeRequestDownlink 守卫生成请求时 X-Resume-Downlink 必须反映
// 「本地已收下行字节(clientDownlink)」，而非上行环游标(ringBuf.WindowEnd())。
// 回归：此前 h2 路径误用 ringBuf.WindowEnd()(上行坐标) 作为下行水位，导致断线重连
// 后服务端按错误起点重放，客户端首帧 seq 不匹配 → errGap → 续传失败。
func TestBuildResumeRequestDownlink(t *testing.T) {
	base := clientConfig{
		ServerUrl:     "https://cdn.example.com",
		Path:          "/tunnel",
		TargetAddr:    "db.internal:5432",
		Token:         "sekret",
		Network:       "tcp",
		SessionWindow: 256,
	}

	dl := uint64(1234)
	req := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-1", &dl, newResumeClientRingBuf(256), base.ServerUrl+base.Path, base)
	if got := req.Header.Get("X-Resume-Downlink"); got != "1234" {
		t.Fatalf("X-Resume-Downlink = %q, want 1234（必须反映 clientDownlink 而非上行环游标）", got)
	}

	// 零值：首流 clientDownlink=0，服务端不重放。
	var zero uint64
	req0 := buildResumeRequest(context.Background(), strings.NewReader(""), "sess-1", &zero, newResumeClientRingBuf(256), base.ServerUrl+base.Path, base)
	if got := req0.Header.Get("X-Resume-Downlink"); got != "0" {
		t.Fatalf("X-Resume-Downlink(零值) = %q, want 0", got)
	}
}

// TestResumeRecvLoopDownlinkWatermark 守卫 resumeRecvLoop 必须以 *clientDownlink
// 作为下行坐标系起点（首流=0，重连流=上次已收字节数），并把已投递字节持续回写
// *clientDownlink，供下次重连上报。覆盖 h2(resumeRecvLoop) 与 WT(resumeRecvLoopWT
// 共用同款 expected 初始化) 的续传语义。
func TestResumeRecvLoopDownlinkWatermark(t *testing.T) {
	const seg = 100

	runCase := func(name string, start uint64, seqs []uint64, wantDelivered uint64, wantErr error) {
		t.Run(name, func(t *testing.T) {
			localConn, testConn := net.Pipe()
			defer localConn.Close()
			defer testConn.Close()
			pr, pw := io.Pipe()

			var clientDownlink uint64 = start
			var recvErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				recvErr = resumeRecvLoop(pr, localConn, &clientDownlink)
			}()

			// 帧写入另起 goroutine，避免 net.Pipe 同步写导致的死锁。
			go func() {
				data := bytes.Repeat([]byte("x"), seg)
				for _, s := range seqs {
					_ = writeResumeFrame(pw, s, data, 0)
				}
				_ = pw.Close()
			}()

			if wantErr == nil {
				buf := make([]byte, len(seqs)*seg)
				if _, err := io.ReadFull(testConn, buf); err != nil {
					t.Fatalf("读取下行数据失败: %v", err)
				}
			}
			wg.Wait()

			if wantErr == nil {
				if clientDownlink != wantDelivered {
					t.Fatalf("clientDownlink = %d, want %d", clientDownlink, wantDelivered)
				}
				// 真实客户端里：流正常以 END 帧结束 → err=nil；流被关闭(无 END) →
				// err=io.EOF，调用方据此重连。两种都属「无缺口、水位正确推进」。
				// 真正要守卫的是：重连流首帧 seq=clientDownlink 不得被判为 errGap。
				if recvErr != nil && !errorsIs(recvErr, io.EOF) {
					t.Fatalf("%s: 期望正常结束或 EOF(重连路径)，实际 err=%v", name, recvErr)
				}
				t.Logf("✅ %s: 续传正常，clientDownlink=%d, err=%v", name, clientDownlink, recvErr)
			} else {
				if !errorsIs(recvErr, wantErr) {
					t.Fatalf("%s: err = %v, want %v", name, recvErr, wantErr)
				}
				if clientDownlink != start {
					t.Fatalf("%s: 缺口场景 clientDownlink 应保持 %d，实际 %d", name, start, clientDownlink)
				}
				t.Logf("✅ %s: 缺口正确判定为 %v，clientDownlink 保持 %d", name, wantErr, clientDownlink)
			}
		})
	}

	// 首流：从 0 起，收 3 段 → 0,100,200，已收 300。
	runCase("首流从0起算", 0, []uint64{0, 100, 200}, 300, nil)
	// 重连流：从 500 起，收 500,600,700，已收 800。
	runCase("重连流从clientDownlink起算", 500, []uint64{500, 600, 700}, 800, nil)
	// 缺口：期望 0 但首帧为 500 → errGap，clientDownlink 不动。
	runCase("缺口判定ErrGap", 0, []uint64{500, 600, 700}, 0, errGap)
}

// errorsIs 小封装，避免在测试文件引入 errors 导入歧义。
func errorsIs(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}
	return err.Error() == target.Error() || err == target
}
