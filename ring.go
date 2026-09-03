package main

import (
	"errors"
	"sync"
)

// =========================================
// ringBuffer — 固定容量字节环形缓冲
//
// 用作会话恢复层的「最近 N 字节」缓存。
//
// 关键特性：
//   - 全局 64-bit seq 坐标系，窗口 [windowStartSeq, windowStartSeq+length)
//   - 写满时按环形覆盖最旧（覆盖即窗口滚动 + windowStartSeq++）
//   - 读端按 seq 取，若 seq < windowStartSeq 则返回 ErrGap（缺口已不可恢复）
//   - 支持并发写、并发读；Append 不阻塞（环形覆盖语义下总有空间）
//
// 设计动机：SSH 这种长连接流式协议，断线时不能丢会话。
// 双端各保留最近 N KB（默认 256KB），断线后按 seq 重放补缺。
// 覆盖最旧的代价是丢失最老窗口——客户端断线久了再来恢复，
// 会话表能告诉它"早于 X 的数据我丢了"，客户端可选择放弃恢复。
// =========================================

var ErrGap = errors.New("ringBuffer: requested seq is before current window start (gap unrecoverable)")

type ringBuffer struct {
	mu             sync.Mutex
	buf            []byte
	size           int
	head           int    // buf 中窗口起始的物理位置
	length         int    // 当前有效字节数
	windowStartSeq uint64 // buf[head] 对应的全局 seq
	notify         *sync.Cond
}

func newRingBuffer(sizeKB int) *ringBuffer {
	sizeKB = resolveSessionWindow(sizeKB)
	rb := &ringBuffer{
		buf:  make([]byte, sizeKB*1024),
		size: sizeKB * 1024,
	}
	rb.notify = sync.NewCond(&rb.mu)
	return rb
}

// Append 写入一段字节。缓冲满时按环形覆盖最旧，窗口随覆盖向前滚动。
// 简化实现：单次写入不跨越 head/tail 边界（先一次性尽力写入，
// 若 len(p) > free 则一次性覆盖并滚动窗口）。
func (rb *ringBuffer) Append(p []byte) {
	if len(p) == 0 {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for len(p) > 0 {
		tail := (rb.head + rb.length) % rb.size
		free := rb.size - rb.length
		if free == 0 {
			// 缓冲已满时按整段覆盖，而非一次腾一个字节。恢复窗口经常
			// 在高吞吐下保持满载；逐字节滚动会让每个 32KB 数据块多出
			// 32K 次循环和索引计算。
			if len(p) >= rb.size {
				overwriteLen := len(p)
				p = p[len(p)-rb.size:]
				rb.windowStartSeq += uint64(overwriteLen)
				copy(rb.buf, p)
				rb.head = 0
				rb.length = rb.size
				break
			}

			n := len(p)
			first := rb.size - tail
			if n <= first {
				copy(rb.buf[tail:tail+n], p)
			} else {
				copy(rb.buf[tail:rb.size], p[:first])
				copy(rb.buf[:n-first], p[first:n])
			}
			rb.head = (rb.head + n) % rb.size
			rb.windowStartSeq += uint64(n)
			break
		}
		n := len(p)
		if n > free {
			n = free
		}
		first := rb.size - tail
		if n <= first {
			copy(rb.buf[tail:tail+n], p[:n])
		} else {
			copy(rb.buf[tail:rb.size], p[:first])
			copy(rb.buf[:n-first], p[first:n])
		}
		rb.length += n
		p = p[n:]
	}
	rb.notify.Broadcast()
}

// ReadAt 从全局 seq 处开始读取最多 len(p) 字节。返回实际读取字节数。
// 若 seq < windowStartSeq 则窗口外（已被覆盖），返回 ErrGap。
func (rb *ringBuffer) ReadAt(seq uint64, p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	windowEnd := rb.windowStartSeq + uint64(rb.length)
	if seq < rb.windowStartSeq {
		return 0, ErrGap
	}
	if seq >= windowEnd {
		return 0, nil
	}
	offset := int(seq - rb.windowStartSeq)
	physStart := (rb.head + offset) % rb.size
	avail := int(windowEnd - seq)
	n := len(p)
	if n > avail {
		n = avail
	}
	first := rb.size - physStart
	if n <= first {
		copy(p[:n], rb.buf[physStart:physStart+n])
	} else {
		copy(p[:first], rb.buf[physStart:rb.size])
		copy(p[first:n], rb.buf[:n-first])
	}
	return n, nil
}

// WindowEnd 返回当前窗口末尾 seq（不含）
func (rb *ringBuffer) WindowEnd() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.windowStartSeq + uint64(rb.length)
}

// WaitNewData 阻塞直到窗口末尾超过 seq（用于消费者等待新数据）
func (rb *ringBuffer) WaitNewData(seq uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for rb.windowStartSeq+uint64(rb.length) <= seq {
		rb.notify.Wait()
	}
}

// WindowStartSeq 返回当前窗口起点 seq
func (rb *ringBuffer) WindowStartSeq() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.windowStartSeq
}
