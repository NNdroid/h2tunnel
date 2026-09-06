package h2tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

func newClientSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 极罕见；失败用 time 拼一个仍可用的 ID
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// pickClient 经 L3 连接管理取当前活跃主线路的 http.Client。
// typ 为业务类型（"tcp"/"udp"，类型分流维度）。mgr 为 nil（如 WT 专属路径）时返回 nil。
func pickClient(mgr *connectionManager, typ string) *http.Client {
	if mgr == nil {
		return nil
	}
	return mgr.PickClient(typ)
}
