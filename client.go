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
		// Extremely rare; on failure fall back to a still-usable time-based ID
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// pickClient returns the current active primary-lane http.Client via L3 connection
// management. typ is the business type ("tcp"/"udp", the type-demux dimension);
// when mgr is nil (e.g. the WT-only path) it returns nil.
func pickClient(mgr *connectionManager, typ string) *http.Client {
	if mgr == nil {
		return nil
	}
	return mgr.PickClient(typ)
}
