package h2tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// =========================================
// connmanager.go — L3 connection-management layer
//
// Responsibility: lifecycle management over the primary/backup connection pools.
// resume/2 is the only upper-layer protocol; h2/h3/grpc/masque/wt are just
// underlying transports. This layer only cares about "how many primaries, how
// many backups, who's alive, who should take over, who needs refilling".
//
// Key design:
//   - Primary/backup counts are configurable (primary_count / backup_count, default 1+1).
//   - With PrimaryCount>1 type demux is on: primaries manage one lane per business type (netType).
//   - Primary dies -> promote a confirmed-alive (backupAlive) backup to primary -> dial a new backup to refill backup_count.
//   - Primary/backup dial intervals are separately configurable (throttling, to prevent redial storms).
//   - Primary/backup establish interval defaults to 100s (establish_interval_sec): dial the primary first, then the backup out of phase,
//     so pool connections have staggered ages and a CDN won't kill primary and backup at once.
//
// Each "lane" is a keepalive probe session (reusing backupLine: A+B handshake +
// KEEPALIVE liveness). A lane's primary/backup tag is this layer's failover
// semantics (who may be promoted), independent of the wire role — probe sessions
// all exist as keepalive on the wire.
// =========================================

// defaults
const (
	defaultPrimaryCount    = 1
	defaultBackupCount     = 1
	defaultEstablishSec    = 100
	primaryDialDefault     = 30 * time.Second // default primary redial throttle
	backupDialDefault      = 15 * time.Second // default backup refill throttle
	defaultBackupMissedAck = 3
	// manager monitor and establish-check period
	connManagerTick = 200 * time.Millisecond
	// max time PickClient waits for a given type's primary lane to establish
	pickClientTimeout = 10 * time.Second
)

// connectionPolicy is the connection-management policy (primary/backup counts, intervals, type demux).
type connectionPolicy struct {
	PrimaryCount         int
	BackupCount          int
	PrimaryDialInterval  time.Duration
	BackupDialInterval   time.Duration
	EstablishInterval    time.Duration
	BackoffMaxMissedAcks int
	PrimaryNetworks      []string
}

// resolveDial converts a seconds-based setting into an interval; 0/invalid -> default.
func resolveDial(sec int, def time.Duration) time.Duration {
	if sec <= 0 {
		return def
	}
	return time.Duration(sec) * time.Second
}

// normalizePrimaryNetworks keeps only the actually-supported business types, in a fixed tcp->udp order.
func normalizePrimaryNetworks(networks []string) []string {
	if len(networks) == 0 {
		return []string{networkTCP, networkUDP}
	}
	var tcp, udp bool
	for _, network := range networks {
		switch strings.ToLower(strings.TrimSpace(network)) {
		case networkAll:
			tcp, udp = true, true
		case networkTCP:
			tcp = true
		case networkUDP:
			udp = true
		}
	}
	out := make([]string, 0, 2)
	if tcp {
		out = append(out, networkTCP)
	}
	if udp {
		out = append(out, networkUDP)
	}
	if len(out) == 0 {
		return []string{networkTCP, networkUDP}
	}
	return out
}

// resolveConnectionPolicy derives the connection-management policy from a fileConfig (with default fallback).
func resolveConnectionPolicy(pc, bc, pdSec, bdSec, esSec, missed int, networks []string) connectionPolicy {
	if pc <= 0 {
		pc = defaultPrimaryCount
	}
	if bc < 0 {
		bc = defaultBackupCount
	}
	if missed <= 0 {
		missed = defaultBackupMissedAck
	}
	establish := defaultEstablishSec * time.Second
	if esSec > 0 {
		establish = time.Duration(esSec) * time.Second
	}
	primaryNetworks := normalizePrimaryNetworks(networks)
	if pc > 1 && pc > len(primaryNetworks) {
		pc = len(primaryNetworks)
	}
	return connectionPolicy{
		PrimaryCount:         pc,
		BackupCount:          bc,
		PrimaryDialInterval:  resolveDial(pdSec, primaryDialDefault),
		BackupDialInterval:   resolveDial(bdSec, backupDialDefault),
		EstablishInterval:    establish,
		BackoffMaxMissedAcks: missed,
		PrimaryNetworks:      primaryNetworks,
	}
}

// normalizePolicy normalizes the policy: an all-zero value (not explicitly configured, e.g.
// a test/programmatic clientConfig construction) gets the defaults: 1 primary + 1 backup +
// 30s primary dial + 15s backup dial + 100s establish interval + 3 failure threshold + a
// tcp/udp network order. If partially configured, it only falls back for 0/invalid fields and
// never overrides explicit values.
func normalizePolicy(p connectionPolicy) connectionPolicy {
	allZero := p.PrimaryCount == 0 && p.BackupCount == 0 &&
		p.PrimaryDialInterval == 0 && p.BackupDialInterval == 0 &&
		p.EstablishInterval == 0 && p.BackoffMaxMissedAcks == 0 && len(p.PrimaryNetworks) == 0
	if allZero {
		return resolveConnectionPolicy(0, -1, 0, 0, 0, 0, nil)
	}
	if p.PrimaryCount <= 0 {
		p.PrimaryCount = defaultPrimaryCount
	}
	// 0 explicitly disables backups; only negatives fall back as invalid. The all-zero policy was handled above as defaults.
	if p.BackupCount < 0 {
		p.BackupCount = defaultBackupCount
	}
	if p.PrimaryDialInterval <= 0 {
		p.PrimaryDialInterval = primaryDialDefault
	}
	if p.BackupDialInterval <= 0 {
		p.BackupDialInterval = backupDialDefault
	}
	if p.EstablishInterval <= 0 {
		p.EstablishInterval = time.Duration(defaultEstablishSec) * time.Second
	}
	if p.BackoffMaxMissedAcks <= 0 {
		p.BackoffMaxMissedAcks = defaultBackupMissedAck
	}
	p.PrimaryNetworks = normalizePrimaryNetworks(p.PrimaryNetworks)
	if p.PrimaryCount > 1 && p.PrimaryCount > len(p.PrimaryNetworks) {
		p.PrimaryCount = len(p.PrimaryNetworks)
	}
	return p
}

// primaryTypes computes the set of business types that need a maintained primary connection.
//   - PrimaryCount<=1 -> a single default type "default" (no demux).
//   - PrimaryCount>1  -> the first N enabled networks form the type set (type demux on).
func (p connectionPolicy) primaryTypes() []string {
	if p.PrimaryCount <= 1 {
		return []string{"default"}
	}
	networks := normalizePrimaryNetworks(p.PrimaryNetworks)
	count := min(p.PrimaryCount, len(networks))
	if count == 0 {
		return []string{"default"}
	}
	return networks[:count]
}

// connectionManager is the primary/backup connection manager.
type connectionManager struct {
	policy        connectionPolicy
	cfg           clientConfig
	reqUrl        string
	httpClient    *http.Client        // shared default client (probe-lane fallback)
	clientFactory func() *http.Client // per-lane dedicated-client factory (set when on the real data path)
	sessPrefix    string
	primaryKinds  []string // compiled once at startup to avoid iterating/sorting a map on the monitor hot path

	mu        sync.Mutex
	primaries map[string]*backupLine // netType -> primary connection (type demux)
	backups   []*backupLine          // backup pool
	lastDial  map[string]time.Time   // key: "primary:<type>" | "backup" -> last dial time
	// backupsEstablished marks whether the initial backup-establish phase finished.
	// Initial establishment must wait out establish_interval (out of phase); afterward refills are only bounded by backup_dial_interval.
	backupsEstablished bool
	closed             bool
	closeCh            chan struct{}
	startedAt          time.Time
}

// newConnectionManager creates the connection manager. sessPrefix generates each lane's distinct session id.
func newConnectionManager(policy connectionPolicy, cfg clientConfig, reqUrl string, httpClient *http.Client, sessPrefix string) *connectionManager {
	policy = normalizePolicy(policy)
	return &connectionManager{
		policy:       policy,
		cfg:          cfg,
		reqUrl:       reqUrl,
		httpClient:   httpClient,
		sessPrefix:   sessPrefix,
		primaryKinds: policy.primaryTypes(),
		primaries:    make(map[string]*backupLine),
		lastDial:     make(map[string]time.Time),
		closeCh:      make(chan struct{}),
	}
}

// SetClientFactory sets the per-lane dedicated http.Client factory.
// Called when on the real data path: each primary/backup lane owns an independent
// transport/pool, and business tunnels get the current active primary lane's client
// via PickClient (primary down -> backup promotion switches it).
func (m *connectionManager) SetClientFactory(factory func() *http.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientFactory = factory
}

// PickClient returns the http.Client of the current active primary connection for a
// business type.
//   - PrimaryCount<=1 (demux off): a single primary lane under the "default" key is used for every business type (one primary serves all traffic).
//   - PrimaryCount>1 (demux on): the lane is selected by netType.
//
// If that primary hasn't established yet (still handshaking), it blocks until it becomes backupAlive;
// if no primary is available within pickClientTimeout it returns nil (the business tunnel should fail gracefully).
func (m *connectionManager) PickClient(typ string) *http.Client {
	ctx, cancel := context.WithTimeout(context.Background(), pickClientTimeout)
	defer cancel()
	client, _ := m.WaitClient(ctx, typ)
	return client
}

func (m *connectionManager) WaitClient(ctx context.Context, typ string) (*http.Client, error) {
	// single primary (no demux): every type maps to the "default" primary lane
	lookup := typ
	if len(m.primaryKinds) <= 1 {
		lookup = "default"
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, net.ErrClosed
		}
		if bl, ok := m.primaries[lookup]; ok {
			state := bl.State()
			if state == backupAlive {
				if c := bl.Client(); c != nil {
					m.mu.Unlock()
					return c, nil
				}
			}
			if state == backupFailed {
				err := bl.Err()
				m.mu.Unlock()
				if err == nil {
					err = errors.New("h2tunnel: transport readiness handshake failed")
				}
				return nil, err
			}
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(connManagerTick):
		}
	}
}

func (m *connectionManager) WaitAnyClient(ctx context.Context) (*http.Client, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, net.ErrClosed
		}
		failed := 0
		var firstErr error
		for _, kind := range m.primaryKinds {
			line := m.primaries[kind]
			if line == nil {
				continue
			}
			switch line.State() {
			case backupAlive:
				client := line.Client()
				m.mu.Unlock()
				if client == nil {
					return nil, errors.New("h2tunnel: ready transport has no HTTP client")
				}
				return client, nil
			case backupFailed:
				failed++
				if firstErr == nil {
					firstErr = line.Err()
				}
			}
		}
		allFailed := failed == len(m.primaryKinds)
		m.mu.Unlock()
		if allFailed {
			if firstErr == nil {
				firstErr = errors.New("h2tunnel: all transport readiness checks failed")
			}
			return nil, firstErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(connManagerTick):
		}
	}
}

// Policy returns the current policy.
func (m *connectionManager) Policy() connectionPolicy { return m.policy }

// Start begins connection management: dial primaries first (primary_count, type-demuxed),
// wait out establish_interval, then dial backups (backup_count), and start the monitor loop.
func (m *connectionManager) Start() {
	m.mu.Lock()
	m.startedAt = time.Now()
	m.mu.Unlock()

	for _, typ := range m.primaryKinds {
		m.dialPrimaryLocked(typ)
	}
	go m.monitor()
	if m.policy.BackupCount > 0 {
		go m.establishBackupsAfterDelay()
	} else {
		m.mu.Lock()
		m.backupsEstablished = true
		m.mu.Unlock()
	}
}

// dialPrimaryLocked dials one primary connection for a type (respecting the primary dial-interval throttle).
// The caller must hold m.mu.
func (m *connectionManager) dialPrimaryLocked(typ string) {
	key := "primary:" + typ
	if m.lastDial[key].After(time.Now().Add(-m.policy.PrimaryDialInterval)) {
		return // primary dial interval not yet reached
	}
	bl := m.newLane(typ)
	if bl == nil {
		return
	}
	m.primaries[typ] = bl
	m.lastDial[key] = time.Now()
}

// dialBackupLocked dials one backup connection (respecting the backup dial-interval throttle).
// The caller must hold m.mu.
func (m *connectionManager) dialBackupLocked() bool {
	if m.lastDial["backup"].After(time.Now().Add(-m.policy.BackupDialInterval)) {
		return false // backup dial interval not yet reached
	}
	// backups use the "default" type (a backup is a general hot standby, not type-demuxed)
	bl := m.newLane("backup")
	if bl == nil {
		return false
	}
	m.backups = append(m.backups, bl)
	m.lastDial["backup"] = time.Now()
	return true
}

// newLane creates and starts a keepalive probe lane.
// If a clientFactory is set, each lane owns an independent http.Client (own
// transport/pool), isolating primary and backup at the transport layer — so a backup
// (with its pre-warmed pool) can take over business traffic within seconds after the primary drops.
func (m *connectionManager) newLane(netType string) *backupLine {
	sessID := m.sessPrefix + "-" + netType + "-" + newClientSessionID()
	var lineClient *http.Client
	if m.clientFactory != nil {
		lineClient = m.clientFactory()
	}
	laneCfg := m.cfg
	if netType == networkTCP || netType == networkUDP {
		laneCfg.Network = netType
	}
	bl := newManagedLine(sessID, roleBackup, netType, laneCfg, m.reqUrl, m.httpClient, lineClient, m.policy.BackoffMaxMissedAcks)
	go bl.Start()
	return bl
}

// establishBackupsAfterDelay dials backups in after establish_interval elapses (out of phase).
func (m *connectionManager) establishBackupsAfterDelay() {
	select {
	case <-m.closeCh:
		return
	case <-time.After(m.policy.EstablishInterval):
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for i := 0; i < m.policy.BackupCount; i++ {
		m.dialBackupLocked()
	}
	m.backupsEstablished = true
}

// monitor periodically checks all lane states:
//   - primary dead -> promote a live backup -> dial a new backup
//   - backup dead -> remove -> refill
//   - primary/backup count too low -> top up (throttled by dial intervals)
func (m *connectionManager) monitor() {
	t := time.NewTicker(connManagerTick)
	defer t.Stop()
	for {
		select {
		case <-m.closeCh:
			return
		case <-t.C:
			m.reconcile()
		}
	}
}

// reconcile does one pass reconciling primary/backup counts and states.
func (m *connectionManager) reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	now := time.Now()

	// 1. primary dead/missing -> promote a backup / dial a new primary
	for _, typ := range m.primaryKinds {
		cur := m.primaries[typ]
		need := cur == nil || cur.State() == backupFailed || cur.State() == backupIdle || cur.IsClosed()
		if !need {
			continue
		}
		if cur != nil {
			cur.close()
		}
		// try promoting a live backup to primary
		if idx := m.indexOfAliveBackup(); idx >= 0 {
			bl := m.backups[idx]
			m.backups = append(m.backups[:idx], m.backups[idx+1:]...)
			m.primaries[typ] = bl
			continue // refilled by promotion, skip dialing a new primary
		}
		// no usable backup -> dial a new primary, respecting the primary dial interval
		key := "primary:" + typ
		if m.lastDial[key].Before(now.Add(-m.policy.PrimaryDialInterval)) {
			bl := m.newLane(typ)
			if bl != nil {
				m.primaries[typ] = bl
				m.lastDial[key] = now
			}
		}
	}

	// 2. backup dead/closed -> remove
	kept := m.backups[:0]
	for _, bl := range m.backups {
		st := bl.State()
		if st == backupFailed || st == backupIdle || bl.IsClosed() {
			bl.close()
			continue
		}
		kept = append(kept, bl)
	}
	m.backups = kept

	// 3. top up the backup count (throttled by the backup dial interval).
	//    During initial establishment: wait out establish_interval (stagger primary/backup ages);
	//    once the initial backups are up, later refills are throttled only by backup_dial_interval.
	needBackups := m.policy.BackupCount - len(m.backups)
	if needBackups > 0 {
		if m.backupsEstablished || now.Sub(m.startedAt) >= m.policy.EstablishInterval {
			m.backupsEstablished = true
			for i := 0; i < needBackups; i++ {
				if !m.dialBackupLocked() {
					break // backup dial interval not yet reached
				}
			}
		}
	}
}

// indexOfAliveBackup returns the index of a backup with state==backupAlive, or -1.
func (m *connectionManager) indexOfAliveBackup() int {
	for i, bl := range m.backups {
		if bl.State() == backupAlive {
			return i
		}
	}
	return -1
}

// PrimaryCount returns the current primary connection count.
func (m *connectionManager) PrimaryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.primaries)
}

// BackupCount returns the current backup connection count.
func (m *connectionManager) BackupCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.backups)
}

// PrimaryTypes returns the set of types covered by current primaries.
func (m *connectionManager) PrimaryTypes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.primaries))
	for k := range m.primaries {
		out = append(out, k)
	}
	return out
}

// PrimaryState returns the primary state for a type, or backupIdle if none.
func (m *connectionManager) PrimaryState(typ string) backupLineState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bl, ok := m.primaries[typ]; ok {
		return bl.State()
	}
	return backupIdle
}

// FailPrimary simulates the death of a type's primary (for tests/operators to trigger failover).
// It closes that primary immediately, prompting the monitor's promote + refill.
func (m *connectionManager) FailPrimary(typ string) {
	m.mu.Lock()
	if bl, ok := m.primaries[typ]; ok {
		bl.close()
		delete(m.primaries, typ)
	}
	m.mu.Unlock()
}

// Close stops the connection manager and closes all lanes.
func (m *connectionManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	for _, bl := range m.primaries {
		bl.close()
	}
	for _, bl := range m.backups {
		bl.close()
	}
	m.primaries = nil
	m.backups = nil
	m.mu.Unlock()
	close(m.closeCh)
}
