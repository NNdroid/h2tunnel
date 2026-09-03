package main

import (
	"net/http"
	"sync"
	"time"
)

// =========================================
// connmanager.go — L3 连接管理层
//
// 职责：在主/备连接池之上做生命周期管理。resume/2 是唯一上层协议，
// h2/h3/grpc/masque/wt 都只是底层传输；本层只关心「有多少条主、多少条备、
// 谁还活着、谁该顶上、谁该补位」。
//
// 关键设计：
//   - 主/备数量可配（primary_count / backup_count，默认 1+1）。
//   - PrimaryCount>1 时启用类型分流：primaries 按业务类型(netType) 各管一条。
//   - 主连接阵亡 → 从备用池挑「已确认存活(backupAlive)」的备用升级为主 →
//     再拨一条新备补足 backup_count。
//   - 主/备拨号间隔各自可配（节流，防风暴重拨）。
//   - 主/备建立间隔默认 100s（establish_interval_sec）：先拨主、错相后再拨备，
//     使池内连接年龄不同相，CDN 不会同时杀掉主备。
//
// 每条「线路」都是一个 keepalive 探活会话（复用 backupLine：A+B 握手 +
// KEEPALIVE 保活）。线路的 primary/backup 标签是本层的容灾语义（谁可被升级），
// 与线上 role 无关——探活会话在线上统一以 keepalive 方式存在。
// =========================================

// 默认值
const (
	defaultPrimaryCount    = 1
	defaultBackupCount     = 1
	defaultEstablishSec    = 100
	primaryDialDefault     = 30 * time.Second // 主连接重拨节流默认
	backupDialDefault      = 15 * time.Second // 备用补位节流默认
	defaultBackupMissedAck = 3
	// manager 监控与建立检查周期
	connManagerTick = 200 * time.Millisecond
	// PickClient 等待某类型主线路建立成功的最大时长
	pickClientTimeout = 10 * time.Second
)

// ConnectionPolicy 连接管理策略（主备数量/间隔/类型分流）。
type ConnectionPolicy struct {
	PrimaryCount         int
	BackupCount          int
	PrimaryDialInterval  time.Duration
	BackupDialInterval   time.Duration
	EstablishInterval    time.Duration
	BackoffMaxMissedAcks int
	Shard                map[string]string // netType -> 协议
}

// resolveDial 把秒级配置换算为间隔；0/非法 → 默认。
func resolveDial(sec int, def time.Duration) time.Duration {
	if sec <= 0 {
		return def
	}
	return time.Duration(sec) * time.Second
}

// normalizeShard 规范化类型分流表；缺省项补默认。
// 默认分流：tcp→h2，udp→masque-udp。
func normalizeShard(m map[string]string) map[string]string {
	out := map[string]string{
		"tcp": "h2",
		"udp": "masque-udp",
	}
	for k, v := range m {
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// resolveConnectionPolicy 从 Config 派生连接管理策略（含默认值兜底）。
func resolveConnectionPolicy(pc, bc, pdSec, bdSec, esSec, missed int, shard map[string]string) ConnectionPolicy {
	if pc <= 0 {
		pc = defaultPrimaryCount
	}
	if bc <= 0 {
		bc = defaultBackupCount
	}
	if missed <= 0 {
		missed = defaultBackupMissedAck
	}
	establish := defaultEstablishSec * time.Second
	if esSec > 0 {
		establish = time.Duration(esSec) * time.Second
	}
	return ConnectionPolicy{
		PrimaryCount:         pc,
		BackupCount:          bc,
		PrimaryDialInterval:  resolveDial(pdSec, primaryDialDefault),
		BackupDialInterval:   resolveDial(bdSec, backupDialDefault),
		EstablishInterval:    establish,
		BackoffMaxMissedAcks: missed,
		Shard:                normalizeShard(shard),
	}
}

// normalizePolicy 归一策略：全零值（未显式配置，如直接构造 ClientConfig 的测试/程序化调用）
// 时套用默认 1 主 + 1 备 + 主拨号30s + 备拨号15s + 建立间隔100s + 失效阈值3 + 默认分流表。
// 已部分配置则仅对 0/非法项兜底，不覆盖显式值。
func normalizePolicy(p ConnectionPolicy) ConnectionPolicy {
	if p.PrimaryCount <= 0 {
		p.PrimaryCount = defaultPrimaryCount
	}
	if p.BackupCount <= 0 {
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
	if len(p.Shard) == 0 {
		p.Shard = normalizeShard(nil)
	}
	return p
}

// primaryTypes 计算需要维护主连接的业务类型集合。
//   - PrimaryCount<=1 → 单条默认类型 "default"（不启用分流）。
//   - PrimaryCount>1  → 取分流表的前 N 个 key 作为类型集合（启用类型分流）。
func (p ConnectionPolicy) primaryTypes() []string {
	if p.PrimaryCount <= 1 {
		return []string{"default"}
	}
	types := make([]string, 0, p.PrimaryCount)
	for k := range p.Shard {
		types = append(types, k)
		if len(types) >= p.PrimaryCount {
			break
		}
	}
	if len(types) == 0 {
		types = []string{"default"}
	}
	return types
}

// ConnectionManager 主/备连接管理器。
type ConnectionManager struct {
	policy        ConnectionPolicy
	cfg           ClientConfig
	reqUrl        string
	httpClient    *http.Client        // 共享默认客户端（探活线路回退）
	clientFactory func() *http.Client // 每线路专属客户端工厂（接入真实数据路径时设置）
	sessPrefix    string

	mu        sync.Mutex
	primaries map[string]*backupLine // netType -> 主连接（类型分流）
	backups   []*backupLine          // 备用池
	lastDial  map[string]time.Time   // key: "primary:<type>" | "backup" → 上次拨号时间
	// backupsEstablished 标记初始备用建立阶段是否完成。
	// 初始建立须等 establish_interval（错相）；完成后补位只受 backup_dial_interval。
	backupsEstablished bool
	closed             bool
	closeCh            chan struct{}
	startedAt          time.Time
}

// NewConnectionManager 创建连接管理器。sessPrefix 用于生成每条的独立 session id。
func NewConnectionManager(policy ConnectionPolicy, cfg ClientConfig, reqUrl string, httpClient *http.Client, sessPrefix string) *ConnectionManager {
	return &ConnectionManager{
		policy:     policy,
		cfg:        cfg,
		reqUrl:     reqUrl,
		httpClient: httpClient,
		sessPrefix: sessPrefix,
		primaries:  make(map[string]*backupLine),
		lastDial:   make(map[string]time.Time),
		closeCh:    make(chan struct{}),
	}
}

// SetClientFactory 设置每线路专属 http.Client 的工厂。
// 接入真实数据路径时调用：每条主/备线路拥有独立传输/连接池，
// 业务隧道经 PickClient 取当前活跃主线路的客户端（主断 → 备升级即切换）。
func (m *ConnectionManager) SetClientFactory(factory func() *http.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientFactory = factory
}

// PickClient 返回指定业务类型当前活跃主连接的 http.Client。
//   - PrimaryCount<=1（类型分流关闭）：单一主线路存于 "default" 键，任何业务类型
//     都取该主线路（单主服务所有流量）。
//   - PrimaryCount>1（类型分流开启）：按业务类型 netType 取对应主线路。
//
// 若该主线路尚未建立成功（仍在握手），阻塞等待其变为 backupAlive；
// 超过 pickClientTimeout 仍无可用主线路则返回 nil（业务隧道应优雅失败）。
func (m *ConnectionManager) PickClient(typ string) *http.Client {
	// 单主（未分流）时，任何类型都落到 "default" 主线路
	lookup := typ
	if m.policy.PrimaryCount <= 1 {
		lookup = "default"
	}
	deadline := time.Now().Add(pickClientTimeout)
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil
		}
		if bl, ok := m.primaries[lookup]; ok && bl.State() == backupAlive {
			if c := bl.Client(); c != nil {
				m.mu.Unlock()
				return c
			}
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			zlog.Warnf("[ConnMgr] 等待 %s 主线路 %v 超时，返回 nil", lookup, pickClientTimeout)
			return nil
		}
		time.Sleep(connManagerTick)
	}
}

// Policy 返回当前策略。
func (m *ConnectionManager) Policy() ConnectionPolicy { return m.policy }

// Start 启动连接管理：先拨主（primary_count 条，类型分流），
// 等 establish_interval 后再拨备（backup_count 条），并启动监控循环。
func (m *ConnectionManager) Start() {
	m.mu.Lock()
	m.startedAt = time.Now()
	m.mu.Unlock()

	for _, typ := range m.policy.primaryTypes() {
		m.dialPrimaryLocked(typ)
	}
	go m.monitor()
	go m.establishBackupsAfterDelay()
}

// dialPrimaryLocked 为指定类型拨一条主连接（遵循主拨号间隔节流）。
// 调用方须持有 m.mu。
func (m *ConnectionManager) dialPrimaryLocked(typ string) {
	key := "primary:" + typ
	if m.lastDial[key].After(time.Now().Add(-m.policy.PrimaryDialInterval)) {
		return // 未到主拨号间隔
	}
	bl := m.newLane(typ)
	if bl == nil {
		return
	}
	m.primaries[typ] = bl
	m.lastDial[key] = time.Now()
}

// dialBackupLocked 拨一条备用连接（遵循备拨号间隔节流）。
// 调用方须持有 m.mu。
func (m *ConnectionManager) dialBackupLocked() bool {
	if m.lastDial["backup"].After(time.Now().Add(-m.policy.BackupDialInterval)) {
		return false // 未到备拨号间隔
	}
	// 备用用 "default" 类型（备用是通用热备，不参与类型分流）
	bl := m.newLane("backup")
	if bl == nil {
		return false
	}
	m.backups = append(m.backups, bl)
	m.lastDial["backup"] = time.Now()
	return true
}

// newLane 创建并启动一条 keepalive 探活线路。
// 若设置了 clientFactory，则每条线路拥有独立 http.Client（独立传输/连接池），
// 使主备线路在传输层彼此隔离——主断后备用（含其预热的传输池）可秒级接管业务。
func (m *ConnectionManager) newLane(netType string) *backupLine {
	sessID := m.sessPrefix + "-" + netType + "-" + newClientSessionID()
	var lineClient *http.Client
	if m.clientFactory != nil {
		lineClient = m.clientFactory()
	}
	bl := newManagedLine(sessID, roleBackup, netType, m.cfg, m.reqUrl, m.httpClient, lineClient, m.policy.BackoffMaxMissedAcks)
	go bl.Start()
	return bl
}

// establishBackupsAfterDelay 在 establish_interval 到期后拨入备用（错相）。
func (m *ConnectionManager) establishBackupsAfterDelay() {
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

// monitor 周期检查所有线路状态：
//   - 主线路失效 → 用存活备用升级补位 → 补一条新备
//   - 备用失效 → 移除 → 补位
//   - 主/备数量不足 → 补足（受拨号间隔节流）
func (m *ConnectionManager) monitor() {
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

// reconcile 做一次主/备数量与状态对账。
func (m *ConnectionManager) reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	now := time.Now()

	// 1. 主连接失效/缺失 → 升级备用 / 补主
	for _, typ := range m.policy.primaryTypes() {
		cur := m.primaries[typ]
		need := cur == nil || cur.State() == backupFailed || cur.State() == backupIdle || cur.IsClosed()
		if !need {
			continue
		}
		if cur != nil {
			cur.close()
		}
		// 尝试用存活备用升级为主
		if idx := m.indexOfAliveBackup(); idx >= 0 {
			bl := m.backups[idx]
			m.backups = append(m.backups[:idx], m.backups[idx+1:]...)
			m.primaries[typ] = bl
			continue // 已补位，跳过补主
		}
		// 无可用备用 → 按主拨号间隔补主
		key := "primary:" + typ
		if m.lastDial[key].Before(now.Add(-m.policy.PrimaryDialInterval)) {
			bl := m.newLane(typ)
			if bl != nil {
				m.primaries[typ] = bl
				m.lastDial[key] = now
			}
		}
	}

	// 2. 备用失效/关闭 → 移除
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

	// 3. 补足备用数量（受备拨号间隔节流）。
	//    初始建立阶段：须等 establish_interval 到期（错相错开主备年龄）；
	//    一旦初始备用建立完成，后续补位仅受 backup_dial_interval 节流。
	needBackups := m.policy.BackupCount - len(m.backups)
	if needBackups > 0 {
		if m.backupsEstablished || now.Sub(m.startedAt) >= m.policy.EstablishInterval {
			m.backupsEstablished = true
			for i := 0; i < needBackups; i++ {
				if !m.dialBackupLocked() {
					break // 未到备拨号间隔
				}
			}
		}
	}
}

// indexOfAliveBackup 返回一个 state==backupAlive 的备用下标；无则 -1。
func (m *ConnectionManager) indexOfAliveBackup() int {
	for i, bl := range m.backups {
		if bl.State() == backupAlive {
			return i
		}
	}
	return -1
}

// PrimaryCount 返回当前主连接数。
func (m *ConnectionManager) PrimaryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.primaries)
}

// BackupCount 返回当前备用连接数。
func (m *ConnectionManager) BackupCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.backups)
}

// PrimaryTypes 返回当前主连接覆盖的类型集合。
func (m *ConnectionManager) PrimaryTypes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.primaries))
	for k := range m.primaries {
		out = append(out, k)
	}
	return out
}

// PrimaryState 返回指定类型主连接的状态；不存在返回 backupIdle。
func (m *ConnectionManager) PrimaryState(typ string) backupLineState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bl, ok := m.primaries[typ]; ok {
		return bl.State()
	}
	return backupIdle
}

// FailPrimary 模拟某类型主连接阵亡（供测试/运维触发切换）。
// 会立即关闭该主连接，触发 monitor 的升级+补位。
func (m *ConnectionManager) FailPrimary(typ string) {
	m.mu.Lock()
	if bl, ok := m.primaries[typ]; ok {
		bl.close()
		delete(m.primaries, typ)
	}
	m.mu.Unlock()
}

// Close 停止连接管理器，关闭所有线路。
func (m *ConnectionManager) Close() {
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
