package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

type Config struct {
	NodeID                 int
	FetchUsersInterval     time.Duration
	ReportTrafficsInterval time.Duration
	HeartbeatInterval      time.Duration
	CheckNodeInterval      time.Duration
	DomainStrategy         string
	DisableSniffing        bool
	AllowPrivateOutbound   bool
	Cert                   *CertConfig
}

type Builder struct {
	instance                       *core.Instance
	config                         *Config
	nodeInfo                       *api.NodeInfo
	inboundTag                     string
	userList                       []api.UserInfo
	pendingTraffic                 map[int][2]int64
	trafficScanCursor              int
	lastRuntimeConfigWarning       *api.NodeInfo
	mu                             sync.RWMutex
	apiClient                      PanelAPI
	pendingNodeInfo                *api.NodeInfo
	retiredUsers                   map[string]int
	retiredOrder                   []string
	retiredScanCursor              int
	reportMu                       sync.Mutex
	lastReportedIPs                map[int][]string
	lastReportedAt                 map[int]time.Time
	deviceSyncMu                   sync.Mutex
	closeOnce                      sync.Once
	closeErr                       error
	fetchUsersMonitorPeriodic      *periodic
	reportTrafficsMonitorPeriodic  *periodic
	heartbeatMonitorPeriodic       *periodic
	checkNodeConfigMonitorPeriodic *periodic
	ctx                            context.Context
	cancel                         context.CancelFunc
}

const trafficScanBatchSize = 2048

type nodeConfigChange int

const (
	nodeConfigChangeNone nodeConfigChange = iota
	nodeConfigChangeReloadInbound
	nodeConfigChangeNeedsRestart
)

func classifyNodeConfigChange(inboundUnchanged, runtimeConfigUnchanged bool) nodeConfigChange {
	if inboundUnchanged && runtimeConfigUnchanged {
		return nodeConfigChangeNone
	}
	if runtimeConfigUnchanged {
		return nodeConfigChangeReloadInbound
	}
	return nodeConfigChangeNeedsRestart
}

func New(ctx context.Context, inboundTag string, instance *core.Instance, config *Config, nodeInfo *api.NodeInfo,
	apiClient PanelAPI,
) *Builder {
	ctx, cancel := context.WithCancel(ctx)
	return &Builder{
		inboundTag: inboundTag,
		instance:   instance,
		config:     config,
		nodeInfo:   nodeInfo,
		apiClient:  apiClient,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (b *Builder) Start() (err error) {
	// Start applies panel-supplied data (user rows become speed limits, Xray
	// users, and device limits) and it sits on the process's critical path:
	// Server.Start calls it before cmd/server's deferred recoverPanic is
	// registered, and urfave/cli recovers nothing, so a panic here used to
	// take the whole process down with no chance to report why. Turn it into
	// an ordinary startup error; Server.Start's failure path still closes
	// whatever this function managed to start.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while starting service: %v\n%s", r, debug.Stack())
		}
	}()

	if b.config.FetchUsersInterval <= 0 {
		return fmt.Errorf("invalid FetchUsersInterval: must be > 0, got %v", b.config.FetchUsersInterval)
	}
	if b.config.ReportTrafficsInterval <= 0 {
		return fmt.Errorf("invalid ReportTrafficsInterval: must be > 0, got %v", b.config.ReportTrafficsInterval)
	}

	// Initial user fetch
	userList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		return err
	}
	if len(userList) == 0 {
		// Not an error. The panel's getAvailableUsers filters on
		// u+d < transfer_enable, expired_at, and banned, so an empty list is
		// how it says "nobody in this node's group is currently entitled" --
		// which is also what an unset group_id produces (whereIn([]) compiles
		// to WHERE 0=1). Failing here crash-loops the node under systemd
		// Restart=on-failure and hits the panel twice per retry, while the
		// same response at runtime is correctly handled as "evict everyone".
		// Start empty; the fetch monitor picks users up when they appear.
		log.Warnln("panel lists no entitled users for this node; starting with an empty user list. Check this node's group assignment, and whether every user in the group has expired or exhausted their quota.")
	}
	err = b.addNewUser(userList)
	if err != nil {
		return err
	}
	b.userList = userList
	b.syncDeviceLimits()

	b.fetchUsersMonitorPeriodic = &periodic{
		Interval: b.config.FetchUsersInterval,
		Execute:  b.fetchUsersMonitor,
	}
	b.reportTrafficsMonitorPeriodic = &periodic{
		// V2Board considers a node stale after 300 seconds without /push.
		Interval: min(b.config.ReportTrafficsInterval, 120*time.Second),
		Execute:  b.reportTrafficsMonitor,
	}
	checkInterval := b.config.CheckNodeInterval
	if checkInterval <= 0 {
		checkInterval = b.config.FetchUsersInterval
	}
	b.checkNodeConfigMonitorPeriodic = &periodic{
		Interval: checkInterval,
		Execute:  b.checkNodeConfigMonitor,
	}

	log.Infoln("Start monitoring for user acquisition")
	b.fetchUsersMonitorPeriodic.Start()

	log.Infoln("Start traffic reporting monitoring")
	b.reportTrafficsMonitorPeriodic.Start()

	log.Infoln("Start node config monitoring")
	b.checkNodeConfigMonitorPeriodic.Start()

	// Device admission depends on alive/alivelist even when online reporting
	// was not explicitly configured. Keep a bounded refresh cadence.
	heartbeatInterval := b.config.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = b.config.FetchUsersInterval
	}
	if heartbeatInterval > 0 {
		b.heartbeatMonitorPeriodic = &periodic{
			Interval: min(heartbeatInterval, 60*time.Second),
			Execute:  b.heartbeatMonitor,
		}
		log.Infoln("Start heartbeat monitoring")
		b.heartbeatMonitorPeriodic.Start()
	}
	return nil
}

func (b *Builder) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.shutdown() })
	return b.closeErr
}

// Users returns a snapshot of the current user list. Safe for concurrent use.
func (b *Builder) Users() []api.UserInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]api.UserInfo, len(b.userList))
	copy(out, b.userList)
	return out
}

func (b *Builder) fetchUsersMonitor() error {
	newUserList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		log.Errorln(err)
		return nil
	}

	defer b.syncDeviceLimits()
	b.mu.Lock()
	defer b.mu.Unlock()

	deleted, added := b.compareUserList(newUserList, b.userList)
	var removeErr error
	if len(deleted) > 0 {
		deletedEmail := make([]string, len(deleted))
		for i, u := range deleted {
			email := buildUserEmail(b.inboundTag, u.Id, u.Uuid)
			deletedEmail[i] = email
			b.retireUserLocked(email, u.Id)
		}
		removeErr = b.removeUsers(deletedEmail, b.inboundTag)
		if removeErr != nil {
			log.Errorf("failed to remove users; retaining previous user snapshot for retry: %v", removeErr)
		}
	}
	// Reconcile against the actual handler even on 304/cached user lists;
	// a previous partial apply must not become permanent cache divergence.
	if err := b.addNewUser(newUserList); err != nil {
		log.Errorln(err)
		return nil
	}
	if removeErr != nil {
		return nil
	}
	if len(deleted) > 0 || len(added) > 0 {
		log.Infof("%d user deleted, %d user added", len(deleted), len(added))
	}
	b.userList = newUserList
	// Refresh per-user speed limits so SpeedLimit changes on existing users
	// (same ID+UUID) are picked up. Set() is a no-op when unchanged.
	for _, u := range newUserList {
		limiter.Set(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.SpeedLimit)
		limiter.SetDeviceLimit(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.DeviceLimit)
	}
	return nil
}

func sameRuntimeConfig(a, b *api.NodeInfo) bool {
	return reflect.DeepEqual(a.Routes, b.Routes) &&
		reflect.DeepEqual(a.Rules, b.Rules) &&
		reflect.DeepEqual(a.RawDNS, b.RawDNS)
}

func (b *Builder) runtimeConfigUnchanged(newNodeInfo *api.NodeInfo) bool {
	if b.nodeInfo == nil || newNodeInfo == nil {
		return true
	}
	return sameRuntimeConfig(b.nodeInfo, newNodeInfo)
}

func (b *Builder) runtimeWarningAlreadyLogged(newNodeInfo *api.NodeInfo) bool {
	if b.lastRuntimeConfigWarning == nil || newNodeInfo == nil {
		return false
	}
	return sameRuntimeConfig(b.lastRuntimeConfigWarning, newNodeInfo)
}

func (b *Builder) resetRuntimeConfigWarningLocked() {
	b.lastRuntimeConfigWarning = nil
}

func (b *Builder) checkNodeConfigMonitor() error {
	newNodeInfo, err := b.apiClient.GetNodeInfo(b.ctx)
	if err != nil {
		log.Errorln("Failed to fetch node info:", err)
		return nil
	}
	b.mu.Lock()
	if newNodeInfo != nil {
		b.pendingNodeInfo = newNodeInfo
	} else {
		// UniProxy commits its ETag before the local apply succeeds. Retry
		// the desired snapshot even when subsequent responses are 304.
		newNodeInfo = b.pendingNodeInfo
	}
	b.mu.Unlock()
	if newNodeInfo == nil || newNodeInfo.Vless == nil {
		return nil
	}

	// Fast path: compare under read lock and bail out if nothing changed.
	b.mu.RLock()
	inboundUnchanged := false
	runtimeConfigUnchanged := true
	if b.nodeInfo != nil && b.nodeInfo.Vless != nil {
		inboundUnchanged = b.nodeInfo.Vless.ServerPort == newNodeInfo.Vless.ServerPort &&
			b.nodeInfo.Vless.Flow == newNodeInfo.Vless.Flow &&
			b.nodeInfo.Vless.Network == newNodeInfo.Vless.Network &&
			b.nodeInfo.Vless.Tls == newNodeInfo.Vless.Tls &&
			b.nodeInfo.Vless.Encryption == newNodeInfo.Vless.Encryption &&
			reflect.DeepEqual(b.nodeInfo.Vless.NetworkSettings, newNodeInfo.Vless.NetworkSettings) &&
			reflect.DeepEqual(b.nodeInfo.Vless.TlsSettings, newNodeInfo.Vless.TlsSettings) &&
			reflect.DeepEqual(b.nodeInfo.Vless.EncryptionSettings, newNodeInfo.Vless.EncryptionSettings)
		runtimeConfigUnchanged = b.runtimeConfigUnchanged(newNodeInfo)
	}
	b.mu.RUnlock()
	change := classifyNodeConfigChange(inboundUnchanged, runtimeConfigUnchanged)
	if runtimeConfigUnchanged {
		b.mu.Lock()
		if b.lastRuntimeConfigWarning != nil {
			b.resetRuntimeConfigWarningLocked()
		}
		b.mu.Unlock()
	}
	if change == nodeConfigChangeNone {
		return nil
	}
	if change == nodeConfigChangeNeedsRestart {
		b.mu.Lock()
		shouldWarn := !b.runtimeWarningAlreadyLogged(newNodeInfo)
		if shouldWarn {
			b.lastRuntimeConfigWarning = newNodeInfo
		}
		b.mu.Unlock()
		if shouldWarn {
			log.Warnln("Node routing/DNS config changed; full core reload is required, restart server-vless to apply routes, DNS, custom outbounds, and any bundled inbound changes")
		}
		return nil
	}

	log.Infoln("Node inbound configuration changed, reloading inbound...")

	b.mu.RLock()
	oldNodeInfo := b.nodeInfo
	b.mu.RUnlock()

	// Heavy prep outside the lock: build pb config and allocate the handler.
	// These operations only depend on b.config and nodeInfo snapshots so they
	// are safe without holding b.mu.
	newInboundConfig, err := InboundBuilder(b.config, newNodeInfo)
	if err != nil {
		log.Errorln("Failed to build new inbound config:", err)
		return nil
	}
	rawHandler, err := core.CreateObject(b.instance, newInboundConfig)
	if err != nil {
		log.Errorln("Failed to create new inbound handler object:", err)
		return nil
	}
	newHandler, ok := rawHandler.(inbound.Handler)
	if !ok {
		log.Errorln("Created object is not an InboundHandler")
		return nil
	}

	oldInboundConfig, err := InboundBuilder(b.config, oldNodeInfo)
	if err != nil {
		_ = newHandler.Close()
		log.Errorln("Failed to build rollback inbound config:", err)
		return nil
	}
	rawOldHandler, err := core.CreateObject(b.instance, oldInboundConfig)
	if err != nil {
		_ = newHandler.Close()
		log.Errorln("Failed to create rollback inbound handler object:", err)
		return nil
	}
	oldHandler, ok := rawOldHandler.(inbound.Handler)
	if !ok {
		_ = newHandler.Close()
		log.Errorln("Created rollback object is not an InboundHandler")
		return nil
	}

	// Hot-swap + state update under lock.
	b.mu.Lock()
	defer b.mu.Unlock()

	inboundManager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		_ = newHandler.Close()
		_ = oldHandler.Close()
		log.Errorln("Inbound manager feature is unavailable")
		return nil
	}
	// Populate both handlers before removing the working inbound. Rollback
	// must restore actual users, not only our cached userList.
	if err := b.populateHandler(newHandler, newInboundConfig.Tag, newNodeInfo); err != nil {
		_ = newHandler.Close()
		_ = oldHandler.Close()
		return err
	}
	if err := b.populateHandler(oldHandler, b.inboundTag, oldNodeInfo); err != nil {
		_ = newHandler.Close()
		_ = oldHandler.Close()
		return err
	}
	if err := inboundManager.RemoveHandler(b.ctx, b.inboundTag); err != nil {
		_ = newHandler.Close()
		_ = oldHandler.Close()
		log.Errorln("Failed to remove old inbound handler:", err)
		return nil
	}
	if err := inboundManager.AddHandler(b.ctx, newHandler); err != nil {
		log.Errorln("Failed to add new inbound handler:", err)
		// Xray inserts the handler into its map before Start can fail.
		_ = inboundManager.RemoveHandler(b.ctx, newInboundConfig.Tag)
		_ = newHandler.Close()
		if restoreErr := inboundManager.AddHandler(b.ctx, oldHandler); restoreErr != nil {
			log.Errorln("Failed to restore old inbound handler after reload failure:", restoreErr)
		}
		return nil
	}

	_ = oldHandler.Close()
	oldTag := b.inboundTag
	b.pendingNodeInfo = nil
	b.nodeInfo = newNodeInfo
	b.inboundTag = newInboundConfig.Tag

	if oldTag != b.inboundTag {
		for _, u := range b.userList {
			b.retireUserLocked(buildUserEmail(oldTag, u.Id, u.Uuid), u.Id)
		}
	}

	for _, u := range b.userList {
		limiter.Set(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.SpeedLimit)
		limiter.SetDeviceLimit(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.DeviceLimit)
	}

	log.Infoln("Node configuration reloaded successfully. New Tag:", b.inboundTag)
	return nil
}

func (b *Builder) addPendingTrafficLocked(uid int, up, down int64) {
	if up <= 0 && down <= 0 {
		return
	}
	if b.pendingTraffic == nil {
		b.pendingTraffic = make(map[int][2]int64)
	}
	prev := b.pendingTraffic[uid]
	b.pendingTraffic[uid] = [2]int64{prev[0] + up, prev[1] + down}
}

func (b *Builder) nextTrafficScanUsersLocked(batchSize int) []api.UserInfo {
	users := make([]api.UserInfo, 0, min(len(b.userList), batchSize))
	if len(b.userList) == 0 {
		return users
	}
	if b.trafficScanCursor >= len(b.userList) {
		b.trafficScanCursor = 0
	}
	end := b.trafficScanCursor + batchSize
	if end > len(b.userList) {
		end = len(b.userList)
	}
	users = append(users, b.userList[b.trafficScanCursor:end]...)
	b.trafficScanCursor = end
	if b.trafficScanCursor >= len(b.userList) {
		b.trafficScanCursor = 0
	}
	return users
}

// nextRetiredScanLocked mirrors nextTrafficScanUsersLocked for retiredUsers,
// walking retiredOrder so the set can be drained in batches. The order slice
// exists because Go randomises map iteration, so a map cannot carry a cursor.
// The retired set only grows -- every port or UUID change adds the whole user
// list to it -- so draining all of it every cycle would hold the write lock for
// longer and longer. Batching delays late traffic from an already-retired
// identity, but getTraffic drains a counter rather than reading it, so nothing
// is lost, only reported a few cycles later.
func (b *Builder) nextRetiredScanLocked(batchSize int) []string {
	if len(b.retiredOrder) == 0 {
		return nil
	}
	if b.retiredScanCursor >= len(b.retiredOrder) {
		b.retiredScanCursor = 0
	}
	end := b.retiredScanCursor + batchSize
	if end > len(b.retiredOrder) {
		end = len(b.retiredOrder)
	}
	batch := b.retiredOrder[b.retiredScanCursor:end]
	b.retiredScanCursor = end
	if b.retiredScanCursor >= len(b.retiredOrder) {
		b.retiredScanCursor = 0
	}
	return batch
}

func (b *Builder) reportTrafficsMonitor() error {
	return b.reportTraffic(b.ctx, false)
}

func (b *Builder) reportTraffic(ctx context.Context, all bool) error {
	b.reportMu.Lock()
	defer b.reportMu.Unlock()
	b.mu.Lock()
	tag := b.inboundTag
	batchSize := trafficScanBatchSize
	retiredBatchSize := trafficScanBatchSize
	if all {
		// The final drain has to cover everything, not one batch.
		batchSize = len(b.userList)
		retiredBatchSize = len(b.retiredOrder)
		b.trafficScanCursor = 0
		b.retiredScanCursor = 0
	}
	users := b.nextTrafficScanUsersLocked(batchSize)

	currentTraffic := make(map[int][2]int64)
	for _, user := range users {
		email := buildUserEmail(tag, user.Id, user.Uuid)
		up, down := b.getTraffic(email)
		if up > 0 || down > 0 {
			currentTraffic[user.Id] = [2]int64{up, down}
		}
	}

	for _, email := range b.nextRetiredScanLocked(retiredBatchSize) {
		up, down := b.getTraffic(email)
		b.addPendingTrafficLocked(b.retiredUsers[email], up, down)
	}
	for uid, t := range currentTraffic {
		b.addPendingTrafficLocked(uid, t[0], t[1])
	}

	userTraffic := make([]api.UserTraffic, 0, len(b.pendingTraffic))
	for uid, t := range b.pendingTraffic {
		userTraffic = append(userTraffic, api.UserTraffic{
			UID:      uid,
			Upload:   t[0],
			Download: t[1],
		})
	}
	b.mu.Unlock()

	log.Infof("%d user traffic needs to be reported", len(userTraffic))
	if err := b.apiClient.ReportUserTraffic(ctx, userTraffic); err != nil {
		log.Errorln("server error when submitting traffic, will retry next cycle:", err)
		return err
	}

	b.mu.Lock()
	for _, t := range userTraffic {
		pending := b.pendingTraffic[t.UID]
		pending[0] -= t.Upload
		pending[1] -= t.Download
		if pending[0] <= 0 && pending[1] <= 0 {
			delete(b.pendingTraffic, t.UID)
		} else {
			b.pendingTraffic[t.UID] = pending
		}
	}
	b.mu.Unlock()
	return nil
}

func (b *Builder) heartbeatMonitor() error {
	b.deviceSyncMu.Lock()
	defer b.deviceSyncMu.Unlock()
	b.mu.RLock()
	users := make([]api.UserInfo, len(b.userList))
	copy(users, b.userList)
	tag := b.inboundTag
	b.mu.RUnlock()

	statsManager, ok := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return nil
	}

	data := make(map[int][]netip.Addr, len(users))
	for _, user := range users {
		name := "user>>>" + buildUserEmail(tag, user.Id, user.Uuid) + ">>>online"
		om := statsManager.GetOnlineMap(name)
		if om == nil {
			continue
		}
		var ips []netip.Addr
		om.ForEach(func(ip string, _ int64) bool {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return true
			}
			ips = append(ips, addr)
			return true
		})
		if len(ips) > 0 {
			data[user.Id] = ips
		}
	}

	if err := b.apiClient.ReportNodeOnlineUsers(b.ctx, data); err != nil {
		log.Errorln("server error when sending heartbeat", err)
	} else if len(data) > 0 {
		b.mu.Lock()
		if b.lastReportedIPs == nil {
			b.lastReportedIPs = make(map[int][]string)
		}
		if b.lastReportedAt == nil {
			b.lastReportedAt = make(map[int]time.Time)
		}
		for uid, ips := range data {
			b.lastReportedAt[uid] = time.Now()
			b.lastReportedIPs[uid] = nil
			for _, ip := range ips {
				b.lastReportedIPs[uid] = append(b.lastReportedIPs[uid], ip.String())
			}
		}
		b.mu.Unlock()
	}
	b.syncDeviceLimitsLocked()
	return nil
}

func (b *Builder) compareUserList(newUsers, oldUsers []api.UserInfo) (deleted, added []api.UserInfo) {
	// Index old users by Id for diff; UUID change on the same Id is treated as
	// a replacement (delete + re-add) so the in-memory Xray user gets the new UUID.
	oldByID := make(map[int]api.UserInfo, len(oldUsers))
	for _, u := range oldUsers {
		oldByID[u.Id] = u
	}

	newByID := make(map[int]api.UserInfo, len(newUsers))
	for _, u := range newUsers {
		newByID[u.Id] = u
		prev, ok := oldByID[u.Id]
		if !ok {
			added = append(added, u)
		} else if prev.Uuid != u.Uuid {
			deleted = append(deleted, prev)
			added = append(added, u)
		}
	}

	for _, u := range oldUsers {
		if _, ok := newByID[u.Id]; !ok {
			deleted = append(deleted, u)
		}
	}
	return deleted, added
}

// getTraffic drains the user's byte counters and returns the delta since the
// previous call. A missing counter reads as zero: GetCounter does not create.
func (b *Builder) getTraffic(email string) (up int64, down int64) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"

	statsManager, ok := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return 0, 0
	}
	upCounter := statsManager.GetCounter(upName)
	downCounter := statsManager.GetCounter(downName)

	if upCounter != nil {
		up = upCounter.Set(0)
	}
	if downCounter != nil {
		down = downCounter.Set(0)
	}
	return up, down
}

func (b *Builder) addNewUser(userInfo []api.UserInfo) error {
	nodeFlow := ""
	if b.nodeInfo != nil && b.nodeInfo.Vless != nil {
		nodeFlow = b.nodeInfo.Vless.Flow
	}
	log.Debugf("addNewUser - NodeFlow: '%s', Users: %d", nodeFlow, len(userInfo))
	// Assumes caller holds lock or is safe
	users := buildUser(b.inboundTag, userInfo, nodeFlow)
	if len(users) == 0 {
		return nil
	}
	// Register per-user speed limits (mbps=0 is treated as "no limit" and
	// quietly cleared).
	for _, u := range userInfo {
		limiter.Set(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.SpeedLimit)
		limiter.SetDeviceLimit(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.DeviceLimit)
	}
	return b.addUsers(users, b.inboundTag)
}

func (b *Builder) addUsers(users []*protocol.User, tag string) error {
	inboundManager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return fmt.Errorf("inbound manager feature is unavailable")
	}
	handler, err := inboundManager.GetHandler(b.ctx, tag)
	if err != nil {
		return fmt.Errorf("failed to get inbound handler: %w", err)
	}

	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not a proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("inbound handler %s does not implement proxy.UserManager", tag)
	}

	for _, user := range users {
		mUser, err := user.ToMemoryUser()
		if err != nil {
			return fmt.Errorf("create memory user: %w", err)
		}
		if userManager.GetUser(b.ctx, user.Email) != nil {
			continue
		}
		if err := userManager.AddUser(b.ctx, mUser); err != nil {
			return fmt.Errorf("add memory user: %w", err)
		}
	}
	return nil
}

func (b *Builder) removeUsers(users []string, tag string) error {
	inboundManager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return fmt.Errorf("inbound manager feature is unavailable")
	}
	handler, err := inboundManager.GetHandler(b.ctx, tag)
	if err != nil {
		return fmt.Errorf("failed to get inbound handler: %w", err)
	}

	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not a proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("inbound handler %s does not implement proxy.UserManager", tag)
	}

	return removeUsersFromManager(b.ctx, userManager, users)
}

func removeUsersFromManager(ctx context.Context, userManager proxy.UserManager, users []string) error {
	var removeErrs []error
	for _, email := range users {
		if userManager.GetUser(ctx, email) == nil {
			continue
		}
		if err := userManager.RemoveUser(ctx, email); err != nil {
			// A concurrent remover may have completed the operation between
			// GetUser and RemoveUser. Treat that converged state as success.
			if userManager.GetUser(ctx, email) == nil {
				continue
			}
			removeErrs = append(removeErrs, fmt.Errorf("remove user %q: %w", email, err))
		}
	}
	return errors.Join(removeErrs...)
}
