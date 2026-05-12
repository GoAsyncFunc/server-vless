package service

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
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
	apiClient                      *api.Client
	fetchUsersMonitorPeriodic      *task.Periodic
	reportTrafficsMonitorPeriodic  *task.Periodic
	heartbeatMonitorPeriodic       *task.Periodic
	checkNodeConfigMonitorPeriodic *task.Periodic
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
	apiClient *api.Client,
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

func (b *Builder) Start() error {
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
		return fmt.Errorf("no valid user for this node; check v2board group/plan assignment")
	}
	err = b.addNewUser(userList)
	if err != nil {
		return err
	}
	b.userList = userList

	b.fetchUsersMonitorPeriodic = &task.Periodic{
		Interval: b.config.FetchUsersInterval,
		Execute:  b.fetchUsersMonitor,
	}
	b.reportTrafficsMonitorPeriodic = &task.Periodic{
		Interval: b.config.ReportTrafficsInterval,
		Execute:  b.reportTrafficsMonitor,
	}
	checkInterval := b.config.CheckNodeInterval
	if checkInterval <= 0 {
		checkInterval = b.config.FetchUsersInterval
	}
	b.checkNodeConfigMonitorPeriodic = &task.Periodic{
		Interval: checkInterval,
		Execute:  b.checkNodeConfigMonitor,
	}

	log.Infoln("Start monitoring for user acquisition")
	if err := b.fetchUsersMonitorPeriodic.Start(); err != nil {
		return fmt.Errorf("fetch users monitor periodic start error: %s", err)
	}

	log.Infoln("Start traffic reporting monitoring")
	if err := b.reportTrafficsMonitorPeriodic.Start(); err != nil {
		return fmt.Errorf("traffic monitor periodic start error: %s", err)
	}

	log.Infoln("Start node config monitoring")
	if err := b.checkNodeConfigMonitorPeriodic.Start(); err != nil {
		return fmt.Errorf("node config monitor periodic start error: %s", err)
	}

	if b.config.HeartbeatInterval > 0 {
		b.heartbeatMonitorPeriodic = &task.Periodic{
			Interval: b.config.HeartbeatInterval,
			Execute:  b.heartbeatMonitor,
		}
		log.Infoln("Start heartbeat monitoring")
		if err := b.heartbeatMonitorPeriodic.Start(); err != nil {
			return fmt.Errorf("heartbeat monitor periodic start error: %s", err)
		}
	}
	return nil
}

func (b *Builder) Close() error {
	b.cancel()
	if b.fetchUsersMonitorPeriodic != nil {
		b.fetchUsersMonitorPeriodic.Close()
	}
	if b.reportTrafficsMonitorPeriodic != nil {
		b.reportTrafficsMonitorPeriodic.Close()
	}
	if b.checkNodeConfigMonitorPeriodic != nil {
		b.checkNodeConfigMonitorPeriodic.Close()
	}
	if b.heartbeatMonitorPeriodic != nil {
		b.heartbeatMonitorPeriodic.Close()
	}
	// Drop rate-limit buckets so the global registry doesn't keep stale
	// entries across restarts in long-lived embedded scenarios.
	b.mu.RLock()
	tag := b.inboundTag
	users := b.userList
	b.mu.RUnlock()
	for _, u := range users {
		limiter.Remove(buildUserEmail(tag, u.Id, u.Uuid))
	}
	return nil
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

	b.mu.Lock()
	defer b.mu.Unlock()

	deleted, added := b.compareUserList(newUserList, b.userList)
	if len(deleted) > 0 {
		deletedEmail := make([]string, len(deleted))
		for i, u := range deleted {
			email := buildUserEmail(b.inboundTag, u.Id, u.Uuid)
			deletedEmail[i] = email
			up, down, _ := b.getTraffic(email)
			b.addPendingTrafficLocked(u.Id, up, down)
			b.unregisterUserStats(email)
		}
		if err := b.removeUsers(deletedEmail, b.inboundTag); err != nil {
			log.Errorln(err)
			// Continue to add users even if remove failed
		}
	}
	if len(added) > 0 {
		if err := b.addNewUser(added); err != nil {
			log.Errorln(err)
			return nil
		}
	}
	if len(deleted) > 0 || len(added) > 0 {
		log.Infof("%d user deleted, %d user added", len(deleted), len(added))
	}
	b.userList = newUserList
	// Refresh per-user speed limits so SpeedLimit changes on existing users
	// (same ID+UUID) are picked up. Set() is a no-op when unchanged.
	for _, u := range newUserList {
		limiter.Set(buildUserEmail(b.inboundTag, u.Id, u.Uuid), u.SpeedLimit)
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
		log.Errorln("Failed to build rollback inbound config:", err)
		return nil
	}
	rawOldHandler, err := core.CreateObject(b.instance, oldInboundConfig)
	if err != nil {
		log.Errorln("Failed to create rollback inbound handler object:", err)
		return nil
	}
	oldHandler, ok := rawOldHandler.(inbound.Handler)
	if !ok {
		log.Errorln("Created rollback object is not an InboundHandler")
		return nil
	}

	// Hot-swap + state update under lock.
	b.mu.Lock()
	defer b.mu.Unlock()

	inboundManager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		log.Errorln("Inbound manager feature is unavailable")
		return nil
	}
	if err := inboundManager.RemoveHandler(b.ctx, b.inboundTag); err != nil {
		log.Errorln("Failed to remove old inbound handler:", err)
		return nil
	}
	if err := inboundManager.AddHandler(b.ctx, newHandler); err != nil {
		log.Errorln("Failed to add new inbound handler:", err)
		if restoreErr := inboundManager.AddHandler(b.ctx, oldHandler); restoreErr != nil {
			log.Errorln("Failed to restore old inbound handler after reload failure:", restoreErr)
		}
		return nil
	}

	oldTag := b.inboundTag
	b.nodeInfo = newNodeInfo
	b.inboundTag = newInboundConfig.Tag

	if oldTag != b.inboundTag {
		for _, u := range b.userList {
			b.unregisterUserStats(buildUserEmail(oldTag, u.Id, u.Uuid))
		}
	}

	if len(b.userList) > 0 {
		log.Infof("Re-adding %d users to new inbound...", len(b.userList))
		if err := b.addNewUser(b.userList); err != nil {
			log.Errorln("Failed to re-add users after reload:", err)
		}
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

func (b *Builder) reportTrafficsMonitor() error {
	b.mu.Lock()
	tag := b.inboundTag
	users := b.nextTrafficScanUsersLocked(trafficScanBatchSize)
	b.mu.Unlock()

	currentTraffic := make(map[int][2]int64)
	for _, user := range users {
		email := buildUserEmail(tag, user.Id, user.Uuid)
		up, down, _ := b.getTraffic(email)
		if up > 0 || down > 0 {
			currentTraffic[user.Id] = [2]int64{up, down}
		}
	}

	b.mu.Lock()
	for uid, t := range currentTraffic {
		b.addPendingTrafficLocked(uid, t[0], t[1])
	}
	if len(b.pendingTraffic) == 0 {
		b.mu.Unlock()
		return nil
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
	if err := b.apiClient.ReportUserTraffic(b.ctx, userTraffic); err != nil {
		log.Errorln("server error when submitting traffic, will retry next cycle:", err)
		return nil
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
	}
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

func (b *Builder) getTraffic(email string) (up int64, down int64, count int64) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"

	statsManager, ok := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return 0, 0, 0
	}
	upCounter := statsManager.GetCounter(upName)
	downCounter := statsManager.GetCounter(downName)

	if upCounter != nil {
		up = upCounter.Set(0)
	}
	if downCounter != nil {
		down = downCounter.Set(0)
	}
	return up, down, 0
}

// unregisterUserStats removes per-user counter and online map entries from the
// stats manager and drops the user's rate-limit bucket. Used both when a user
// is deleted and when the inbound tag changes (old-email entries leak).
func (b *Builder) unregisterUserStats(email string) {
	limiter.Remove(email)
	sm, ok := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return
	}
	_ = sm.UnregisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	_ = sm.UnregisterCounter("user>>>" + email + ">>>traffic>>>downlink")
	_ = sm.UnregisterOnlineMap("user>>>" + email + ">>>online")
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
		return fmt.Errorf("failed to get inbound handler: %s", err)
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
			log.Errorf("failed to create memory user %s: %s", user.Email, err)
			continue
		}
		if err := userManager.AddUser(b.ctx, mUser); err != nil {
			log.Errorf("failed to add user %s: %s", user.Email, err)
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
		return fmt.Errorf("failed to get inbound handler: %s", err)
	}

	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not a proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("inbound handler %s does not implement proxy.UserManager", tag)
	}

	for _, email := range users {
		if err := userManager.RemoveUser(b.ctx, email); err != nil {
			log.Errorf("failed to remove user %s: %s", email, err)
		}
	}
	return nil
}
