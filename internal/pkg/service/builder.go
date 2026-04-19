package service

import (
	"context"
	"fmt"
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

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

type Config struct {
	NodeID                 int
	FetchUsersInterval     time.Duration
	ReportTrafficsInterval time.Duration
	HeartbeatInterval      time.Duration
	CheckNodeInterval      time.Duration
	Cert                   *CertConfig
}

type Builder struct {
	instance                       *core.Instance
	config                         *Config
	nodeInfo                       *api.NodeInfo
	inboundTag                     string
	userList                       []api.UserInfo
	pendingTraffic                 map[int][2]int64
	mu                             sync.RWMutex
	apiClient                      *api.Client
	fetchUsersMonitorPeriodic      *task.Periodic
	reportTrafficsMonitorPeriodic  *task.Periodic
	heartbeatMonitorPeriodic       *task.Periodic
	checkNodeConfigMonitorPeriodic *task.Periodic
	ctx                            context.Context
	cancel                         context.CancelFunc
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
	return nil
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
			delete(b.pendingTraffic, u.Id)
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
	return nil
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
	unchanged := false
	if b.nodeInfo != nil && b.nodeInfo.Vless != nil {
		unchanged = b.nodeInfo.Vless.ServerPort == newNodeInfo.Vless.ServerPort &&
			b.nodeInfo.Vless.Flow == newNodeInfo.Vless.Flow &&
			b.nodeInfo.Vless.Network == newNodeInfo.Vless.Network &&
			b.nodeInfo.Vless.Tls == newNodeInfo.Vless.Tls &&
			b.nodeInfo.Vless.Encryption == newNodeInfo.Vless.Encryption &&
			reflect.DeepEqual(b.nodeInfo.Vless.NetworkSettings, newNodeInfo.Vless.NetworkSettings) &&
			reflect.DeepEqual(b.nodeInfo.Vless.TlsSettings, newNodeInfo.Vless.TlsSettings) &&
			reflect.DeepEqual(b.nodeInfo.Vless.EncryptionSettings, newNodeInfo.Vless.EncryptionSettings) &&
			reflect.DeepEqual(b.nodeInfo.Rules, newNodeInfo.Rules) &&
			reflect.DeepEqual(b.nodeInfo.RawDNS, newNodeInfo.RawDNS)
	}
	b.mu.RUnlock()
	if unchanged {
		return nil
	}

	log.Infoln("Node configuration changed, reloading inbound...")

	// Heavy prep outside the lock: build pb config and allocate the handler.
	// These operations only depend on b.config and newNodeInfo (both
	// captured locally) so they are safe without holding b.mu.
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

	// Hot-swap + state update under lock.
	b.mu.Lock()
	defer b.mu.Unlock()

	inboundManager := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if err := inboundManager.RemoveHandler(b.ctx, b.inboundTag); err != nil {
		log.Errorln("Failed to remove old inbound handler:", err)
		return nil
	}
	if err := inboundManager.AddHandler(b.ctx, newHandler); err != nil {
		log.Errorln("Failed to add new inbound handler:", err)
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

func (b *Builder) reportTrafficsMonitor() error {
	b.mu.Lock()
	users := b.userList
	tag := b.inboundTag
	if b.pendingTraffic == nil {
		b.pendingTraffic = make(map[int][2]int64)
	}

	for _, user := range users {
		email := buildUserEmail(tag, user.Id, user.Uuid)
		up, down, _ := b.getTraffic(email)
		if up > 0 || down > 0 {
			prev := b.pendingTraffic[user.Id]
			b.pendingTraffic[user.Id] = [2]int64{prev[0] + up, prev[1] + down}
		}
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
	b.pendingTraffic = make(map[int][2]int64)
	b.mu.Unlock()
	return nil
}

func (b *Builder) heartbeatMonitor() error {
	b.mu.RLock()
	users := b.userList
	tag := b.inboundTag
	b.mu.RUnlock()

	statsManager, ok := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return nil
	}

	data := make(map[int][]string, len(users))
	for _, user := range users {
		name := "user>>>" + buildUserEmail(tag, user.Id, user.Uuid) + ">>>online"
		om := statsManager.GetOnlineMap(name)
		if om == nil {
			continue
		}
		var ips []string
		om.ForEach(func(ip string, _ int64) bool {
			ips = append(ips, ip)
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

	statsManager := b.instance.GetFeature(stats.ManagerType()).(stats.Manager)
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
// stats manager, so deleted users (or old-tag entries after reload) don't leak.
func (b *Builder) unregisterUserStats(email string) {
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
	return b.addUsers(users, b.inboundTag)
}

func (b *Builder) addUsers(users []*protocol.User, tag string) error {
	inboundManager := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
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
	inboundManager := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
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
