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
	NodeType               string
	FetchUsersInterval     time.Duration
	ReportTrafficsInterval time.Duration
	HeartbeatInterval      time.Duration
	Cert                   *CertConfig
	ListenAddr             string
}

type Builder struct {
	instance                       *core.Instance
	config                         *Config
	nodeInfo                       *api.NodeInfo
	inboundTag                     string
	userList                       []api.UserInfo
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
	// Initial user fetch
	userList, err := b.apiClient.GetUserList(b.ctx)
	if err != nil {
		return err
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
	// Use same interval as fetch users for node config check, or 60s default
	checkInterval := b.config.FetchUsersInterval
	if checkInterval == 0 {
		checkInterval = time.Minute
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
			deletedEmail[i] = buildUserEmail(b.inboundTag, u.Id, u.Uuid)
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

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check for changes
	if b.nodeInfo != nil && b.nodeInfo.Vless != nil {
		if b.nodeInfo.Vless.ServerPort == newNodeInfo.Vless.ServerPort &&
			b.nodeInfo.Vless.Flow == newNodeInfo.Vless.Flow &&
			b.nodeInfo.Vless.Network == newNodeInfo.Vless.Network &&
			b.nodeInfo.Vless.Tls == newNodeInfo.Vless.Tls &&
			reflect.DeepEqual(b.nodeInfo.Vless.NetworkSettings, newNodeInfo.Vless.NetworkSettings) {
			return nil // No change
		}
	}

	log.Infoln("Node configuration changed, reloading inbound...")

	// 1. Build new inbound config
	newInboundConfig, err := InboundBuilder(b.config, newNodeInfo)
	if err != nil {
		log.Errorln("Failed to build new inbound config:", err)
		return nil
	}

	// 2. Create Handler from config
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

	inboundManager := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)

	// 3. Remove old inbound
	if err := inboundManager.RemoveHandler(b.ctx, b.inboundTag); err != nil {
		log.Errorln("Failed to remove old inbound handler:", err)
		return nil
	}

	// 4. Add new inbound
	if err := inboundManager.AddHandler(b.ctx, newHandler); err != nil {
		log.Errorln("Failed to add new inbound handler:", err)
		// Try to restore old one? It's tricky.
		return nil
	}

	// 5. Update state
	b.nodeInfo = newNodeInfo
	b.inboundTag = newInboundConfig.Tag

	// 6. Re-add current users to new inbound
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
	b.mu.RLock()
	users := b.userList
	tag := b.inboundTag
	b.mu.RUnlock()

	userTraffic := make([]api.UserTraffic, 0, len(users))
	for _, user := range users {
		email := buildUserEmail(tag, user.Id, user.Uuid)
		up, down, _ := b.getTraffic(email) // Count not used in uniproxy v1? Check model.
		if up > 0 || down > 0 {
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.Id,
				Upload:   int64(up),
				Download: int64(down),
			})
		}
	}
	if len(userTraffic) > 0 {
		log.Infof("%d user traffic needs to be reported", len(userTraffic))
		err := b.apiClient.ReportUserTraffic(b.ctx, userTraffic)
		if err != nil {
			log.Errorln("server error when submitting traffic", err)
			return nil
		}
	}
	return nil
}

func (b *Builder) heartbeatMonitor() error {
	data := make(map[int][]string)
	err := b.apiClient.ReportNodeOnlineUsers(b.ctx, data)
	if err != nil {
		log.Errorln("server error when sending heartbeat", err)
	}
	return nil
}

func (b *Builder) compareUserList(newUsers, oldUsers []api.UserInfo) (deleted, added []api.UserInfo) {
	oldUserMap := make(map[int]bool, len(oldUsers))
	for _, user := range oldUsers {
		oldUserMap[user.Id] = true
	}

	newUserMap := make(map[int]bool)
	for _, newUser := range newUsers {
		newUserMap[newUser.Id] = true
		if !oldUserMap[newUser.Id] {
			added = append(added, newUser)
		}
	}

	for _, oldUser := range oldUsers {
		if !newUserMap[oldUser.Id] {
			deleted = append(deleted, oldUser)
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
		up = upCounter.Value()
		if up > 0 {
			upCounter.Set(0)
		}
	}
	if downCounter != nil {
		down = downCounter.Value()
		if down > 0 {
			downCounter.Set(0)
		}
	}
	return up, down, 0
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
