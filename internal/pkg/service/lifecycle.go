package service

import (
	"fmt"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
)

func (b *Builder) populateHandler(handler inbound.Handler, tag string, node *api.NodeInfo) error {
	inboundProxy, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler does not expose inbound")
	}
	manager, ok := inboundProxy.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("inbound does not support users")
	}
	flow := ""
	if node != nil && node.Vless != nil {
		flow = node.Vless.Flow
	}
	for _, user := range buildUser(tag, b.userList, flow) {
		memory, err := user.ToMemoryUser()
		if err != nil {
			return err
		}
		if err := manager.AddUser(b.ctx, memory); err != nil {
			return err
		}
	}
	return nil
}

// Keep the old counters registered: in-flight connections may still hold them
// and add bytes after a port/UUID change. Each reporting cycle drains them.
// They live until core shutdown rather than risking dropping late traffic.
func (b *Builder) retireUserLocked(email string, uid int) {
	up, down, _ := b.getTraffic(email)
	b.addPendingTrafficLocked(uid, up, down)
	if b.retiredUsers == nil {
		b.retiredUsers = make(map[string]int)
	}
	b.retiredUsers[email] = uid
	limiter.Remove(email)
	limiter.RemoveDevices(email)
}
