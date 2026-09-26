package service

import (
	"fmt"
	"time"

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
// and add bytes after a port/UUID change. Each reporting cycle drains a batch
// of them, and reportTraffic drops the entry once it has been retired for
// retiredIdentityTTL, so a node that changes ports often does not accumulate a
// retired identity per user per change forever.
func (b *Builder) retireUserLocked(email string, uid int) {
	up, down := b.getTraffic(email)
	b.addPendingTrafficLocked(uid, up, down)
	if b.retiredUsers == nil {
		b.retiredUsers = make(map[string]int)
	}
	if b.retiredAt == nil {
		b.retiredAt = make(map[string]time.Time)
	}
	// The same identity can be retired more than once across repeated tag
	// changes. Append it to the scan order only the first time, so one sweep
	// drains its counter once instead of once per retirement.
	if _, seen := b.retiredUsers[email]; !seen {
		b.retiredOrder = append(b.retiredOrder, email)
	}
	b.retiredUsers[email] = uid
	// Age from the latest retirement: a tag that comes back and is retired
	// again hands us the same email, and the earlier timestamp would let it
	// expire while its new counter is still being written to.
	b.retiredAt[email] = time.Now()
	limiter.Remove(email)
	limiter.RemoveDevices(email)
}
