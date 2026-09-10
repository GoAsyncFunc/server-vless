package service

import (
	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	log "github.com/sirupsen/logrus"
)

func (b *Builder) syncDeviceLimits() {
	b.mu.RLock()
	needed := false
	for _, u := range b.userList {
		if u.DeviceLimit > 0 {
			needed = true
			break
		}
	}
	b.mu.RUnlock()
	if !needed {
		return
	}
	alive, err := b.apiClient.GetAliveList(b.ctx)
	if err != nil {
		log.Warn("device count refresh failed; retaining last snapshot")
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, u := range b.userList {
		email := buildUserEmail(b.inboundTag, u.Id, u.Uuid)
		limiter.SetDeviceLimit(email, u.DeviceLimit)
		limiter.SyncDevices(email, alive[u.Id], b.lastReportedIPs[u.Id])
	}
}
