package service

import (
	"time"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	log "github.com/sirupsen/logrus"
)

// The reference panel removes per-node entries after 100 seconds. Use a
// conservative 90s credit lifetime; stale local credits must never hide remote use.
const localDeviceCreditTTL = 90 * time.Second

func (b *Builder) syncDeviceLimits() {
	b.deviceSyncMu.Lock()
	defer b.deviceSyncMu.Unlock()
	b.syncDeviceLimitsLocked()
}

func (b *Builder) syncDeviceLimitsLocked() {
	b.mu.Lock()
	needed := false
	for _, u := range b.userList {
		if u.DeviceLimit > 0 {
			needed = true
			break
		}
	}
	// Expire local credits even when no user has a device limit. heartbeatMonitor
	// records a reported-IP entry for every online user regardless of the limit,
	// so gating this on `needed` would let both maps grow for the lifetime of the
	// process on any node that never enables the device limit.
	for uid, at := range b.lastReportedAt {
		if time.Since(at) >= localDeviceCreditTTL {
			delete(b.lastReportedAt, uid)
			delete(b.lastReportedIPs, uid)
		}
	}
	b.mu.Unlock()

	if !needed {
		return
	}
	alive, err := b.apiClient.GetAliveList(b.ctx)
	if err != nil {
		log.Warn("device count refresh failed; retaining last snapshot")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, u := range b.userList {
		email := buildUserEmail(b.inboundTag, u.Id, u.Uuid)
		limiter.SetDeviceLimit(email, u.DeviceLimit)
		reported := b.lastReportedIPs[u.Id]
		if b.lastReportedAt[u.Id].IsZero() {
			reported = nil
		}
		limiter.SyncDevices(email, alive[u.Id], reported)
	}
}
