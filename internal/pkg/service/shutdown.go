package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	"github.com/xtls/xray-core/features/inbound"
)

var ErrShutdownIncomplete = errors.New("service shutdown incomplete")

const shutdownTimeout = 10 * time.Second

func (b *Builder) shutdown() error {
	tasks := []*periodic{b.fetchUsersMonitorPeriodic, b.reportTrafficsMonitorPeriodic, b.checkNodeConfigMonitorPeriodic, b.heartbeatMonitorPeriodic}
	for _, task := range tasks {
		task.Stop()
	}
	if b.cancel != nil {
		b.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, task := range tasks {
		if err := task.Wait(ctx); err != nil {
			return fmt.Errorf("%w: waiting for background tasks: %w", ErrShutdownIncomplete, err)
		}
	}
	// Remove listeners before the final drain. Stats remain available until the
	// owner closes the core. This does not guarantee delivery after process kill.
	if b.instance != nil {
		if manager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager); ok {
			b.stopInboundListener(ctx, manager)
		}
	}
	var err error
	if b.instance != nil && b.apiClient != nil {
		err = b.reportTraffic(ctx, true)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, u := range b.userList {
		email := buildUserEmail(b.inboundTag, u.Id, u.Uuid)
		limiter.Remove(email)
		limiter.RemoveDevices(email)
	}
	for email := range b.retiredUsers {
		limiter.Remove(email)
		limiter.RemoveDevices(email)
	}
	if err != nil {
		return fmt.Errorf("final traffic report failed (pending data retained in memory): %w", err)
	}
	return nil
}

// stopInboundListener closes the listening socket so nothing new arrives while
// the final drain runs.
//
// A failure is logged, never returned. The drain in shutdown is the only thing
// that gets pending traffic to the panel and Close is a sync.Once, so treating
// this as fatal would drop metered bytes for good -- and a listener that will
// not stop is not a reason to stop reporting what we already metered. Xray's
// manager fails this only when the tag is already gone, which the GetHandler
// probe covers, but the interface promises nothing of the sort, so keep the
// failure non-fatal.
func (b *Builder) stopInboundListener(ctx context.Context, manager inbound.Manager) {
	if _, err := manager.GetHandler(ctx, b.inboundTag); err != nil {
		return
	}
	if err := manager.RemoveHandler(ctx, b.inboundTag); err != nil {
		log.Errorln("Failed to remove inbound handler during shutdown:", err)
	}
}
