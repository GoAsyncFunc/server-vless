package service

import (
	"context"
	"errors"
	"fmt"
	"time"

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
			return fmt.Errorf("%w: waiting for background tasks: %v", ErrShutdownIncomplete, err)
		}
	}
	// Remove listeners before the final drain. Stats remain available until the
	// owner closes the core. This does not guarantee delivery after process kill.
	if b.instance != nil {
		if manager, ok := b.instance.GetFeature(inbound.ManagerType()).(inbound.Manager); ok {
			if _, err := manager.GetHandler(ctx, b.inboundTag); err == nil {
				if err := manager.RemoveHandler(ctx, b.inboundTag); err != nil {
					return fmt.Errorf("stop inbound: %w", err)
				}
			}
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
