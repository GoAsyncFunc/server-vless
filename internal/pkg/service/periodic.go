package service

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// periodic owns one non-overlapping worker. Errors do not disable future polls.
// Stop prevents new work; Wait joins an in-flight callback before core teardown.
type periodic struct {
	Interval time.Duration
	Execute  func() error
	once     sync.Once
	cancel   context.CancelFunc
	done     chan struct{}
}

func (p *periodic) Start() error {
	p.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancel = cancel
		p.done = make(chan struct{})
		go func() {
			defer close(p.done)
			for {
				if ctx.Err() != nil {
					return
				}
				if err := p.Execute(); err != nil {
					log.Warn("periodic task failed; retrying next interval")
				}
				timer := time.NewTimer(p.Interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	})
	return nil
}
func (p *periodic) Stop() {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
}
func (p *periodic) Wait(ctx context.Context) error {
	if p == nil || p.done == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
