package service

import (
	"context"
	"runtime/debug"
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

// Start launches the worker. It cannot fail: the first call wins via sync.Once
// and every later call is a no-op, so there is no error to report.
func (p *periodic) Start() {
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
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Errorf("periodic task panicked; retrying next interval: %v\n%s", r, debug.Stack())
						}
					}()
					if err := p.Execute(); err != nil {
						log.Warnf("periodic task failed; retrying next interval: %v", err)
					}
				}()
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
