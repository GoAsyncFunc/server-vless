package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

type shutdownPanel struct {
	PanelAPI
	mu        sync.Mutex
	calls     int
	entered   chan struct{}
	failFinal bool
}

func (p *shutdownPanel) ReportUserTraffic(ctx context.Context, traffic []api.UserTraffic) error {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	if call == 1 && p.entered != nil {
		close(p.entered)
		<-ctx.Done()
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.failFinal {
		return errors.New("panel unavailable")
	}
	return nil
}

func TestShutdownWaitsForReportThenUsesFreshContext(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appstats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	panel := &shutdownPanel{entered: make(chan struct{})}
	b := New(context.Background(), "test", instance, &Config{}, nil, panel)
	b.pendingTraffic = map[int][2]int64{1: {100, 200}}
	b.reportTrafficsMonitorPeriodic = &periodic{Interval: time.Second, Execute: b.reportTrafficsMonitor}
	b.reportTrafficsMonitorPeriodic.Start()
	select {
	case <-panel.entered:
	case <-time.After(time.Second):
		t.Fatal("report not started")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.pendingTraffic) != 0 {
		t.Fatal("final report did not acknowledge pending bytes")
	}
	panel.mu.Lock()
	defer panel.mu.Unlock()
	if panel.calls != 2 {
		t.Fatalf("report calls %d", panel.calls)
	}
}

func TestShutdownReportFailureRetainsPendingTraffic(t *testing.T) {
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appstats.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	panel := &shutdownPanel{failFinal: true}
	b := New(context.Background(), "test", instance, &Config{}, nil, panel)
	b.pendingTraffic = map[int][2]int64{1: {100, 200}}
	if b.Close() == nil {
		t.Fatal("failure was hidden")
	}
	if b.pendingTraffic[1] != [2]int64{100, 200} {
		t.Fatal("unacknowledged bytes discarded")
	}
}
