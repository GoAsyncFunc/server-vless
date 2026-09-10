package dispatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
)

func TestUserCounterConcurrentRegistration(t *testing.T) {
	sm, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sm.Close() })
	d := &DefaultDispatcher{stats: sm}
	const email = "stats@example.com"
	if c := d.userCounter(email, false, "uplink"); c != nil {
		t.Fatal("disabled statistics registered a counter")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			c := d.userCounter(email, true, "uplink")
			if c == nil {
				t.Error("counter registration returned nil")
				return
			}
			c.Add(1)
		})
	}
	wg.Wait()
	c := sm.GetCounter("user>>>" + email + ">>>traffic>>>uplink")
	if c == nil || c.Value() != 32 {
		t.Fatalf("concurrent registrations did not share one counter: %v", c)
	}
}

func TestTrackOnlineIPConnectionLifetime(t *testing.T) {
	sm, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sm.Close() })
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	const email = "online@example.com"
	trackOnlineIP(ctx1, sm, email, "192.0.2.1")
	trackOnlineIP(ctx2, sm, email, "192.0.2.1")
	om := sm.GetOnlineMap("user>>>" + email + ">>>online")
	if om == nil || om.Count() != 1 {
		t.Fatal("connections from the same IP should share one online entry")
	}
	cancel1()
	cancel2()
	deadline := time.Now().Add(2 * time.Second)
	for om.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if om.Count() != 0 {
		t.Fatal("online IP was not removed after both connections closed")
	}
}
