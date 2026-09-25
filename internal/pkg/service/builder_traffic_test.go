package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	appdispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

// newStatlessInstance is a core without the stats app, used to prove the
// counter and online-map paths degrade to no-ops instead of panicking.
func newStatlessInstance(t *testing.T) *core.Instance {
	t.Helper()
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appdispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

func TestGetTrafficReadsUnknownUserAsZero(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)

	// GetCounter does not create, so a user the node never saw reads as zero.
	if up, down := b.getTraffic(buildUserEmail(tag, 1, testUuidA)); up != 0 || down != 0 {
		t.Fatalf("unknown user traffic = %d/%d, want 0/0", up, down)
	}
}

func TestGetTrafficHandlesSingleSidedCounter(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)
	email := buildUserEmail(tag, 1, testUuidA)
	sm := testStatsManager(t, instance)
	up, err := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	up.Add(42)

	// Only the uplink counter exists: the missing downlink side must read as
	// zero rather than making the whole user look absent.
	if got, down := b.getTraffic(email); got != 42 || down != 0 {
		t.Fatalf("uplink-only traffic = %d/%d, want 42/0", got, down)
	}
	if got, down := b.getTraffic(email); got != 0 || down != 0 {
		t.Fatalf("draining must be destructive: second read = %d/%d", got, down)
	}
}

func TestGetTrafficDrainsBothDirections(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)
	email := buildUserEmail(tag, 1, testUuidA)
	addTestTraffic(t, instance, email, 123, 456)

	if up, down := b.getTraffic(email); up != 123 || down != 456 {
		t.Fatalf("traffic = %d/%d, want 123/456", up, down)
	}
	if up, down := b.getTraffic(email); up != 0 || down != 0 {
		t.Fatalf("second drain = %d/%d, want 0/0", up, down)
	}
}

func TestGetTrafficWithoutStatsManagerReadsZero(t *testing.T) {
	b := New(context.Background(), "vless_1", newStatlessInstance(t), &Config{}, nil, nil)
	if up, down := b.getTraffic("whatever"); up != 0 || down != 0 {
		t.Fatalf("core without stats = %d/%d, want 0/0", up, down)
	}
}

func TestHeartbeatMonitorReportsOnlineIps(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	email := buildUserEmail(tag, 1, testUuidA)
	sm := testStatsManager(t, instance)
	om, err := sm.GetOrRegisterOnlineMap("user>>>" + email + ">>>online")
	if err != nil {
		t.Fatal(err)
	}
	om.AddIP("192.0.2.1")
	om.AddIP("2001:db8::1")

	if err := b.heartbeatMonitor(); err != nil {
		t.Fatal(err)
	}

	reported := panel.lastOnline()
	if len(reported) != 1 {
		t.Fatalf("reported %v, want exactly one user", reported)
	}
	ips := make([]string, 0, len(reported[1]))
	for _, ip := range reported[1] {
		ips = append(ips, ip.String())
	}
	slices.Sort(ips)
	if !slices.Equal(ips, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("reported ips = %v", ips)
	}
	if got := b.lastReportedIPs[1]; len(got) != 2 {
		t.Fatalf("local credit snapshot = %v, want both ips", got)
	}
	if b.lastReportedAt[1].IsZero() {
		t.Fatal("local credit timestamp was not recorded")
	}
}

func TestHeartbeatMonitorSkipsUsersWithoutOnlineMap(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	// No online map was ever registered for this user, which is the normal
	// state before the first connection arrives.
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}

	if err := b.heartbeatMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := panel.lastOnline(); len(got) != 0 {
		t.Fatalf("user without an online map must not be reported: %v", got)
	}
	// An empty heartbeat must not seed a credit snapshot, otherwise every user
	// that has ever connected would get a permanent entry.
	if b.lastReportedIPs != nil || b.lastReportedAt != nil {
		t.Fatal("an empty heartbeat must not create a local credit snapshot")
	}
}

func TestHeartbeatMonitorIgnoresUnparsableIp(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	sm := testStatsManager(t, instance)
	om, err := sm.GetOrRegisterOnlineMap("user>>>" + buildUserEmail(tag, 1, testUuidA) + ">>>online")
	if err != nil {
		t.Fatal(err)
	}
	om.AddIP("not-an-ip")
	om.AddIP("192.0.2.1")

	if err := b.heartbeatMonitor(); err != nil {
		t.Fatal(err)
	}
	reported := panel.lastOnline()
	if len(reported) != 1 || len(reported[1]) != 1 || reported[1][0].String() != "192.0.2.1" {
		t.Fatalf("unparsable ip leaked into the report: %v", reported)
	}
}

func TestHeartbeatMonitorKeepsSnapshotOnPanelFailure(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, onlineErr: errors.New("panel down")}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	sm := testStatsManager(t, instance)
	om, err := sm.GetOrRegisterOnlineMap("user>>>" + buildUserEmail(tag, 1, testUuidA) + ">>>online")
	if err != nil {
		t.Fatal(err)
	}
	om.AddIP("192.0.2.1")
	earlier := time.Now().Add(-time.Minute)
	b.lastReportedIPs = map[int][]string{1: {"198.51.100.1"}}
	b.lastReportedAt = map[int]time.Time{1: earlier}

	if err := b.heartbeatMonitor(); err != nil {
		t.Fatalf("a panel failure must not surface as an error: %v", err)
	}
	// The previous snapshot must survive: it describes what the panel last
	// acknowledged, and overwriting it on a failed send would grant local
	// device credit the panel never recorded.
	if got := b.lastReportedIPs[1]; !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Fatalf("credit snapshot overwritten on failure: %v", got)
	}
	if !b.lastReportedAt[1].Equal(earlier) {
		t.Fatalf("credit timestamp overwritten on failure: %v", b.lastReportedAt[1])
	}
}

func TestHeartbeatMonitorWithoutStatsManagerIsNoop(t *testing.T) {
	b := New(context.Background(), "vless_1", newStatlessInstance(t), &Config{}, nil, &fakePanel{})
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}

	if err := b.heartbeatMonitor(); err != nil {
		t.Fatalf("core without stats must not fail the heartbeat: %v", err)
	}
}

func TestReportTrafficsMonitorRetainsPendingUntilAcknowledged(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, trafficErr: errors.New("panel down")}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	email := buildUserEmail(tag, 1, testUuidA)
	addTestTraffic(t, instance, email, 100, 200)

	if err := b.reportTrafficsMonitor(); err == nil {
		t.Fatal("a panel failure must surface as an error so the monitor retries")
	}
	// The counters were already drained, so the bytes must still be queued.
	if got := b.pendingTraffic[1]; got != [2]int64{100, 200} {
		t.Fatalf("unacknowledged bytes were discarded: %v", got)
	}

	panel.trafficErr = nil
	if err := b.reportTrafficsMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := panel.lastTraffic(); len(got) != 1 || got[0].Upload != 100 || got[0].Download != 200 {
		t.Fatalf("retry reported %+v, want the retained 100/200", got)
	}
	if len(b.pendingTraffic) != 0 {
		t.Fatalf("acknowledged bytes left pending: %v", b.pendingTraffic)
	}
}
