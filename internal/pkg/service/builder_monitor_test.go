package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	log "github.com/sirupsen/logrus"
	appdispatcher "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

const (
	testUuidA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testUuidB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

// fakePanel drives the monitor entry points directly so every panel result is
// injectable and every call is recorded. Embedding PanelAPI makes a method the
// test did not expect fail loudly instead of silently returning zero values.
type fakePanel struct {
	PanelAPI

	mu sync.Mutex

	node    *api.NodeInfo
	nodeErr error

	users    []api.UserInfo
	usersErr error
	userCall int
	// usersPanic, when non-nil, makes GetUserList panic with it. Used to prove
	// Builder.Start converts a panic into an error instead of killing the
	// process on the startup path.
	usersPanic any

	trafficErr  error
	trafficSent [][]api.UserTraffic

	onlineErr  error
	onlineSent []map[int][]netip.Addr

	alive    map[int]int
	aliveErr error
}

func (p *fakePanel) GetNodeInfo(context.Context) (*api.NodeInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.node, p.nodeErr
}

func (p *fakePanel) GetUserList(context.Context) ([]api.UserInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userCall++
	if p.usersPanic != nil {
		panic(p.usersPanic)
	}
	return p.users, p.usersErr
}

func (p *fakePanel) ReportUserTraffic(_ context.Context, traffic []api.UserTraffic) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trafficSent = append(p.trafficSent, traffic)
	return p.trafficErr
}

func (p *fakePanel) ReportNodeOnlineUsers(_ context.Context, data map[int][]netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onlineSent = append(p.onlineSent, data)
	return p.onlineErr
}

func (p *fakePanel) GetAliveList(context.Context) (map[int]int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.alive, p.aliveErr
}

func (p *fakePanel) setUsers(users []api.UserInfo, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users, p.usersErr = users, err
}

func (p *fakePanel) lastTraffic() []api.UserTraffic {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.trafficSent) == 0 {
		return nil
	}
	return p.trafficSent[len(p.trafficSent)-1]
}

func (p *fakePanel) lastOnline() map[int][]netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.onlineSent) == 0 {
		return nil
	}
	return p.onlineSent[len(p.onlineSent)-1]
}

// newTestNode returns the minimum node the inbound builder accepts. The tag it
// produces is derived from the port, so callers must use the returned tag
// rather than assuming one.
func newTestNode(t *testing.T) *api.NodeInfo {
	t.Helper()
	return &api.NodeInfo{
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: freePort(t)},
			Network:    "tcp",
			Encryption: "none",
		},
	}
}

// newTestInstance starts a real Xray core with one VLESS inbound. A real
// handler is the point: addUsers/removeUsers/populateHandler all go through
// proxy.UserManager, which a stub would not exercise.
func newTestInstance(t *testing.T, node *api.NodeInfo) (*core.Instance, string) {
	t.Helper()
	ic, err := InboundBuilder(&Config{}, node)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appdispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&appstats.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{ic},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance, ic.Tag
}

func testStatsManager(t *testing.T, instance *core.Instance) stats.Manager {
	t.Helper()
	sm, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		t.Fatal("stats manager feature is unavailable")
	}
	return sm
}

func testHandler(t *testing.T, instance *core.Instance, tag string) inbound.Handler {
	t.Helper()
	manager, ok := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		t.Fatal("inbound manager feature is unavailable")
	}
	handler, err := manager.GetHandler(context.Background(), tag)
	if err != nil {
		t.Fatalf("handler %q: %v", tag, err)
	}
	return handler
}

func testUserManager(t *testing.T, instance *core.Instance, tag string) proxy.UserManager {
	t.Helper()
	inboundProxy, ok := testHandler(t, instance, tag).(proxy.GetInbound)
	if !ok {
		t.Fatal("handler does not expose inbound")
	}
	manager, ok := inboundProxy.GetInbound().(proxy.UserManager)
	if !ok {
		t.Fatal("inbound does not support users")
	}
	return manager
}

func testUserEmails(t *testing.T, instance *core.Instance, tag string) []string {
	t.Helper()
	users := testUserManager(t, instance, tag).GetUsers(context.Background())
	emails := make([]string, 0, len(users))
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	slices.Sort(emails)
	return emails
}

func addTestTraffic(t *testing.T, instance *core.Instance, email string, up, down int64) {
	t.Helper()
	sm := testStatsManager(t, instance)
	for name, delta := range map[string]int64{"uplink": up, "downlink": down} {
		if delta == 0 {
			continue
		}
		counter, err := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>" + name)
		if err != nil {
			t.Fatal(err)
		}
		counter.Add(delta)
	}
}

func TestStartValidatesIntervalsBeforeTouchingPanel(t *testing.T) {
	panel := &fakePanel{}
	// A nil instance proves validation runs before anything needs the core.
	b := New(context.Background(), "vless_1", nil, &Config{}, nil, panel)
	err := b.Start()
	if err == nil || !strings.Contains(err.Error(), "FetchUsersInterval") {
		t.Fatalf("expected FetchUsersInterval validation error, got %v", err)
	}
	b = New(context.Background(), "vless_1", nil, &Config{FetchUsersInterval: time.Second}, nil, panel)
	err = b.Start()
	if err == nil || !strings.Contains(err.Error(), "ReportTrafficsInterval") {
		t.Fatalf("expected ReportTrafficsInterval validation error, got %v", err)
	}
	if panel.userCall != 0 {
		t.Fatal("interval validation must run before any panel request")
	}
}

func TestStartPropagatesUserListError(t *testing.T) {
	boom := errors.New("panel down")
	panel := &fakePanel{usersErr: boom}
	b := New(context.Background(), "vless_1", nil, startableConfig(), nil, panel)
	if err := b.Start(); !errors.Is(err, boom) {
		t.Fatalf("Start error = %v, want %v", err, boom)
	}
}

// An empty user list is the panel's normal way of saying "nobody in this
// node's group is entitled right now": getAvailableUsers filters on
// u+d < transfer_enable, expired_at, and banned. Refusing to start turned that
// into a crash-loop under systemd Restart=on-failure, with two panel requests
// per retry, while the same response at runtime is correctly handled as
// "evict everyone".
func TestStartToleratesEmptyUserList(t *testing.T) {
	var logs syncBuffer
	originalOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(originalOutput)

	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node}
	b := New(context.Background(), tag, instance, startableConfig(), node, panel)

	if err := b.Start(); err != nil {
		t.Fatalf("Start with an empty panel user list = %v, want nil", err)
	}
	if got := b.Users(); len(got) != 0 {
		t.Fatalf("Users() = %+v, want empty", got)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 0 {
		t.Fatalf("empty user list registered users with Xray: %v", emails)
	}
	// The operator's only signal, and the monitors must keep running so users
	// are picked up once the panel lists them again.
	if !strings.Contains(logs.String(), "no entitled users") {
		t.Fatalf("empty user list was not warned about: %q", logs.String())
	}
	for name, p := range map[string]*periodic{
		"fetch users": b.fetchUsersMonitorPeriodic,
		"heartbeat":   b.heartbeatMonitorPeriodic,
	} {
		if p == nil || p.done == nil {
			t.Fatalf("%s monitor was not started for an empty user list", name)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

// Builder.Start runs before cmd/server registers its deferred recoverPanic and
// urfave/cli recovers nothing, so a panic while applying panel data used to
// take the whole process down with no report of why.
func TestStartRecoversFromPanicInsteadOfKillingTheProcess(t *testing.T) {
	panel := &fakePanel{usersPanic: "boom from panel data"}
	b := New(context.Background(), "vless_1", nil, startableConfig(), nil, panel)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped Start: %v", r)
		}
	}()
	err := b.Start()
	if err == nil || !strings.Contains(err.Error(), "boom from panel data") {
		t.Fatalf("Start error = %v, want it to carry the panic value", err)
	}
}

func startableConfig() *Config {
	return &Config{
		FetchUsersInterval:     time.Hour,
		ReportTrafficsInterval: time.Hour,
		HeartbeatInterval:      time.Hour,
		CheckNodeInterval:      time.Hour,
	}
}

func TestStartAddsUsersAndStartsEveryMonitor(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, users: []api.UserInfo{{Id: 1, Uuid: testUuidA}}}
	b := New(context.Background(), tag, instance, startableConfig(), node, panel)

	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	if got := b.Users(); len(got) != 1 || got[0].Id != 1 {
		t.Fatalf("Start did not adopt the panel user list: %+v", got)
	}
	want := buildUserEmail(tag, 1, testUuidA)
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 || emails[0] != want {
		t.Fatalf("Start did not register the user with Xray: %v", emails)
	}
	for name, p := range map[string]*periodic{
		"fetch users":    b.fetchUsersMonitorPeriodic,
		"report traffic": b.reportTrafficsMonitorPeriodic,
		"check node":     b.checkNodeConfigMonitorPeriodic,
		"heartbeat":      b.heartbeatMonitorPeriodic,
	} {
		if p == nil {
			t.Fatalf("%s monitor was not created", name)
		}
		if p.done == nil {
			t.Fatalf("%s monitor was not started", name)
		}
	}
	// Start runs every monitor once immediately, so Close must be able to stop
	// them from whatever state they are in.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFetchUsersMonitorRetiresDeletedUserTraffic(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, users: []api.UserInfo{{Id: 1, Uuid: testUuidA}}}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = panel.users
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}
	email := buildUserEmail(tag, 1, testUuidA)
	addTestTraffic(t, instance, email, 123, 456)

	panel.setUsers(nil, nil)
	if err := b.fetchUsersMonitor(); err != nil {
		t.Fatal(err)
	}

	if emails := testUserEmails(t, instance, tag); len(emails) != 0 {
		t.Fatalf("deleted user still registered with Xray: %v", emails)
	}
	if _, ok := b.retiredUsers[email]; !ok {
		t.Fatal("deleted user's counters must stay registered for in-flight connections")
	}
	if got := b.pendingTraffic[1]; got != [2]int64{123, 456} {
		t.Fatalf("retired traffic not drained into pending: %v", b.pendingTraffic)
	}
	if got := b.Users(); len(got) != 0 {
		t.Fatalf("user list not updated after deletion: %v", got)
	}

	// Bytes written after the deletion by a connection that is still open must
	// be billed exactly once, not dropped and not double counted.
	addTestTraffic(t, instance, email, 7, 9)
	if err := b.reportTrafficsMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := panel.lastTraffic(); len(got) != 1 || got[0].UID != 1 || got[0].Upload != 130 || got[0].Download != 465 {
		t.Fatalf("first report = %+v, want uid 1 with 130/465", got)
	}
	if len(b.pendingTraffic) != 0 {
		t.Fatalf("acknowledged bytes left pending: %v", b.pendingTraffic)
	}
	if err := b.reportTrafficsMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := panel.lastTraffic(); len(got) != 0 {
		t.Fatalf("second report should be empty, got %+v", got)
	}
}

func TestFetchUsersMonitorReplacesUserOnUuidChange(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, users: []api.UserInfo{{Id: 1, Uuid: testUuidA}}}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = panel.users
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}
	oldEmail := buildUserEmail(tag, 1, testUuidA)
	addTestTraffic(t, instance, oldEmail, 50, 0)

	panel.setUsers([]api.UserInfo{{Id: 1, Uuid: testUuidB}}, nil)
	if err := b.fetchUsersMonitor(); err != nil {
		t.Fatal(err)
	}

	newEmail := buildUserEmail(tag, 1, testUuidB)
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 || emails[0] != newEmail {
		t.Fatalf("UUID change must re-register the user, got %v", emails)
	}
	if _, ok := b.retiredUsers[oldEmail]; !ok {
		t.Fatal("old UUID counters must stay registered")
	}
	if got := b.pendingTraffic[1]; got != [2]int64{50, 0} {
		t.Fatalf("old UUID traffic not drained: %v", b.pendingTraffic)
	}
	if got := b.Users(); len(got) != 1 || got[0].Uuid != testUuidB {
		t.Fatalf("user list not updated to the new UUID: %v", got)
	}
}

func TestFetchUsersMonitorRetriesFailedDeletion(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, users: []api.UserInfo{{Id: 1, Uuid: testUuidA}}}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = append([]api.UserInfo(nil), panel.users...)
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}
	email := buildUserEmail(tag, 1, testUuidA)

	panel.setUsers(nil, nil)
	b.inboundTag = "missing-handler"
	if err := b.fetchUsersMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := b.Users(); len(got) != 1 || got[0].Uuid != testUuidA {
		t.Fatalf("failed deletion must retain the old user snapshot: %v", got)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 || emails[0] != email {
		t.Fatalf("failed deletion must leave the Xray user registered: %v", emails)
	}

	// Restore the handler tag. The next poll must retry the deletion rather
	// than treating the already-fetched empty panel list as applied.
	b.inboundTag = tag
	if err := b.fetchUsersMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := b.Users(); len(got) != 0 {
		t.Fatalf("successful retry must commit the empty user snapshot: %v", got)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 0 {
		t.Fatalf("successful retry must remove the Xray user: %v", emails)
	}
}

func TestFetchUsersMonitorKeepsStateOnPanelError(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, users: []api.UserInfo{{Id: 1, Uuid: testUuidA}}}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = panel.users
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}
	email := buildUserEmail(tag, 1, testUuidA)
	addTestTraffic(t, instance, email, 11, 0)

	panel.setUsers(nil, errors.New("panel down"))
	if err := b.fetchUsersMonitor(); err != nil {
		t.Fatalf("a transient panel failure must not surface as an error: %v", err)
	}

	if got := b.Users(); len(got) != 1 || got[0].Uuid != testUuidA {
		t.Fatalf("user list must be untouched on panel failure: %v", got)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 || emails[0] != email {
		t.Fatalf("registered users must be untouched on panel failure: %v", emails)
	}
	// The counters were never drained, so nothing should be queued for reporting.
	if len(b.pendingTraffic) != 0 {
		t.Fatalf("no traffic should be drained on a failed refresh: %v", b.pendingTraffic)
	}
	if err := b.reportTrafficsMonitor(); err != nil {
		t.Fatal(err)
	}
	if got := panel.lastTraffic(); len(got) != 1 || got[0].Upload != 11 {
		t.Fatalf("traffic recorded before the failure must still be reported: %+v", got)
	}
}

func TestAddUsersSkipsAlreadyRegisteredUser(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)
	users := buildUser(tag, []api.UserInfo{{Id: 1, Uuid: testUuidA}}, "")

	if err := b.addUsers(users, tag); err != nil {
		t.Fatal(err)
	}
	// Second call must be a no-op: re-adding would reset Xray's validator entry.
	if err := b.addUsers(users, tag); err != nil {
		t.Fatal(err)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 {
		t.Fatalf("duplicate add registered %d users, want 1: %v", len(emails), emails)
	}
}

func TestAddUsersReportsMissingHandler(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)

	err := b.addUsers(buildUser(tag, []api.UserInfo{{Id: 1, Uuid: testUuidA}}, ""), "no-such-tag")
	if err == nil || !strings.Contains(err.Error(), "failed to get inbound handler") {
		t.Fatalf("expected missing-handler error, got %v", err)
	}
}

func TestRemoveUsersReportsMissingHandler(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)

	err := b.removeUsers([]string{"whatever"}, "no-such-tag")
	if err == nil || !strings.Contains(err.Error(), "failed to get inbound handler") {
		t.Fatalf("expected missing-handler error, got %v", err)
	}
}

type fakeUserManager struct {
	users      map[string]*protocol.MemoryUser
	removeErrs map[string]error
	removeCall []string
}

func (m *fakeUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	m.users[user.Email] = user
	return nil
}

func (m *fakeUserManager) RemoveUser(_ context.Context, email string) error {
	m.removeCall = append(m.removeCall, email)
	if err := m.removeErrs[email]; err != nil {
		return err
	}
	delete(m.users, email)
	return nil
}

func (m *fakeUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}

func (m *fakeUserManager) GetUsers(_ context.Context) []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users
}

func (m *fakeUserManager) GetUsersCount(_ context.Context) int64 {
	return int64(len(m.users))
}

func TestRemoveUsersReturnsExistingUserErrorsAndContinues(t *testing.T) {
	transient := errors.New("temporary removal failure")
	manager := &fakeUserManager{
		users: map[string]*protocol.MemoryUser{
			"failed":  {Email: "failed"},
			"removed": {Email: "removed"},
		},
		removeErrs: map[string]error{"failed": transient},
	}

	err := removeUsersFromManager(context.Background(), manager, []string{"failed", "removed", "unknown"})
	if !errors.Is(err, transient) || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("error = %v, want the failed user's error and email", err)
	}
	if got := manager.removeCall; !slices.Equal(got, []string{"failed", "removed"}) {
		t.Fatalf("remove calls = %v, want failed and removed only", got)
	}
	if manager.GetUser(context.Background(), "removed") != nil {
		t.Fatal("successful removal did not remove the user")
	}
	if manager.GetUser(context.Background(), "failed") == nil {
		t.Fatal("failed removal must leave the user for retry")
	}
}

func TestRemoveUsersIsIdempotentForUnknownEmail(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)

	// A user the handler never had is already in the desired state and must
	// not make the batch fail.
	if err := b.removeUsers([]string{"never-registered"}, tag); err != nil {
		t.Fatalf("unknown email should not fail the batch: %v", err)
	}
}

// stubHandler satisfies inbound.Handler without being a proxy.GetInbound, which
// is the shape populateHandler has to reject.
type stubHandler struct{ tag string }

func (h *stubHandler) Start() error                           { return nil }
func (h *stubHandler) Close() error                           { return nil }
func (h *stubHandler) Tag() string                            { return h.tag }
func (h *stubHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (h *stubHandler) ProxySettings() *serial.TypedMessage    { return nil }

func TestPopulateHandlerRejectsHandlerWithoutInbound(t *testing.T) {
	b := &Builder{}
	err := b.populateHandler(&stubHandler{tag: "t"}, "t", nil)
	if err == nil || !strings.Contains(err.Error(), "does not expose inbound") {
		t.Fatalf("expected inbound-exposure error, got %v", err)
	}
}

func TestPopulateHandlerRegistersUsersWithNodeFlow(t *testing.T) {
	node := newTestNode(t)
	node.Vless.Flow = "xtls-rprx-vision"
	instance, tag := newTestInstance(t, node)
	b := New(context.Background(), tag, instance, &Config{}, node, nil)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}

	if err := b.populateHandler(testHandler(t, instance, tag), tag, node); err != nil {
		t.Fatal(err)
	}
	email := buildUserEmail(tag, 1, testUuidA)
	manager := testUserManager(t, instance, tag)
	user := manager.GetUser(context.Background(), email)
	if user == nil {
		t.Fatalf("user %q was not registered", email)
	}
	account, ok := user.Account.ToProto().(*vless.Account)
	if !ok {
		t.Fatalf("account is %T, want *vless.Account", user.Account.ToProto())
	}
	if account.Id != testUuidA || account.Flow != "xtls-rprx-vision" {
		t.Fatalf("account = %+v, want uuid %s with the node flow", account, testUuidA)
	}
}

func TestCheckNodeConfigMonitorToleratesPanelFailure(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node, nodeErr: errors.New("panel down")}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}

	if err := b.checkNodeConfigMonitor(); err != nil {
		t.Fatalf("a transient panel failure must not surface as an error: %v", err)
	}
	if b.inboundTag != tag {
		t.Fatalf("inbound tag changed on a failed fetch: %q", b.inboundTag)
	}
	if emails := testUserEmails(t, instance, tag); len(emails) != 1 {
		t.Fatalf("users lost on a failed fetch: %v", emails)
	}
}

func TestCheckNodeConfigMonitorIgnoresNilNodeInfo(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	// nil node info with no pending snapshot: nothing to apply, nothing to do.
	panel := &fakePanel{node: nil}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)

	if err := b.checkNodeConfigMonitor(); err != nil {
		t.Fatal(err)
	}
	if b.inboundTag != tag {
		t.Fatalf("inbound tag changed without a node snapshot: %q", b.inboundTag)
	}
}

func TestCheckNodeConfigMonitorLeavesUnchangedNodeAlone(t *testing.T) {
	node := newTestNode(t)
	instance, tag := newTestInstance(t, node)
	panel := &fakePanel{node: node}
	b := New(context.Background(), tag, instance, &Config{}, node, panel)
	b.userList = []api.UserInfo{{Id: 1, Uuid: testUuidA}}
	if err := b.addNewUser(b.userList); err != nil {
		t.Fatal(err)
	}

	if err := b.checkNodeConfigMonitor(); err != nil {
		t.Fatal(err)
	}
	if b.inboundTag != tag {
		t.Fatalf("unchanged config must not reload the inbound: %q", b.inboundTag)
	}
	// The snapshot is retained even when nothing changed: UniProxy commits its
	// ETag before the local apply succeeds, so a later 304 has to be able to
	// retry the last desired state.
	if b.pendingNodeInfo != node {
		t.Fatal("the latest node snapshot must be kept for a later 304 retry")
	}
}
