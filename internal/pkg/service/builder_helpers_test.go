package service

import (
	"bytes"
	"sync"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// syncBuffer is a bytes.Buffer that tolerates concurrent use. Tests capture the
// global log output while a started Builder keeps logging from its monitor
// goroutines, so a bare bytes.Buffer races between the goroutine's Write and
// the test's String.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestClassifyNodeConfigChangeNoChange(t *testing.T) {
	if got := classifyNodeConfigChange(true, true); got != nodeConfigChangeNone {
		t.Fatalf("no-change classification = %v, want %v", got, nodeConfigChangeNone)
	}
}

func TestRuntimeConfigUnchangedTreatsNilAsUnchanged(t *testing.T) {
	b := &Builder{nodeInfo: nil}
	if !b.runtimeConfigUnchanged(&api.NodeInfo{Id: 7}) {
		t.Fatal("nil current nodeInfo should be considered unchanged")
	}
	b = &Builder{nodeInfo: &api.NodeInfo{Id: 1}}
	if !b.runtimeConfigUnchanged(nil) {
		t.Fatal("nil incoming nodeInfo should be considered unchanged")
	}
}

func TestRuntimeWarningAlreadyLoggedReturnsFalseWhenNoWarning(t *testing.T) {
	b := &Builder{}
	if b.runtimeWarningAlreadyLogged(&api.NodeInfo{Id: 1}) {
		t.Fatal("no prior warning means we have not logged for this snapshot")
	}
}

func TestRuntimeWarningAlreadyLoggedReturnsFalseWhenIncomingNil(t *testing.T) {
	b := &Builder{lastRuntimeConfigWarning: &api.NodeInfo{Id: 9}}
	if b.runtimeWarningAlreadyLogged(nil) {
		t.Fatal("nil incoming nodeInfo cannot match a prior warning snapshot")
	}
}

func TestNextTrafficScanUsersLockedReturnsEmptyForEmptyUserList(t *testing.T) {
	b := &Builder{}
	got := b.nextTrafficScanUsersLocked(8)
	if len(got) != 0 {
		t.Fatalf("empty user list should return no users, got %d", len(got))
	}
	if b.trafficScanCursor != 0 {
		t.Fatalf("cursor must remain at 0, got %d", b.trafficScanCursor)
	}
}

func TestNextTrafficScanUsersLockedResetsCursorWhenStale(t *testing.T) {
	b := &Builder{
		userList:          []api.UserInfo{{Id: 1, Uuid: "uuid-1"}, {Id: 2, Uuid: "uuid-2"}},
		trafficScanCursor: 99,
	}
	got := b.nextTrafficScanUsersLocked(2)
	if len(got) != 2 {
		t.Fatalf("expected full batch after cursor reset, got %d", len(got))
	}
	if got[0].Id != 1 || got[1].Id != 2 {
		t.Fatalf("expected users [1,2] after reset, got %+v", got)
	}
}

func TestNextTrafficScanUsersLockedRequestLargerThanList(t *testing.T) {
	b := &Builder{
		userList: []api.UserInfo{{Id: 1, Uuid: "uuid-1"}},
	}
	got := b.nextTrafficScanUsersLocked(10)
	if len(got) != 1 {
		t.Fatalf("expected 1 user, got %d", len(got))
	}
	// Cursor wraps back to 0 once the end is reached.
	if b.trafficScanCursor != 0 {
		t.Fatalf("cursor should wrap to 0, got %d", b.trafficScanCursor)
	}
}

func TestCompareUserListAllAddedWhenOldEmpty(t *testing.T) {
	b := &Builder{}
	added := []api.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}

	deleted, got := b.compareUserList(added, nil)
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions, got %v", deleted)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 added, got %d", len(got))
	}
}

func TestCompareUserListAllDeletedWhenNewEmpty(t *testing.T) {
	b := &Builder{}
	prev := []api.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}

	deleted, added := b.compareUserList(nil, prev)
	if len(deleted) != 2 {
		t.Fatalf("expected 2 deletions, got %d", len(deleted))
	}
	if len(added) != 0 {
		t.Fatalf("expected no additions, got %v", added)
	}
}

func TestUsersReturnsIndependentSnapshot(t *testing.T) {
	b := &Builder{userList: []api.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}}
	snap := b.Users()
	if len(snap) != 2 {
		t.Fatalf("snapshot length = %d, want 2", len(snap))
	}
	// Mutating the snapshot must not affect the builder's stored list.
	snap[0].Id = 999
	if b.userList[0].Id != 1 {
		t.Fatal("Users() snapshot must not alias internal storage")
	}
}

func TestSameRuntimeConfigDetectsRouteChange(t *testing.T) {
	a := &api.NodeInfo{Routes: []api.Route{{Id: 1, Action: api.RouteActionBlock}}}
	b := &api.NodeInfo{Routes: []api.Route{{Id: 1, Action: api.RouteActionBlockIP}}}
	if sameRuntimeConfig(a, b) {
		t.Fatal("different route actions must not be considered equal")
	}
}

func TestSameRuntimeConfigDetectsLegacyRulesChange(t *testing.T) {
	a := &api.NodeInfo{Rules: api.Rules{Regexp: []string{"old"}}}
	b := &api.NodeInfo{Rules: api.Rules{Regexp: []string{"new"}}}
	if sameRuntimeConfig(a, b) {
		t.Fatal("different legacy rules must not be considered equal")
	}
}

func TestSameRuntimeConfigDetectsRawDNSChange(t *testing.T) {
	a := &api.NodeInfo{RawDNS: api.RawDNS{DNSJson: []byte(`{"servers":["1.1.1.1"]}`)}}
	b := &api.NodeInfo{RawDNS: api.RawDNS{DNSJson: []byte(`{"servers":["8.8.8.8"]}`)}}
	if sameRuntimeConfig(a, b) {
		t.Fatal("different DNSJson must not be considered equal")
	}
}
