package service

import (
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestAddPendingTrafficLockedAccumulatesTraffic(t *testing.T) {
	b := &Builder{pendingTraffic: map[int][2]int64{1: {100, 200}}}

	b.addPendingTrafficLocked(1, 30, 40)
	b.addPendingTrafficLocked(2, 5, 0)
	b.addPendingTrafficLocked(3, 0, 0)

	if got, want := b.pendingTraffic[1], [2]int64{130, 240}; got != want {
		t.Fatalf("pending traffic for user 1 = %v, want %v", got, want)
	}
	if got, want := b.pendingTraffic[2], [2]int64{5, 0}; got != want {
		t.Fatalf("pending traffic for user 2 = %v, want %v", got, want)
	}
	if _, ok := b.pendingTraffic[3]; ok {
		t.Fatal("zero traffic should not create pending entry")
	}
}

func TestRuntimeConfigWarningReset(t *testing.T) {
	applied := &api.NodeInfo{Routes: []api.Route{{Id: 1, Action: api.RouteActionBlock, Match: []string{"domain:old.example"}}}}
	changed := &api.NodeInfo{Routes: []api.Route{{Id: 2, Action: api.RouteActionBlock, Match: []string{"domain:new.example"}}}}
	b := &Builder{nodeInfo: applied, lastRuntimeConfigWarning: changed}

	if !b.runtimeConfigUnchanged(applied) {
		t.Fatal("applied runtime config should be unchanged")
	}
	b.resetRuntimeConfigWarningLocked()
	if b.lastRuntimeConfigWarning != nil {
		t.Fatal("runtime warning snapshot was not reset")
	}
	if b.runtimeWarningAlreadyLogged(changed) {
		t.Fatal("changed runtime config should warn again after reset")
	}
}

func TestClassifyNodeConfigChangeRequiresRestartForMixedRuntimeAndInboundChange(t *testing.T) {
	if got := classifyNodeConfigChange(false, false); got != nodeConfigChangeNeedsRestart {
		t.Fatalf("mixed runtime and inbound change = %v, want %v", got, nodeConfigChangeNeedsRestart)
	}
}

func TestClassifyNodeConfigChangeAllowsInboundReloadOnlyWhenRuntimeUnchanged(t *testing.T) {
	if got := classifyNodeConfigChange(false, true); got != nodeConfigChangeReloadInbound {
		t.Fatalf("inbound-only change = %v, want %v", got, nodeConfigChangeReloadInbound)
	}
}

func TestClassifyNodeConfigChangeWarnsForRuntimeOnlyChange(t *testing.T) {
	if got := classifyNodeConfigChange(true, false); got != nodeConfigChangeNeedsRestart {
		t.Fatalf("runtime-only change = %v, want %v", got, nodeConfigChangeNeedsRestart)
	}
}

func TestNextTrafficScanUsersLockedAdvancesCursorInBatches(t *testing.T) {
	b := &Builder{userList: []api.UserInfo{
		{Id: 1, Uuid: "uuid-1"},
		{Id: 2, Uuid: "uuid-2"},
		{Id: 3, Uuid: "uuid-3"},
	}}

	first := b.nextTrafficScanUsersLocked(2)
	second := b.nextTrafficScanUsersLocked(2)
	third := b.nextTrafficScanUsersLocked(2)

	assertUsers(t, first, []api.UserInfo{{Id: 1, Uuid: "uuid-1"}, {Id: 2, Uuid: "uuid-2"}})
	assertUsers(t, second, []api.UserInfo{{Id: 3, Uuid: "uuid-3"}})
	assertUsers(t, third, []api.UserInfo{{Id: 1, Uuid: "uuid-1"}, {Id: 2, Uuid: "uuid-2"}})
}

func TestCompareUserList(t *testing.T) {
	b := &Builder{}

	oldUsers := []api.UserInfo{
		{Id: 1, Uuid: "uuid-1"},
		{Id: 2, Uuid: "uuid-2"},
		{Id: 3, Uuid: "uuid-3"},
	}
	newUsers := []api.UserInfo{
		{Id: 1, Uuid: "uuid-1"},
		{Id: 2, Uuid: "uuid-2-new"},
		{Id: 4, Uuid: "uuid-4"},
	}

	deleted, added := b.compareUserList(newUsers, oldUsers)

	assertUsers(t, deleted, []api.UserInfo{
		{Id: 2, Uuid: "uuid-2"},
		{Id: 3, Uuid: "uuid-3"},
	})
	assertUsers(t, added, []api.UserInfo{
		{Id: 2, Uuid: "uuid-2-new"},
		{Id: 4, Uuid: "uuid-4"},
	})
}

func TestCompareUserListUnchanged(t *testing.T) {
	b := &Builder{}
	users := []api.UserInfo{{Id: 1, Uuid: "uuid-1"}}

	deleted, added := b.compareUserList(users, users)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("expected no changes, got deleted=%v added=%v", deleted, added)
	}
}

func assertUsers(t *testing.T, got, want []api.UserInfo) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d; got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Id != want[i].Id || got[i].Uuid != want[i].Uuid {
			t.Fatalf("user[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
