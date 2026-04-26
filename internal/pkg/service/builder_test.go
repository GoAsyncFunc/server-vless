package service

import (
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

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
