package service

import (
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// The reconcile cycle usually sees the list it saw a minute ago. That case
// must cost one pass and allocate nothing, and the fast path must not change
// what the diff says about the cases that do differ.
func TestCompareUserListFastPathAgreesWithTheDiff(t *testing.T) {
	b := &Builder{}
	users := []api.UserInfo{{Id: 1, Uuid: "a"}, {Id: 2, Uuid: "b", SpeedLimit: 10}}

	deleted, added := b.compareUserList(users, append([]api.UserInfo(nil), users...))
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("identical lists: deleted=%v added=%v, want nothing", deleted, added)
	}

	// A changed limit on the same identity is not an add or a delete.
	changed := append([]api.UserInfo(nil), users...)
	changed[1].SpeedLimit = 20
	deleted, added = b.compareUserList(changed, users)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("changed limit: deleted=%v added=%v, want nothing", deleted, added)
	}

	// A new UUID on the same id is a replacement; an extra user is an add.
	replaced := append([]api.UserInfo(nil), users...)
	replaced[0].Uuid = "a2"
	replaced = append(replaced, api.UserInfo{Id: 3, Uuid: "c"})
	deleted, added = b.compareUserList(replaced, users)
	if len(deleted) != 1 || deleted[0].Id != 1 {
		t.Fatalf("replacement: deleted=%v, want the old id 1", deleted)
	}
	if len(added) != 2 || added[0].Id != 1 || added[1].Id != 3 {
		t.Fatalf("replacement: added=%v, want ids 1 and 3", added)
	}
}
