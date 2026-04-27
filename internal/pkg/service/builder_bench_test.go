package service

import (
	"fmt"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func BenchmarkReportTrafficUserSliceSelection(b *testing.B) {
	for _, userCount := range []int{100, 1000, 10000, 100000} {
		b.Run(fmt.Sprintf("users_%d", userCount), func(b *testing.B) {
			builder := &Builder{userList: benchmarkUsers(userCount)}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				builder.mu.Lock()
				users := builder.nextTrafficScanUsersLocked(trafficScanBatchSize)
				builder.mu.Unlock()
				if len(users) == 0 && userCount > 0 {
					b.Fatal("expected users")
				}
			}
		})
	}
}

func BenchmarkCompareUserList(b *testing.B) {
	for _, userCount := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("users_%d", userCount), func(b *testing.B) {
			builder := &Builder{}
			oldUsers := benchmarkUsers(userCount)
			newUsers := benchmarkUsers(userCount)
			if userCount > 0 {
				newUsers[userCount-1].Uuid = "changed"
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				deleted, added := builder.compareUserList(newUsers, oldUsers)
				if userCount > 0 && (len(deleted) != 1 || len(added) != 1) {
					b.Fatalf("deleted=%d added=%d", len(deleted), len(added))
				}
			}
		})
	}
}

func benchmarkUsers(count int) []api.UserInfo {
	users := make([]api.UserInfo, count)
	for i := range users {
		users[i] = api.UserInfo{
			Id:   i + 1,
			Uuid: fmt.Sprintf("uuid-%d", i+1),
		}
	}
	return users
}
