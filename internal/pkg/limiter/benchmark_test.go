package limiter

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
)

func BenchmarkDeviceAdmission(b *testing.B) {
	for _, users := range []int{1, 1024} {
		b.Run(fmt.Sprintf("users=%d", users), func(b *testing.B) {
			emails := make([]string, users)
			for i := range emails {
				emails[i] = fmt.Sprintf("bench-device-%d", i)
				SetDeviceLimit(emails[i], 10)
			}
			defer func() {
				for _, email := range emails {
					RemoveDevices(email)
				}
			}()
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				email := emails[int(next.Add(1)-1)%users]
				for pb.Next() {
					release, ok := AcquireDevice(email, "192.0.2.1")
					if !ok {
						b.Error("unexpected rejection")
						return
					}
					release()
				}
			})
		})
	}
}

func BenchmarkWaitUnlimited(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(32768)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := Wait(ctx, "bench-unlimited", 32768); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkBucketLookup(b *testing.B) {
	Set("bench-bucket", 100)
	defer Remove("bench-bucket")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if Bucket("bench-bucket") == nil {
				b.Fatal("missing bucket")
			}
		}
	})
}

func BenchmarkWaitLimited(b *testing.B) {
	// A fixed-size workload includes real throttling, not an artificial refill
	// loop. Run with -benchtime=100x to avoid long adaptive benchmark runs.
	Set("bench-limited", 8)
	defer Remove("bench-limited")
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(32768)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Wait(ctx, "bench-limited", 32768); err != nil {
			b.Fatal(err)
		}
	}
}
