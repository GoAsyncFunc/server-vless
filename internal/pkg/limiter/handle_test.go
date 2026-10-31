package limiter

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A connection resolves its Handle when it opens. Everything the panel does
// to the limit afterwards -- set it, change it, clear it, set it again --
// has to reach that same Handle, or the connection runs on a stale limit.
func TestHandleSeesEveryLimitChangeAfterLookup(t *testing.T) {
	const email = "handle-late-limit"
	defer Remove(email)

	h := Lookup(email)
	if h.Bucket() != nil {
		t.Fatal("a user with no limit must start unlimited")
	}
	Set(email, 8)
	first := h.Bucket()
	if first == nil {
		t.Fatal("a limit set after Lookup did not reach the handle")
	}
	if Lookup(email) != h {
		t.Fatal("Lookup handed out a second handle for the same email")
	}
	Set(email, 8)
	if h.Bucket() != first {
		t.Fatal("an unchanged limit replaced the bucket and its token balance")
	}
	Set(email, 16)
	if h.Bucket() == first || h.Bucket() == nil {
		t.Fatal("a changed limit did not replace the bucket")
	}
	Set(email, 0)
	if h.Bucket() != nil {
		t.Fatal("clearing the limit did not reach the handle")
	}
	Set(email, 8)
	if h.Bucket() == nil {
		t.Fatal("limiting again after unlimited did not reach the handle")
	}
}

// Remove is for an identity that is gone: its open connections stop being
// throttled and the registry forgets it, so a same-named identity later
// starts from scratch instead of inheriting the old Handle.
func TestRemoveClearsTheHandleAndForgetsTheEmail(t *testing.T) {
	const email = "handle-remove"
	Set(email, 8)
	h := Lookup(email)

	Remove(email)

	if h.Bucket() != nil {
		t.Fatal("a removed user's open connections should run unlimited")
	}
	if Bucket(email) != nil {
		t.Fatal("the registry still knows a removed email")
	}
	fresh := Lookup(email)
	defer Remove(email)
	if fresh == h {
		t.Fatal("a removed email must get a fresh handle")
	}
}

// The data path reads the bucket without a lock while Set swaps it; the race
// detector has to agree that this is sound.
func TestHandleConcurrentSetAndWait(t *testing.T) {
	const email = "handle-concurrent"
	defer Remove(email)
	h := Lookup(email)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = h.Wait(ctx, 1)
			}
		})
	}
	for i := range 200 {
		Set(email, 1+i%3)
		Set(email, 0)
	}
	cancel()
	wg.Wait()
}

func BenchmarkHandleWaitUnlimited(b *testing.B) {
	const email = "bench-handle-unlimited"
	h := Lookup(email)
	defer Remove(email)
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(32768)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := h.Wait(ctx, 32768); err != nil {
				b.Fatal(err)
			}
		}
	})
}
