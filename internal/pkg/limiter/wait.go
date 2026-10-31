package limiter

import (
	"context"
	"time"
)

// Wait reserves bytes against the user's current limit. It is the
// registry-keyed form of Handle.Wait for callers that have no Handle; the
// data path resolves a Handle once per connection instead of paying the
// registry lookup on every chunk.
func Wait(ctx context.Context, email string, bytes int64) error {
	return Lookup(email).Wait(ctx, bytes)
}

// Wait reserves bytes against the Handle's current limit. Unlimited is the
// hot path and stays as close to free as a call can be: no defer, no timer,
// one atomic load. The checks run in the same order as the limited loop, so
// a cancelled connection stops here just the same.
func (h *Handle) Wait(ctx context.Context, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.bucket.Load() == nil {
		return nil
	}
	return h.waitLimited(ctx, bytes)
}

// waitLimited polls the limit on every bounded reservation, so a change made
// while the transfer is blocked -- removed, lowered, or unlimited becoming
// limited -- and cancellation both interrupt the wait. It allocates one timer
// per blocked transfer, not per polling tick.
func (h *Handle) waitLimited(ctx context.Context, bytes int64) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for bytes > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := h.bucket.Load()
		if bucket == nil {
			return nil
		}
		quantum := bucket.Capacity() / 20
		if quantum < 1 {
			quantum = 1
		}
		if quantum > bytes {
			quantum = bytes
		}
		taken := bucket.TakeAvailable(quantum)
		bytes -= taken
		if taken == quantum {
			continue
		}
		if timer == nil {
			timer = time.NewTimer(10 * time.Millisecond)
		} else {
			timer.Reset(10 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
