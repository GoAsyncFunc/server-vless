package limiter

import (
	"context"
	"time"
)

// Wait looks up the current bucket on every bounded reservation. Existing
// connections therefore observe changed limits, including unlimited -> limited.
// Polling also lets cancellation or removing a limit interrupt a queued wait.
func Wait(ctx context.Context, email string, bytes int64) error {
	// Lazily allocate one timer per blocked transfer, not per polling tick.
	// Unlimited and immediately available paths remain allocation-free.
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
		bucket := Bucket(email)
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
