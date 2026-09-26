// Package limiter provides per-user bandwidth rate limiting backed by a
// token-bucket registry keyed on the Xray user email
// ("<inboundTag>|<uid>|<uuid>"). Builder maintains the registry when user
// lists change; Dispatcher consults it while transferring data so existing
// connections observe updated limits.
//
// One bucket per user is shared across uplink and downlink, so a user
// limit of N Mbps is a cap on total throughput in either direction,
// matching typical v2board semantics.
package limiter

import (
	"math"
	"sync"
	"time"

	"github.com/juju/ratelimit"
)

// bitsPerMbps is the conversion from Mbps (stored in v2board) to bytes/sec.
const bitsPerMbps = 1_000_000 / 8

// maxMbps is the largest limit whose byte/sec rate still fits in an int64.
// v2board stores speed_limit in an int(11) column (max 2147483647), so a stock
// panel cannot get within four orders of magnitude of this -- but the value
// arrives over the network unvalidated, and int64(mbps)*bitsPerMbps
// overflowing into a non-positive capacity panics inside
// ratelimit.NewBucketWithQuantum. Saturating keeps an absurd limit meaning
// "effectively unlimited" instead of taking the process down.
const maxMbps = math.MaxInt64 / bitsPerMbps

type entry struct {
	mbps   int
	bucket *ratelimit.Bucket
}

var (
	mu      sync.RWMutex
	buckets = map[string]*entry{}
)

// Set registers the per-user speed limit. mbps <= 0 is treated as "no limit"
// and removes any existing entry. If the limit is unchanged the bucket is
// left alone to preserve the shared token balance.
func Set(email string, mbps int) {
	mu.Lock()
	defer mu.Unlock()
	if mbps <= 0 {
		delete(buckets, email)
		return
	}
	// Clamp before the comparison below so two different absurd limits resolve
	// to the same stored value and do not churn the bucket.
	if mbps > maxMbps {
		mbps = maxMbps
	}
	if e, ok := buckets[email]; ok && e.mbps == mbps {
		return
	}
	bps := int64(mbps) * bitsPerMbps
	buckets[email] = &entry{
		mbps:   mbps,
		bucket: ratelimit.NewBucketWithQuantum(time.Second, bps, bps),
	}
}

// Remove drops any bucket for the user. Safe to call when no entry exists.
func Remove(email string) {
	mu.Lock()
	delete(buckets, email)
	mu.Unlock()
}

// Bucket returns the bucket for the user, or nil if the user has no limit.
// Callers must not cache it for the lifetime of a connection. Use Wait for
// bounded reservations that observe runtime changes and cancellation.
func Bucket(email string) *ratelimit.Bucket {
	mu.RLock()
	e, ok := buckets[email]
	mu.RUnlock()
	if !ok {
		return nil
	}
	return e.bucket
}
