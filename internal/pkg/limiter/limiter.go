// Package limiter provides per-user bandwidth rate limiting backed by a
// token-bucket registry keyed on the Xray user email
// ("<inboundTag>|<uid>|<uuid>"). Builder maintains the registry when user
// lists change; Dispatcher consults it at connection setup to wrap the
// data links.
//
// One bucket per user is shared across uplink and downlink, so a user
// limit of N Mbps is a cap on total throughput in either direction,
// matching typical v2board semantics.
package limiter

import (
	"sync"
	"time"

	"github.com/juju/ratelimit"
)

// bitsPerMbps is the conversion from Mbps (stored in v2board) to bytes/sec.
const bitsPerMbps = 1_000_000 / 8

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
// left alone so in-flight connections keep a stable rate.
func Set(email string, mbps int) {
	mu.Lock()
	defer mu.Unlock()
	if mbps <= 0 {
		delete(buckets, email)
		return
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
// Callers should cache the returned value for the lifetime of a connection
// rather than looking it up per packet.
func Bucket(email string) *ratelimit.Bucket {
	mu.RLock()
	e, ok := buckets[email]
	mu.RUnlock()
	if !ok {
		return nil
	}
	return e.bucket
}
