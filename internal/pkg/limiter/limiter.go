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
	"sync/atomic"
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

// Handle is one user's live speed limit. Every connection of the user holds
// the same Handle, resolved once by Lookup when the connection opens, and
// reads the current bucket with one atomic load per chunk -- no registry
// lock on the data path. Set and Remove swap the bucket, so a connection
// that is already open sees a new limit, a removed one, and the step from
// unlimited to limited on its next chunk.
type Handle struct {
	bucket atomic.Pointer[ratelimit.Bucket]
	// mbps is the limit the bucket was built for. Guarded by mu; only Set
	// reads it, to leave a bucket alone when its limit did not change.
	mbps int
}

var (
	mu      sync.RWMutex
	handles = map[string]*Handle{}
)

// Lookup returns the user's Handle, creating an unlimited one when the user
// has none yet. Creating it is what lets a limit registered after the
// connection opened still reach that connection: Set finds this Handle and
// swaps the bucket in rather than starting one nobody holds.
func Lookup(email string) *Handle {
	mu.RLock()
	h, ok := handles[email]
	mu.RUnlock()
	if ok {
		return h
	}
	mu.Lock()
	defer mu.Unlock()
	if h, ok = handles[email]; ok {
		return h
	}
	h = &Handle{}
	handles[email] = h
	return h
}

// Set registers the per-user speed limit. mbps <= 0 is treated as "no limit"
// and clears the bucket while keeping the Handle, so the user's open
// connections keep observing later changes. If the limit is unchanged the
// bucket is left alone to preserve the shared token balance.
func Set(email string, mbps int) {
	mu.Lock()
	defer mu.Unlock()
	h := handles[email]
	if mbps <= 0 {
		if h != nil {
			h.mbps = 0
			h.bucket.Store(nil)
		}
		return
	}
	// Clamp before the comparison below so two different absurd limits resolve
	// to the same stored value and do not churn the bucket.
	if mbps > maxMbps {
		mbps = maxMbps
	}
	if h == nil {
		h = &Handle{}
		handles[email] = h
	} else if h.mbps == mbps {
		return
	}
	bps := int64(mbps) * bitsPerMbps
	h.mbps = mbps
	h.bucket.Store(ratelimit.NewBucketWithQuantum(time.Second, bps, bps))
}

// Remove forgets the user and clears any bucket, so connections of a removed
// user that are still open run unlimited until they are torn down. A later
// Set for the same email starts a fresh Handle those connections do not see,
// which is right: the identity they belong to is gone. Safe to call when no
// entry exists.
func Remove(email string) {
	mu.Lock()
	h, ok := handles[email]
	delete(handles, email)
	mu.Unlock()
	if ok {
		h.bucket.Store(nil)
	}
}

// Bucket returns the user's current bucket, or nil if the user has no limit.
// It goes through the registry; the data path holds a Handle instead and
// reads it without a lock.
func Bucket(email string) *ratelimit.Bucket {
	mu.RLock()
	h, ok := handles[email]
	mu.RUnlock()
	if !ok {
		return nil
	}
	return h.bucket.Load()
}

// Bucket returns the limit this Handle enforces right now, or nil for none.
func (h *Handle) Bucket() *ratelimit.Bucket { return h.bucket.Load() }
