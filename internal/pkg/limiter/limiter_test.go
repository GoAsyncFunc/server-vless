package limiter

import (
	"testing"
)

func TestSetRemove(t *testing.T) {
	const email = "vless_443|1|abc"
	defer Remove(email)

	if Bucket(email) != nil {
		t.Fatalf("expected nil bucket before Set")
	}

	Set(email, 10)
	b1 := Bucket(email)
	if b1 == nil {
		t.Fatalf("expected non-nil bucket after Set(10)")
	}

	// Same speed → same bucket reference (no recreate, in-flight conns stable).
	Set(email, 10)
	if Bucket(email) != b1 {
		t.Errorf("Set with same mbps recreated the bucket")
	}

	// Different speed → new bucket.
	Set(email, 20)
	b2 := Bucket(email)
	if b2 == b1 {
		t.Errorf("Set with new mbps did not recreate the bucket")
	}

	// Zero / negative → drop.
	Set(email, 0)
	if Bucket(email) != nil {
		t.Errorf("Set(0) should remove the entry")
	}

	Set(email, 5)
	Remove(email)
	if Bucket(email) != nil {
		t.Errorf("Remove did not drop the entry")
	}
}

func TestBucketRate(t *testing.T) {
	const email = "rate-test"
	defer Remove(email)

	Set(email, 8) // 8 Mbps = 1_000_000 byte/s
	b := Bucket(email)
	if b == nil {
		t.Fatal("expected bucket")
	}

	// Token capacity should equal rate (1-second burst).
	if got, want := b.Capacity(), int64(1_000_000); got != want {
		t.Errorf("capacity = %d, want %d", got, want)
	}
}
