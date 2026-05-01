package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// stubNodeInfoFetcher returns a scripted sequence of (NodeInfo, error) pairs.
// Each call to GetNodeInfo consumes one entry; once exhausted it returns the
// final entry indefinitely. Counts call attempts for assertions.
type stubNodeInfoFetcher struct {
	results []nodeInfoResult
	calls   atomic.Int32
}

type nodeInfoResult struct {
	info *api.NodeInfo
	err  error
}

func (s *stubNodeInfoFetcher) GetNodeInfo(_ context.Context) (*api.NodeInfo, error) {
	idx := int(s.calls.Add(1)) - 1
	if idx >= len(s.results) {
		idx = len(s.results) - 1
	}
	r := s.results[idx]
	return r.info, r.err
}

// withFastBackoffs replaces the package-level backoff schedule with a near-zero
// schedule so retry logic completes in milliseconds. Restores the original on
// cleanup.
func withFastBackoffs(t *testing.T, attempts int) {
	t.Helper()
	original := initialNodeInfoBackoffs
	fast := make([]time.Duration, attempts)
	for i := range fast {
		fast[i] = time.Millisecond
	}
	initialNodeInfoBackoffs = fast
	t.Cleanup(func() {
		initialNodeInfoBackoffs = original
	})
}

func TestFetchInitialNodeInfoSucceedsOnFirstAttempt(t *testing.T) {
	withFastBackoffs(t, 5)
	want := &api.NodeInfo{Id: 42}
	stub := &stubNodeInfoFetcher{results: []nodeInfoResult{{info: want}}}

	got, err := fetchInitialNodeInfo(context.Background(), stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if calls := stub.calls.Load(); calls != 1 {
		t.Fatalf("expected exactly 1 call, got %d", calls)
	}
}

func TestFetchInitialNodeInfoRetriesUntilSuccess(t *testing.T) {
	withFastBackoffs(t, 5)
	want := &api.NodeInfo{Id: 7}
	stub := &stubNodeInfoFetcher{results: []nodeInfoResult{
		{err: errors.New("503 transient")},
		{err: errors.New("503 transient")},
		{info: want},
	}}

	got, err := fetchInitialNodeInfo(context.Background(), stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if calls := stub.calls.Load(); calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestFetchInitialNodeInfoExhaustsBackoffsAndReturnsLastError(t *testing.T) {
	withFastBackoffs(t, 3)
	finalErr := errors.New("final 500")
	stub := &stubNodeInfoFetcher{results: []nodeInfoResult{
		{err: errors.New("first")},
		{err: errors.New("second")},
		{err: errors.New("third")},
		{err: finalErr},
	}}

	got, err := fetchInitialNodeInfo(context.Background(), stub)
	if got != nil {
		t.Fatalf("expected nil node info on exhaustion, got %+v", got)
	}
	if err == nil {
		t.Fatal("expected an error after retries are exhausted")
	}
	if err.Error() != finalErr.Error() {
		t.Fatalf("expected last error %q, got %q", finalErr, err)
	}
	// 1 initial + 3 retries = 4 attempts
	if calls := stub.calls.Load(); calls != 4 {
		t.Fatalf("expected 4 calls, got %d", calls)
	}
}

func TestFetchInitialNodeInfoHonorsContextCancellation(t *testing.T) {
	// Use a long backoff so the context cancellation interrupts the retry sleep.
	original := initialNodeInfoBackoffs
	initialNodeInfoBackoffs = []time.Duration{500 * time.Millisecond, 500 * time.Millisecond}
	t.Cleanup(func() { initialNodeInfoBackoffs = original })

	stub := &stubNodeInfoFetcher{results: []nodeInfoResult{
		{err: errors.New("transient")},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first attempt fails and we enter the backoff sleep.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	got, err := fetchInitialNodeInfo(ctx, stub)
	if got != nil {
		t.Fatalf("expected nil node info on cancel, got %+v", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
