package limiter

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDeviceReservations(t *testing.T) {
	const email = "device-test"
	defer RemoveDevices(email)
	SetDeviceLimit(email, 2)
	SyncDevices(email, 1, nil) // one device already active on another node
	release, ok := AcquireDevice(email, "192.0.2.1")
	if !ok {
		t.Fatal("first local IP rejected")
	}
	second, ok := AcquireDevice(email, "192.0.2.1")
	if !ok {
		t.Fatal("same IP must share a slot")
	}
	if _, ok := AcquireDevice(email, "192.0.2.2"); ok {
		t.Fatal("excess IP admitted")
	}
	release()
	if _, ok := AcquireDevice(email, "192.0.2.2"); ok {
		t.Fatal("slot released while same IP still connected")
	}
	second()
	last, ok := AcquireDevice(email, "192.0.2.2")
	if !ok {
		t.Fatal("slot not released")
	}
	last()
	SyncDevices(email, 2, []string{"192.0.2.2"})
	last, ok = AcquireDevice(email, "192.0.2.3")
	if !ok {
		t.Fatal("own reported IP counted twice")
	}
	last()
}

func TestConcurrentDeviceAdmission(t *testing.T) {
	const email = "device-concurrent"
	defer RemoveDevices(email)
	SetDeviceLimit(email, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var releases []func()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		wg.Go(func() {
			if release, ok := AcquireDevice(email, ip); ok {
				mu.Lock()
				releases = append(releases, release)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(releases) != 1 {
		t.Fatalf("admitted %d devices", len(releases))
	}
	for _, release := range releases {
		release()
	}
}

func TestWaitObservesLiveSpeedChanges(t *testing.T) {
	const email = "dynamic-speed"
	defer Remove(email)
	Set(email, 1)
	Bucket(email).TakeAvailable(Bucket(email).Capacity())
	done := make(chan error, 1)
	go func() { done <- Wait(context.Background(), email, 1_000_000) }()
	select {
	case <-done:
		t.Fatal("rate limit not enforced")
	case <-time.After(40 * time.Millisecond):
	}
	Set(email, 0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("existing wait ignored unlimited update")
	}
	Set(email, 1)
	Bucket(email).TakeAvailable(Bucket(email).Capacity())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if Wait(ctx, email, 1_000_000) == nil {
		t.Fatal("unlimited -> limited update not enforced")
	}
	Set(email, 1)
	Bucket(email).TakeAvailable(Bucket(email).Capacity())
	go func() { done <- Wait(context.Background(), email, 1_000_000) }()
	time.Sleep(20 * time.Millisecond)
	Set(email, 100)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("existing wait ignored faster speed")
	}
}
