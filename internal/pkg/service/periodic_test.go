package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeriodicRetriesAndJoins(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	p := &periodic{Interval: time.Millisecond, Execute: func() error {
		if calls.Add(1) == 1 {
			return errors.New("temporary apply failure")
		}
		close(entered)
		<-release
		return nil
	}}
	p.Start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("error disabled polling")
	}
	p.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if p.Wait(ctx) == nil {
		t.Fatal("Wait returned while callback active")
	}
	close(release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := p.Wait(ctx2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatal("callback ran after Stop")
	}
}
