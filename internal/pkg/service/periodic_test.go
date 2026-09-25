package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestPeriodicRecoversFromPanic(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	p := &periodic{Interval: time.Millisecond, Execute: func() error {
		if calls.Add(1) == 1 {
			panic("temporary callback panic")
		}
		close(entered)
		<-release
		return nil
	}}
	p.Start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("panic stopped polling")
	}
	p.Stop()
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("callback calls = %d, want 2", calls.Load())
	}
}

func TestPeriodicRetriesAndJoins(t *testing.T) {
	var logs bytes.Buffer
	originalOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(originalOutput)

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
	if !strings.Contains(logs.String(), "temporary apply failure") {
		t.Fatalf("log does not contain callback error: %q", logs.String())
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
