package knowledge

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCacheObservationCountsActualCallsAndRetainsBypass(t *testing.T) {
	ctx, o := WithCacheObservation(context.Background())
	cache := NewStageCache(8, 1024, time.Minute)
	loads := 0
	load := func(context.Context) ([]byte, error) { loads++; return []byte("private cached value"), nil }
	for i := 0; i < 2; i++ {
		if _, _, err := cache.Do(ctx, "key", load); err != nil {
			t.Fatal(err)
		}
	}
	if lookups, hits, failures := o.Snapshot(); lookups != 2 || hits != 1 || failures != 0 || loads != 1 {
		t.Fatal("wrong actual miss/hit counts", lookups, hits, failures, loads)
	}
	var bypass *StageCache
	if _, hit, err := bypass.Do(ctx, "key", load); hit || err != nil {
		t.Fatal(hit, err)
	}
	if _, _, err := cache.Do(ctx, "", load); err != nil {
		t.Fatal(err)
	}
	if lookups, _, _ := o.Snapshot(); lookups != 2 {
		t.Fatal("bypassed cache invented a lookup", lookups)
	}
	_, other := WithCacheObservation(context.Background())
	if lookups, hits, failures := other.Snapshot(); lookups != 0 || hits != 0 || failures != 0 {
		t.Fatal("query counters leaked across contexts")
	}
}

func TestCacheObservationTracksFailedLoadsAndCancelledWaiter(t *testing.T) {
	cache := NewStageCache(8, 1024, time.Minute)
	ctx, o := WithCacheObservation(context.Background())
	want := errors.New("private failure")
	if _, _, err := cache.Do(ctx, "failed", func(context.Context) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	entered, finish := make(chan struct{}), make(chan struct{})
	leader := make(chan error, 1)
	go func() {
		_, _, err := cache.Do(ctx, "wait", func(context.Context) ([]byte, error) { close(entered); <-finish; return []byte("value"), nil })
		leader <- err
	}()
	<-entered
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, hit, err := cache.Do(waitCtx, "wait", func(context.Context) ([]byte, error) { t.Error("waiter invoked provider"); return nil, nil }); hit || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(hit, err)
	}
	close(finish)
	if err := <-leader; err != nil {
		t.Fatal(err)
	}
	if lookups, hits, failures := o.Snapshot(); lookups != 3 || hits != 0 || failures != 2 {
		t.Fatal("cancelled cache attempt was lost or became hit", lookups, hits, failures)
	}
}

func TestCacheObservationCoalescedWaiterIsOneLogicalHit(t *testing.T) {
	cache := NewStageCache(8, 1024, time.Minute)
	leaderCtx, leaderObs := WithCacheObservation(context.Background())
	waitCtx, waitObs := WithCacheObservation(context.Background())
	entered, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := cache.Do(leaderCtx, "wait", func(context.Context) ([]byte, error) { close(entered); <-finish; return []byte("value"), nil })
		done <- err
	}()
	<-entered
	go func() { time.Sleep(20 * time.Millisecond); close(finish) }()
	_, hit, err := cache.Do(waitCtx, "wait", func(context.Context) ([]byte, error) { t.Error("coalesced waiter loaded value"); return nil, nil })
	if err != nil || !hit {
		t.Fatal(hit, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if l, h, f := leaderObs.Snapshot(); l != 1 || h != 0 || f != 0 {
		t.Fatal(l, h, f)
	}
	if l, h, f := waitObs.Snapshot(); l != 1 || h != 1 || f != 0 {
		t.Fatal(l, h, f)
	}
}
