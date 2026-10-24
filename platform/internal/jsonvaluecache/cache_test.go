package jsonvaluecache

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

type sample struct{ IDs []string }

func cloneSample(v sample) sample { v.IDs = append([]string(nil), v.IDs...); return v }

func TestDecodeReuseNeverSharesMutableValuesOrAcceptsChangedBytes(t *testing.T) {
	var calls atomic.Int32
	c := New(4, 128, func(raw []byte) (sample, error) {
		calls.Add(1)
		var v sample
		err := json.Unmarshal(raw, &v)
		return v, err
	}, cloneSample)
	first, err := c.Decode([]byte(`{"IDs":["original"]}`))
	if err != nil {
		t.Fatal(err)
	}
	first.IDs[0] = "caller mutation"
	second, err := c.Decode([]byte(`{"IDs":["original"]}`))
	if err != nil || second.IDs[0] != "original" || calls.Load() != 1 {
		t.Fatal(second, err, calls.Load())
	}
	second.IDs[0] = "another mutation"
	changed, err := c.Decode([]byte(`{"IDs":["revoked"]}`))
	if err != nil || changed.IDs[0] != "revoked" || calls.Load() != 2 {
		t.Fatal(changed, err, calls.Load())
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Decode([]byte(`{"IDs":[`)); err == nil {
			t.Fatal("corrupt JSON cached as valid")
		}
	}
	if calls.Load() != 4 {
		t.Fatal("decode errors were reused", calls.Load())
	}
}

func TestDecodeCacheEvictsByCountAndSourceBytesAndBypassesOversize(t *testing.T) {
	var calls int
	c := New(2, 6, func(raw []byte) (string, error) { calls++; return string(raw), nil }, func(v string) string { return v })
	for _, s := range []string{"aa", "bb", "aa", "cc", "bb"} {
		_, _ = c.Decode([]byte(s))
	}
	if calls != 4 || len(c.items) != 2 || c.bytes != 4 {
		t.Fatal(calls, len(c.items), c.bytes)
	}
	_, _ = c.Decode([]byte("1234567"))
	_, _ = c.Decode([]byte("1234567"))
	if calls != 6 || len(c.items) != 2 || c.bytes != 4 {
		t.Fatal("oversized value retained", calls, c.bytes)
	}
	_, _ = c.Decode([]byte("123456"))
	if len(c.items) != 1 || c.bytes != 6 {
		t.Fatal(len(c.items), c.bytes)
	}
}

func TestConcurrentDecodeResultsRemainIsolated(t *testing.T) {
	c := New(8, 1024, func(raw []byte) (sample, error) { var v sample; err := json.Unmarshal(raw, &v); return v, err }, cloneSample)
	var pending sync.WaitGroup
	for i := 0; i < 32; i++ {
		pending.Add(1)
		go func(index int) {
			defer pending.Done()
			for j := 0; j < 30; j++ {
				value, err := c.Decode([]byte(`{"IDs":["original"]}`))
				if err != nil || value.IDs[0] != "original" {
					t.Error(value, err)
					return
				}
				value.IDs[0] = fmt.Sprint(index)
			}
		}(i)
	}
	pending.Wait()
	value, err := c.Decode([]byte(`{"IDs":["original"]}`))
	if err != nil || value.IDs[0] != "original" {
		t.Fatal(value, err)
	}
}
