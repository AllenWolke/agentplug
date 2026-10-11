package security

import (
	"net/http"
	"testing"
)

func TestTraceparentFormatsOnlyWellFormedTraceIDs(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	parent := Traceparent(traceID)
	if len(parent) != 55 || parent[:3] != "00-" || parent[35:36] != "-" || parent[52:] != "-01" {
		t.Fatalf("unexpected traceparent: %q", parent)
	}
	if parent[3:35] != traceID {
		t.Fatalf("trace id was not preserved: %q", parent)
	}
	// Same trace id must yield the same header on every replica, otherwise two
	// replicas of the same run would disagree on the parent span.
	// 同一 trace id 在任意副本上必须得到同一头，否则同一 run 的两个副本会给出不同的父跨度。
	if Traceparent(traceID) != parent {
		t.Fatal("traceparent is not deterministic")
	}
	for _, bad := range []string{"", "short", traceID + "0", "zbf92f3577b34da6a3ce929d0e0e4736"} {
		if Traceparent(bad) != "" {
			t.Fatalf("accepted malformed trace id %q", bad)
		}
	}
}

func TestOutboundHeadersNeverForwardCredentials(t *testing.T) {
	inbound := http.Header{}
	inbound.Set("Authorization", "Bearer caller-secret")
	inbound.Set("Cookie", "session=caller-session")
	inbound.Set("Host", "attacker.example.com")
	inbound.Set("X-Internal-Admin", "true")
	inbound.Set("Accept", "application/json")
	inbound.Set("Traceparent", "00-00000000000000000000000000000000-0000000000000000-01")

	headers := OutboundHeaders(inbound, "4bf92f3577b34da6a3ce929d0e0e4736", "idem-1")

	for _, forbidden := range []string{"Authorization", "Cookie", "Host", "X-Internal-Admin"} {
		if value := headers.Get(forbidden); value != "" {
			t.Fatalf("credential header %s leaked upstream: %q", forbidden, value)
		}
	}
	if headers.Get("Content-Type") != "application/json" {
		t.Fatalf("content type was not fixed: %q", headers.Get("Content-Type"))
	}
	if headers.Get("Accept") != "application/json" {
		t.Fatalf("allow-listed header was dropped: %q", headers.Get("Accept"))
	}
	if headers.Get("Idempotency-Key") != "idem-1" {
		t.Fatalf("idempotency key was not propagated: %q", headers.Get("Idempotency-Key"))
	}
}

func TestOutboundHeadersTrustedTraceWinsOverCallerValue(t *testing.T) {
	inbound := http.Header{}
	// A caller must not be able to pin its own parent span: the verified
	// execution contract owns the trace identity.
	// 调用方不能固定自己的父跨度：trace 身份由已校验的执行契约掌握。
	inbound.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	inbound.Set("Idempotency-Key", "caller-supplied")

	const trusted = "4bf92f3577b34da6a3ce929d0e0e4736"
	headers := OutboundHeaders(inbound, trusted, "contract-supplied")

	if headers.Get("Traceparent") != Traceparent(trusted) {
		t.Fatalf("caller traceparent was not overridden: %q", headers.Get("Traceparent"))
	}
	if headers.Get("Idempotency-Key") != "contract-supplied" {
		t.Fatalf("caller idempotency key was not overridden: %q", headers.Get("Idempotency-Key"))
	}
}

func TestOutboundHeadersWithoutTrustedValuesOmitsThem(t *testing.T) {
	headers := OutboundHeaders(http.Header{}, "", "")
	if headers.Get("Traceparent") != "" || headers.Get("Idempotency-Key") != "" {
		t.Fatalf("invented trace/idempotency headers: %v", headers)
	}
	if headers.Get("Content-Type") != "application/json" {
		t.Fatal("content type must still be fixed")
	}
}
