package notification

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestAuthorizationRevisionTransportAndFailClosed(t *testing.T) {
	ctx := context.Background()
	const version = uint64(9007199254740993)
	e, err := NewAuthorizationChangedEvent("change", "tenant", "department", "application", "user", "subject", version)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Event
	if err := json.Unmarshal(body, &roundTrip); err != nil {
		t.Fatal(err)
	}
	current := version
	var outage error
	calls := 0
	a := VersionedAuthorizationAdapter{ReadRevision: func(_ context.Context, tenant, kind, id string) (uint64, error) {
		calls++
		if tenant != "tenant" || kind != "user" || id != "subject" {
			t.Fatal("reader scope mismatch")
		}
		return current, outage
	}}
	if err := a.Send(ctx, roundTrip); err != nil {
		t.Fatal(err)
	}
	current++
	if err := a.Send(ctx, roundTrip); err != nil {
		t.Fatalf("stale event: %v", err)
	}
	current = version - 1
	if !errors.Is(a.Send(ctx, roundTrip), ErrAuthorizationRevision) {
		t.Fatal("future event acknowledged")
	}
	outage = errors.New("authority unavailable")
	if !errors.Is(a.Send(ctx, roundTrip), outage) {
		t.Fatal("outage acknowledged")
	}
	if calls != 4 {
		t.Fatalf("expected a live read on each delivery, got %d", calls)
	}
	if !errors.Is((VersionedAuthorizationAdapter{}).Send(ctx, roundTrip), ErrAuthorizationRevision) {
		t.Fatal("missing authority accepted")
	}
	if !errors.Is(a.Send(ctx, eventFixture()), ErrAdapterUnavailable) {
		t.Fatal("ordinary notification silently dropped")
	}
}

func TestAuthorizationRevisionRejectsMalformedEnvelope(t *testing.T) {
	mutations := map[string]func(*Event){
		"numeric revision":      func(e *Event) { e.Payload["aggregate_revision"] = float64(2) },
		"noncanonical revision": func(e *Event) { e.Payload["aggregate_revision"] = "02" },
		"zero revision":         func(e *Event) { e.Payload["aggregate_revision"] = "0" },
		"extra data":            func(e *Event) { e.Payload["token"] = "forbidden" },
		"unknown principal":     func(e *Event) { e.Payload["subject_type"] = "administrator" },
		"partition scope":       func(e *Event) { e.TenantID = "other" },
		"event id":              func(e *Event) { e.ID = "other" },
		"topic":                 func(e *Event) { e.Topic = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e, err := NewAuthorizationChangedEvent("change", "tenant", "department", "application", "user", "subject", 2)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&e)
			a := VersionedAuthorizationAdapter{ReadRevision: func(context.Context, string, string, string) (uint64, error) {
				t.Fatal("malformed event reached authority")
				return 2, nil
			}}
			if !errors.Is(a.Send(context.Background(), e), ErrInvalidEvent) {
				t.Fatal("malformed event acknowledged")
			}
		})
	}
}

func TestAuthorizationRevisionConsumerDeduplicatesAndRetries(t *testing.T) {
	e, err := NewAuthorizationChangedEvent("change", "tenant", "department", "application", "service_principal", "machine", 2)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	current := uint64(1)
	a := VersionedAuthorizationAdapter{ReadRevision: func(context.Context, string, string, string) (uint64, error) { calls++; return current, nil }}
	m := NewModuleWithEventBus(NewStore(), &offsetBusStub{}, a, "")
	if !errors.Is(m.deliverConsumed(context.Background(), e), ErrAuthorizationRevision) {
		t.Fatal("future event not retried")
	}
	current = 2
	if err := m.deliverConsumed(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := m.deliverConsumed(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("duplicate entered authority: %d", calls)
	}
}
