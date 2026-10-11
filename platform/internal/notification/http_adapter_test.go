package notification

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHTTPAdapterSendsEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	adapter, err := NewHTTPAdapter(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.Send(context.Background(), Event{ID: "e1", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Topic: "topic", EventType: "event", PartitionKey: "p", Payload: map[string]any{"ok": true}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTPAdapterRejectsInvalidURL(t *testing.T) {
	for _, address := range []string{"file:///etc/passwd", "https://user:password@notify.invalid/event", "https://notify.invalid/event#secret"} {
		if _, err := NewHTTPAdapter(address); err == nil {
			t.Fatal("expected invalid URL")
		}
	}
}

type failedNotificationTransport struct{}

func (failedNotificationTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("private-transport-details")
}

func TestHTTPAdapterFailureDoesNotExposeWebhookSecret(t *testing.T) {
	adapter, err := NewHTTPAdapter("https://notify.invalid/event?token=private-webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	adapter.Client.Transport = failedNotificationTransport{}
	err = adapter.Send(context.Background(), Event{ID: "redaction-test", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Topic: "topic", EventType: "event", PartitionKey: "p", Payload: map[string]any{"ok": true}})
	if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "notify.invalid") {
		t.Fatal("notification failure must not expose URL or transport detail")
	}
}

func TestHTTPAdapterDoesNotForwardEventThroughRedirect(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var forwarded atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer other.Close()
			approved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", other.URL)
				w.WriteHeader(status)
			}))
			defer approved.Close()
			adapter, err := NewHTTPAdapter(approved.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = adapter.Send(context.Background(), Event{ID: "redirect-test", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Topic: "topic", EventType: "event", PartitionKey: "p", Payload: map[string]any{"private": "notification"}})
			if err == nil {
				t.Error("redirected delivery must fail")
			}
			if forwarded.Load() != 0 {
				t.Error("event escaped the configured notification endpoint")
			}
		})
	}
}
