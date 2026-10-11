package notification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserCannotEnqueueOrDispatchPlatformOutbox(t *testing.T) {
	store := NewStore()
	channel := &channelStub{}
	event := eventFixture()
	if _, err := store.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	h := NewModule(store, channel, "token").Handler()
	for _, path := range []string{"/events", "/events/event-1/dispatch"} {
		body, _ := json.Marshal(event)
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		r.Header.Set("X-Internal-Token", "token")
		r.Header.Set("X-Browser-Module", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || channel.calls != 0 {
			t.Fatal("browser changed notification state", w.Code, channel.calls)
		}
	}
	if store.events[event.ID].Status != Pending || len(store.events) != 1 {
		t.Fatal("browser altered the outbox")
	}
	r := httptest.NewRequest(http.MethodPost, "/events/event-1/dispatch", nil)
	r.Header.Set("X-Internal-Token", "token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || channel.calls != 1 || store.events[event.ID].Status != Published {
		t.Fatal("trusted dispatch regressed", w.Code)
	}
}
