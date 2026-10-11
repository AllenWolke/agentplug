package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOriginCookieRefreshAndNoInternalCredentialHeaders(t *testing.T) {
	var refresh atomic.Int32
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin || r.Header.Get("X-Internal-Token") != "" || r.Header.Get("Authorization") != "" {
			t.Error("wrong public authentication boundary")
		}
		switch r.URL.Path {
		case "/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "expired", Path: "/"})
			w.WriteHeader(204)
		case "/auth/refresh":
			refresh.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "new", Path: "/"})
			w.WriteHeader(204)
		default:
			cookie, e := r.Cookie("access")
			if e != nil || cookie.Value != "new" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
	defer server.Close()
	origin = server.URL
	c, e := New(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Login(context.Background(), Credentials{Username: "user", Password: "fixture-password"}); e != nil {
		t.Fatal(e)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if e = c.Do(context.Background(), "GET", "/api/test", nil, &out); e != nil || !out.OK || refresh.Load() != 1 {
		t.Fatalf("refresh failed %v", e)
	}
}
func TestConcurrentExpirationRefreshesOneSessionGeneration(t *testing.T) {
	const n = 12
	var initial, refresh atomic.Int32
	gate := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/refresh" {
			refresh.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "new", Path: "/"})
			w.WriteHeader(204)
			return
		}
		cookie, e := r.Cookie("access")
		if e != nil || cookie.Value != "new" {
			if initial.Add(1) == n {
				close(gate)
			}
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	c, _ := New(server.URL)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out any
			if e := c.Do(context.Background(), "GET", "/api/test", nil, &out); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if refresh.Load() != 1 {
		t.Fatalf("refresh requests=%d", refresh.Load())
	}
}
func TestRedirectAndPrivateErrorBodiesNeverEscape(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, 302)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"password=should-not-escape"}`)
	}))
	defer server.Close()
	c, _ := New(server.URL)
	if e := c.Do(context.Background(), "GET", "/redirect", nil, nil); e == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("credentials followed redirect")
	}
	e := c.Do(context.Background(), "GET", "/private", nil, nil)
	if e == nil || strings.Contains(e.Error(), "should-not-escape") {
		t.Fatalf("private error escaped: %v", e)
	}
}
func TestStructuredPlatformErrorCodeIsPreserved(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		fmt.Fprint(w, `{"error":{"code":"REVISION_CONFLICT"}}`)
	}))
	defer s.Close()
	c, _ := New(s.URL)
	if e := c.Do(context.Background(), "GET", "/api/test", nil, nil); e == nil || !strings.Contains(e.Error(), "REVISION_CONFLICT") {
		t.Fatalf("%v", e)
	}
}

func TestAcceptedErrorBodyIsNotAnEmptyRun(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"error":"RUN_QUEUED_STATUS_RECONCILIATION_REQUIRED"}`)
	}))
	defer s.Close()
	c, _ := New(s.URL)
	var run Resource
	if e := c.Do(context.Background(), "POST", "/runs", map[string]any{}, &run); e == nil || !strings.Contains(e.Error(), "RUN_QUEUED_STATUS_RECONCILIATION_REQUIRED") {
		t.Fatal("accepted error body silently decoded as empty Run", e)
	}
}
func TestPagingRejectsChangingCountAndDuplicateInstances(t *testing.T) {
	for _, mode := range []string{"valid", "count-changed", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := 1
				if r.URL.Query().Get("page") == "2" {
					page = 2
				}
				total := 101
				start, size := 0, 100
				if page == 2 {
					start, size = 100, 1
				}
				if mode == "count-changed" && page == 2 {
					total = 102
				}
				if mode == "duplicate" && page == 2 {
					start = 0
				}
				items := []map[string]any{}
				for i := 0; i < size; i++ {
					items = append(items, map[string]any{"installation_id": fmt.Sprintf("inst-%d", start+i)})
				}
				json.NewEncoder(w).Encode(map[string]any{"page": page, "page_size": 100, "total": total, "items": items})
			}))
			defer s.Close()
			c, _ := New(s.URL)
			d, e := c.Discover(context.Background())
			if mode == "valid" {
				if e != nil || len(d.Items) != 101 {
					t.Fatalf("%v count=%d", e, len(d.Items))
				}
			} else if e == nil {
				t.Fatal("inconsistent discovery accepted")
			}
		})
	}
}
func TestURLNeverAcceptsEmbeddedCredentialOrPath(t *testing.T) {
	for _, value := range []string{"file:///tmp/test", "http://user:secret@host", "https://host/base", "https://host?token=secret", "https://host#private"} {
		if _, e := New(value); e == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}
