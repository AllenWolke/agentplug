package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoogleDoHSelectionAndConfigurationBoundaries(t *testing.T) {
	for _, hosts := range [][]string{nil, {}, {"localhost"}, {"127.0.0.1"}, {"*.example.com"}, {"example..com"}, {"-bad.example"}, {"bad-.example"}, {"a_b.example"}, {"api.example", "API.EXAMPLE."}, {strings.Repeat("a", 64) + ".example"}, {strings.Repeat("a.", 128) + "example"}} {
		if _, err := NewGoogleDoHResolver(hosts); err == nil {
			t.Fatal("invalid resolver selection accepted", hosts)
		}
	}
	if _, err := NewGoogleDoHResolver(strings.Fields(strings.Repeat("valid.example ", 17))); err == nil {
		t.Fatal("unbounded selection accepted")
	}
	resolver, err := NewGoogleDoHResolver([]string{"MODEL.EXAMPLE."})
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.(*googleDoHResolver)
	if r.endpoint != "https://dns.google/resolve" || r.client.Jar != nil || r.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("DNS transport inherits identity, cookies or host proxy")
	}
	r.fallback = testIPResolver{"internal-service": {IPAddr("127.0.0.1")}}
	addresses, err := r.LookupIPAddr(context.Background(), "internal-service")
	if err != nil || len(addresses) != 1 || !addresses[0].IP.IsLoopback() {
		t.Fatal("ordinary internal discovery changed", addresses, err)
	}
}

func TestLiveGoogleDoHModelDNS(t *testing.T) {
	raw := os.Getenv("PLATFORM_LIVE_MODEL_DOH_HOSTS_JSON")
	if raw == "" {
		t.Skip("explicit public model DNS probe hostnames required; no model requests")
	}
	var hosts []string
	if json.Unmarshal([]byte(raw), &hosts) != nil {
		t.Fatal("invalid DNS probe configuration")
	}
	resolver, err := NewGoogleDoHResolver(hosts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, host := range hosts {
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			t.Fatalf("public model DNS query failed without a model request: %v", err)
		}
	}
	t.Logf("resolved_public_model_hosts=%d model_requests_sent=0", len(hosts))
}

func TestGoogleDoHOnlySendsQuestionAndFollowsBoundedCNAME(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 || len(r.URL.Query()) != 3 || r.URL.Query().Get("name") != "model.example" || r.URL.Query().Get("type") != "A" || r.URL.Query().Get("edns_client_subnet") != "0.0.0.0/0" {
			t.Error("DNS request disclosed more than its public question")
		}
		if call == 1 {
			ioDNS(w, `{"Status":0,"Question":[{"name":"model.example.","type":1}],"Answer":[{"name":"model.example.","type":5,"data":"edge.example."},{"name":"unrelated.example.","type":1,"data":"127.0.0.1"},{"name":"edge.example.","type":1,"data":"8.8.8.8"}]}`)
		} else {
			ioDNS(w, `{"Status":0,"Question":[{"name":"model.example.","type":1}],"Answer":[{"name":"model.example.","type":1,"data":"198.18.0.79"}]}`)
		}
	}))
	defer server.Close()
	resolver, _ := NewGoogleDoHResolver([]string{"model.example"})
	r := resolver.(*googleDoHResolver)
	r.endpoint = server.URL
	r.client.Transport = server.Client().Transport
	addresses, err := r.LookupIPAddr(context.Background(), "MODEL.EXAMPLE.")
	if err != nil || len(addresses) != 1 || !addresses[0].IP.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("addresses=%v dns_requests=%d error=%v", addresses, calls.Load(), err)
	}
	if _, err := r.LookupIPAddr(context.Background(), "model.example"); !errors.Is(err, ErrUnsafeEndpoint) || calls.Load() != 2 {
		t.Fatal("changed DNS answer reused or fake IP admitted", calls.Load(), err)
	}
}

func ioDNS(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/dns-json")
	w.Write([]byte(body))
}

func TestGoogleDoHMalformedAndUnsafeAnswersNeverFallBack(t *testing.T) {
	valid := `{"Status":0,"Question":[{"name":"model.example.","type":1}],"Answer":[{"name":"model.example.","type":1,"data":"8.8.8.8"}]}`
	for name, body := range map[string]string{
		"missing_status":    strings.Replace(valid, `"Status":0,`, "", 1),
		"failure":           strings.Replace(valid, `"Status":0`, `"Status":2`, 1),
		"truncated":         strings.Replace(valid, `"Status":0`, `"Status":0,"TC":true`, 1),
		"checking_disabled": strings.Replace(valid, `"Status":0`, `"Status":0,"CD":true`, 1),
		"wrong_question":    strings.Replace(valid, `"name":"model.example."`, `"name":"foreign.example."`, 1),
		"wrong_type":        strings.Replace(valid, `"type":1`, `"type":28`, 1),
		"no_answer":         `{"Status":0,"Question":[{"name":"model.example","type":1}]}`,
		"unrelated_answer":  strings.Replace(valid, `"Answer":[{"name":"model.example."`, `"Answer":[{"name":"foreign.example."`, 1),
		"private":           strings.Replace(valid, "8.8.8.8", "169.254.169.254", 1),
		"invalid_ip":        strings.Replace(valid, "8.8.8.8", "not-an-ip", 1),
		"ipv6_in_a":         strings.Replace(valid, "8.8.8.8", "2001:4860:4860::8888", 1),
		"cycle":             `{"Status":0,"Question":[{"name":"model.example","type":1}],"Answer":[{"name":"model.example","type":5,"data":"model.example"}]}`,
		"invalid_alias":     `{"Status":0,"Question":[{"name":"model.example","type":1}],"Answer":[{"name":"model.example","type":5,"data":"bad..example"}]}`,
		"two_documents":     valid + valid, "malformed": "{", "oversize": strings.Repeat(" ", 33000),
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); ioDNS(w, body) }))
			defer server.Close()
			resolver, _ := NewGoogleDoHResolver([]string{"model.example"})
			r := resolver.(*googleDoHResolver)
			r.endpoint = server.URL
			r.client.Transport = server.Client().Transport
			r.fallback = testIPResolver{"model.example": {IPAddr("8.8.4.4")}}
			if addresses, err := r.LookupIPAddr(context.Background(), "model.example"); err == nil || len(addresses) != 0 {
				t.Fatal("bad selected response fell back to ordinary DNS", addresses, err)
			}
			if calls.Load() != 1 {
				t.Fatal("DNS fixture did not receive the original question", calls.Load())
			}
		})
	}
	for _, status := range []int{302, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/other")
				w.WriteHeader(status)
			}))
			defer server.Close()
			resolver, _ := NewGoogleDoHResolver([]string{"model.example"})
			r := resolver.(*googleDoHResolver)
			r.endpoint = server.URL
			r.client.Transport = server.Client().Transport
			if _, err := r.LookupIPAddr(context.Background(), "model.example"); err == nil {
				t.Fatal("HTTP failure accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("HTTP failure fixture was not called exactly once", calls.Load())
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(map[string]any{}) }))
	defer server.Close()
	resolver, _ := NewGoogleDoHResolver([]string{"model.example"})
	r := resolver.(*googleDoHResolver)
	r.endpoint = server.URL
	r.client.Transport = server.Client().Transport
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.LookupIPAddr(ctx, "model.example"); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation was lost", err)
	}
}

func TestGoogleDNSBootstrapRejectsOtherDestinationsAndPreservesCancellation(t *testing.T) {
	for _, value := range [][2]string{{"udp", "dns.google:443"}, {"tcp", "other.example:443"}, {"tcp", "dns.google:80"}, {"tcp", "dns.google"}} {
		if conn, err := googleDNSBootstrapDial(context.Background(), value[0], value[1]); conn != nil || !errors.Is(err, ErrEndpointUnresolved) {
			t.Fatal("bootstrap accepted an unrelated destination", value, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := googleDNSBootstrapDial(ctx, "tcp", "dns.google:443"); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("bootstrap lost cancellation", err)
	}
}
