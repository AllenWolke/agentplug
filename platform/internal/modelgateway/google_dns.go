package modelgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// NewGoogleDoHResolver is an explicit IPv4 resolver for named model endpoints.
// Other hosts keep the ordinary resolver, including private service discovery.
// Only DNS questions go to Google's TLS-authenticated JSON API; provider keys,
// prompts and execution identities never enter this client. Answers are not
// cached, and the model dialer still checks every IP and dials the checked IP.
// Protocol: https://developers.google.com/speed/public-dns/docs/doh/json
func NewGoogleDoHResolver(hosts []string) (IPResolver, error) {
	if len(hosts) == 0 || len(hosts) > 16 {
		return nil, ErrEndpointUnresolved
	}
	selected := map[string]bool{}
	for _, host := range hosts {
		normalized := dnsHost(host)
		if normalized == "" || selected[normalized] {
			return nil, ErrEndpointUnresolved
		}
		selected[normalized] = true
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second,
		DialContext:  googleDNSBootstrapDial,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrEndpointUnresolved }}
	return &googleDoHResolver{hosts: selected, endpoint: "https://dns.google/resolve", client: client, fallback: net.DefaultResolver}, nil
}

// Bootstrap uses Google's published anycast addresses, so a fake-IP system
// resolver cannot recursively intercept the HTTPS resolver's own hostname.
// HTTP still authenticates the original dns.google TLS server name.
func googleDNSBootstrapDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "dns.google" || port != "443" || network != "tcp" {
		return nil, ErrEndpointUnresolved
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	var last error
	for _, ip := range []string{"8.8.8.8", "8.8.4.4"} {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return connection, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

type googleDoHResolver struct {
	hosts    map[string]bool
	endpoint string
	client   *http.Client
	fallback IPResolver
}

func dnsHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || !strings.Contains(host, ".") || strings.TrimSpace(host) != host {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return host
}

func (r *googleDoHResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	normalized := dnsHost(host)
	if !r.hosts[normalized] {
		return r.fallback.LookupIPAddr(ctx, host)
	}
	endpoint, err := url.Parse(r.endpoint)
	if err != nil {
		return nil, ErrEndpointUnresolved
	}
	query := endpoint.Query()
	query.Set("name", normalized)
	query.Set("type", "A")
	query.Set("edns_client_subnet", "0.0.0.0/0")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, ErrEndpointUnresolved
	}
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrEndpointUnresolved
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrEndpointUnresolved
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(raw) > 32<<10 {
		return nil, ErrEndpointUnresolved
	}
	var answer struct {
		Status           *int `json:"Status"`
		Truncated        bool `json:"TC"`
		CheckingDisabled bool `json:"CD"`
		Question         []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		} `json:"Question"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&answer) != nil || decoder.Decode(new(any)) != io.EOF || answer.Status == nil || *answer.Status != 0 || answer.Truncated || answer.CheckingDisabled || len(answer.Question) != 1 || dnsHost(answer.Question[0].Name) != normalized || answer.Question[0].Type != 1 || len(answer.Answer) > 64 {
		return nil, ErrEndpointUnresolved
	}
	seen := map[string]bool{}
	for depth := 0; depth < 8; depth++ {
		if seen[normalized] {
			return nil, ErrEndpointUnresolved
		}
		seen[normalized] = true
		var aliases []string
		var addresses []net.IPAddr
		for _, record := range answer.Answer {
			if dnsHost(record.Name) != normalized {
				continue
			}
			switch record.Type {
			case 5:
				alias := dnsHost(record.Data)
				if alias == "" {
					return nil, ErrEndpointUnresolved
				}
				aliases = append(aliases, alias)
			case 1:
				ip, err := netip.ParseAddr(record.Data)
				if err != nil || !ip.Is4() || !allowedResolvedAddress(ip, false) {
					return nil, ErrUnsafeEndpoint
				}
				addresses = append(addresses, net.IPAddr{IP: net.IP(ip.AsSlice())})
			}
		}
		if len(aliases) > 1 || len(aliases) > 0 && len(addresses) > 0 {
			return nil, ErrEndpointUnresolved
		}
		if len(aliases) == 0 {
			if len(addresses) == 0 {
				return nil, ErrEndpointUnresolved
			}
			return addresses, nil
		}
		normalized = aliases[0]
	}
	return nil, ErrEndpointUnresolved
}
