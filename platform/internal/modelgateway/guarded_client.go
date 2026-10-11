package modelgateway

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// NewGuardedEndpointClient reuses model gateway DNS/IP and redirect boundaries
// for other control-plane configured providers. It never inherits host proxies.
func NewGuardedEndpointClient(endpoint string, developmentLoopback bool) (*http.Client, error) {
	config := HTTPConfig{AllowLoopbackDevelopment: developmentLoopback, AllowedHTTPSPorts: []string{"443", "8443"}}
	parsed, err := url.Parse(endpoint)
	if err != nil || validateEndpointURL(parsed, config) != nil {
		return nil, ErrUnsafeEndpoint
	}
	dialer := &safeDialer{resolver: net.DefaultResolver, timeout: 5 * time.Second, allowLoopback: developmentLoopback}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirects are not allowed") }}, nil
}
