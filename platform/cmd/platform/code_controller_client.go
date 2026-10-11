package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// Code controllers are operator-selected private origins, not external model
// endpoints. Pin one literal IP and port; never use DNS, proxies, redirects or
// caller-controlled origins. Production requires verified TLS, including its
// IP SAN. Development may explicitly use HTTP for this fixed private origin.
func newCodeControllerClient(endpoint string, development bool, caPEM []byte) (*http.Client, error) {
	denied := errors.New("unsafe private code controller origin")
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && (u.Scheme != "http" || !development)) {
		return nil, denied
	}
	address, err := netip.ParseAddr(u.Hostname())
	if err != nil || address.Zone() != "" || address != address.Unmap() || (!address.IsPrivate() && !(development && address.IsLoopback())) {
		return nil, denied
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return nil, denied
	}
	var roots *x509.CertPool
	if len(caPEM) != 0 {
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("code controller CA invalid")
		}
	}
	pinned := net.JoinHostPort(address.String(), port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != pinned {
				return nil, denied
			}
			return dialer.DialContext(ctx, "tcp", pinned)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 65 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 65 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return denied }}, nil
}
