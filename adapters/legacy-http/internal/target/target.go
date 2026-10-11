// Package target validates and pins legacy HTTP egress at connect time.
// target 在连接时验证并固定存量 HTTP 出站地址，防止 DNS 重绑定绕过。
package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var ErrDenied = errors.New("legacy upstream target denied")

// Validate checks the registered endpoint before the adapter starts.
// Validate 在 Adapter 启动前检查已登记的上游端点。
func Validate(raw string, development bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrDenied
	}
	if u.Scheme != "https" && !(development && u.Scheme == "http") {
		return nil, ErrDenied
	}
	if u.Port() != "" {
		port, parseErr := strconv.Atoi(u.Port())
		if parseErr != nil || port < 1 || port > 65535 {
			return nil, ErrDenied
		}
	}
	if strings.Contains(u.Path, "..") || strings.Contains(u.Host, "%") {
		return nil, ErrDenied
	}
	if ip, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil && !allowedIP(ip, development) {
		return nil, ErrDenied
	}
	if strings.EqualFold(u.Hostname(), "localhost") && !development {
		return nil, ErrDenied
	}
	return u, nil
}

// Dialer resolves on every connection and dials only the validated IP. The
// request URL remains the original hostname so TLS still verifies its identity.
// 每次连接重新解析并仅拨号通过策略的 IP；TLS 仍校验原始请求域名。
func Dialer(resolver *net.Resolver, development bool) func(context.Context, string, string) (net.Conn, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, ErrDenied
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDenied
		}
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return nil, ErrDenied
		}
		var candidates []net.IPAddr
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			candidates = []net.IPAddr{{IP: net.IP(ip.AsSlice())}}
		} else {
			candidates, err = resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("%w: address resolution failed", ErrDenied)
			}
		}
		for _, candidate := range candidates {
			ip, parseErr := netip.ParseAddr(candidate.IP.String())
			if parseErr != nil || !allowedIP(ip, development) {
				continue
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, ErrDenied
	}
}

func allowedIP(ip netip.Addr, development bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsLoopback() {
		return development
	}
	return ip.IsPrivate()
}
