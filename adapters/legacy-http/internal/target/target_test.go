package target

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestValidateRejectsUnsafeRegisteredEndpoints(t *testing.T) {
	for _, raw := range []string{
		"http://10.0.0.1:8080", "https://127.0.0.1", "https://169.254.169.254",
		"https://user:secret@10.0.0.1", "https://10.0.0.1?next=elsewhere",
		"file:///etc/passwd", "https://10.0.0.1:0", "https://10.0.0.1:99999",
	} {
		if _, err := Validate(raw, false); !errors.Is(err, ErrDenied) {
			t.Fatalf("unsafe target %q was accepted: %v", raw, err)
		}
	}
	if _, err := Validate("https://10.20.30.40:8443", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate("http://127.0.0.1:8080", true); err != nil {
		t.Fatal(err)
	}
}

func TestDialerChecksResolvedAddressBeforeConnecting(t *testing.T) {
	for _, raw := range []string{"169.254.169.254", "127.0.0.1", "8.8.8.8", "::1"} {
		ip := netip.MustParseAddr(raw)
		if allowedIP(ip, false) {
			t.Fatalf("production allowed %s", raw)
		}
	}
	if !allowedIP(netip.MustParseAddr("10.1.2.3"), false) {
		t.Fatal("private upstream was refused")
	}
	if _, err := Dialer(nil, false)(context.Background(), "tcp", net.JoinHostPort("169.254.169.254", "80")); !errors.Is(err, ErrDenied) {
		t.Fatalf("metadata endpoint was dialed: %v", err)
	}
}
