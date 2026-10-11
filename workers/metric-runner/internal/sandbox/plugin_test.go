package sandbox

import (
	"context"
	"crypto/ed25519"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/lexagent/metric-runner/internal/limits"
	"github.com/lexagent/metric-runner/internal/protocol"
)

func hardenedAdmission() Admission {
	return Admission{SignatureVerified: true, Network: "none", MaxOutputBytes: 1 << 20, MaxSeconds: 30, MaxPIDs: 16}
}

func descriptorWith(limits protocol.Limits) protocol.Descriptor {
	return protocol.Descriptor{ID: "example_metric", Version: "1.0.0", Network: protocol.NetworkNone, Limits: limits}
}

func TestEnvelopeClampsTheAdmission(t *testing.T) {
	runner := PluginRunner{NetworkMode: limits.NetworkNone, RequireNonRoot: true}
	registered := descriptorWith(protocol.Limits{MaxCPUSeconds: 5, MaxMemoryBytes: 64 << 20, MaxPIDs: 64, MaxOutputBytes: 2 << 20, TimeoutSeconds: 60})

	t.Run("descriptor bounds apply when the admission is looser", func(t *testing.T) {
		envelope, err := runner.Envelope(registered, hardenedAdmission())
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if envelope.TimeoutSeconds != 30 {
			t.Fatalf("timeout = %d, want the tighter admission value 30", envelope.TimeoutSeconds)
		}
		if envelope.MaxOutputBytes != 1<<20 || envelope.MaxProcesses != 16 {
			t.Fatalf("admission must tighten output/pids: %+v", envelope)
		}
		if envelope.Network != limits.NetworkNone || !envelope.RequireNonRoot {
			t.Fatalf("mechanism must be preserved: %+v", envelope)
		}
	})

	t.Run("a looser admission can never widen the descriptor", func(t *testing.T) {
		loose := Admission{SignatureVerified: true, Network: "none", MaxOutputBytes: 8 << 20, MaxSeconds: 300, MaxPIDs: 128}
		envelope, err := runner.Envelope(registered, loose)
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if envelope.TimeoutSeconds != 60 || envelope.MaxOutputBytes != 2<<20 || envelope.MaxProcesses != 64 {
			t.Fatalf("descriptor bounds must survive a loose admission: %+v", envelope)
		}
	})

	t.Run("operative mechanism is container when configured", func(t *testing.T) {
		containerRunner := PluginRunner{NetworkMode: limits.NetworkContainer}
		envelope, err := containerRunner.Envelope(registered, hardenedAdmission())
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		if envelope.Network != limits.NetworkContainer {
			t.Fatalf("network = %q, want container", envelope.Network)
		}
	})
}

func TestMatchesPluginPinAcceptsCanonicalDigestFormsAndRejectsDrift(t *testing.T) {
	descriptor := protocol.Descriptor{Version: "1.0.0", SHA256: "sha256:" + strings.Repeat("a", 64)}
	tests := []struct {
		name    string
		version string
		digest  string
		want    bool
	}{
		{name: "platform stores bare hex", version: "1.0.0", digest: strings.Repeat("a", 64), want: true},
		{name: "registry uses sha256 prefix", version: "1.0.0", digest: "sha256:" + strings.Repeat("a", 64), want: true},
		{name: "wrong version", version: "2.0.0", digest: strings.Repeat("a", 64), want: false},
		{name: "wrong digest", version: "1.0.0", digest: strings.Repeat("b", 64), want: false},
		{name: "missing pin", version: "", digest: "", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchesPluginPin(test.version, test.digest, descriptor); got != test.want {
				t.Fatalf("matchesPluginPin(%q, %q) = %t, want %t", test.version, test.digest, got, test.want)
			}
		})
	}
}

func TestExecuteFailsClosedBeforeAnyThirdPartyCode(t *testing.T) {
	request := protocol.PluginRequest{Metric: "example_metric"}

	t.Run("unhardened admission is refused", func(t *testing.T) {
		runner := PluginRunner{RegistryDir: "/plugins", PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
		if _, err := runner.Execute(context.Background(), Admission{}, "example_metric", request); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("unhardened admission must be refused, got %v", err)
		}
	})

	t.Run("missing registry is refused", func(t *testing.T) {
		runner := PluginRunner{PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
		if _, err := runner.Execute(context.Background(), hardenedAdmission(), "example_metric", request); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("missing registry must be refused, got %v", err)
		}
	})

	t.Run("missing public key is refused", func(t *testing.T) {
		runner := PluginRunner{RegistryDir: t.TempDir()}
		if _, err := runner.Execute(context.Background(), hardenedAdmission(), "example_metric", request); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("missing key must be refused, got %v", err)
		}
	})

	t.Run("unregistered plugin id is refused", func(t *testing.T) {
		runner := PluginRunner{RegistryDir: t.TempDir(), PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
		if _, err := runner.Execute(context.Background(), hardenedAdmission(), "absent", request); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("unregistered plugin must be refused, got %v", err)
		}
	})

	t.Run("traversing plugin id is refused", func(t *testing.T) {
		runner := PluginRunner{RegistryDir: t.TempDir(), PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
		if _, err := runner.Execute(context.Background(), hardenedAdmission(), "../../etc/passwd", request); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("traversing id must be refused, got %v", err)
		}
	})
}

func TestSandboxAvailabilityIsPlatformHonest(t *testing.T) {
	err := limits.Available()
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("linux must enforce the sandbox: %v", err)
		}
		return
	}
	if !errors.Is(err, limits.ErrUnavailable) {
		t.Fatalf("off Linux the sandbox must fail closed, got %v", err)
	}
}
