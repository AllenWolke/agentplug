package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadDescriptorRejectsOversizedDocumentAtReadBoundary(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plugin.json")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := LoadDescriptor(file); !errors.Is(err, ErrDescriptorInvalid) {
		t.Fatalf("oversized descriptor accepted: %v", err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("descriptor limit applied after allocating file contents: %d bytes", allocated)
	}
}

func TestArtifactStreamingDigestPreservesFullFileVerification(t *testing.T) {
	data := []byte(strings.Repeat("plugin-artifact-", 100000))
	sum := sha256.Sum256(data)
	d := Descriptor{SHA256: hex.EncodeToString(sum[:])}
	file := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyArtifact(file); err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyArtifact(file); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tail tampering not detected: %v", err)
	}
}

func validLimits() Limits {
	return Limits{MaxCPUSeconds: 2, MaxMemoryBytes: 64 << 20, MaxPIDs: 8, MaxOutputBytes: 256 << 10, TimeoutSeconds: 5}
}

func signedDescriptor(t *testing.T, key ed25519.PrivateKey, artifact []byte) Descriptor {
	t.Helper()
	d := Descriptor{
		ID:         "example_metric",
		Version:    "1.0.0",
		Entrypoint: "/plugins/example_metric/plugin",
		SHA256:     DigestOf(artifact),
		Args:       []string{"--mode=score"},
		Network:    NetworkNone,
		Limits:     validLimits(),
	}
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, d.CanonicalBytes()))
	return d
}

func TestDecodeDescriptorIsStrict(t *testing.T) {
	t.Run("unknown field is rejected", func(t *testing.T) {
		raw := []byte(`{"id":"a","version":"1","entrypoint":"/p/a","sha256":"sha256:0","signature":"s","args":[],"network":"none","limits":{"max_cpu_seconds":1,"max_memory_bytes":1,"max_pids":1,"max_output_bytes":1,"timeout_seconds":1},"surprise":true}`)
		if _, err := DecodeDescriptor(raw); !errors.Is(err, ErrDescriptorInvalid) {
			t.Fatalf("unknown field must be rejected, got %v", err)
		}
	})
	t.Run("trailing data is rejected", func(t *testing.T) {
		raw := []byte(`{"id":"a","version":"1","entrypoint":"/p/a","sha256":"sha256:0","signature":"s","args":[],"network":"none","limits":{"max_cpu_seconds":1,"max_memory_bytes":1,"max_pids":1,"max_output_bytes":1,"timeout_seconds":1}}{}`)
		if _, err := DecodeDescriptor(raw); !errors.Is(err, ErrDescriptorInvalid) {
			t.Fatalf("trailing data must be rejected, got %v", err)
		}
	})
	t.Run("oversized descriptor is rejected", func(t *testing.T) {
		if _, err := DecodeDescriptor(make([]byte, MaxDescriptorBytes+1)); !errors.Is(err, ErrDescriptorInvalid) {
			t.Fatalf("oversized descriptor must be rejected, got %v", err)
		}
	})
	t.Run("well formed descriptor decodes", func(t *testing.T) {
		key := mustKey(t)
		d := signedDescriptor(t, key, []byte("artifact"))
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, err := DecodeDescriptor(raw)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != d.ID || got.SHA256 != d.SHA256 {
			t.Fatalf("round trip lost identity: %+v", got)
		}
	})
}

func TestDescriptorValidateRejectsUnsafeRegistration(t *testing.T) {
	base := func() Descriptor {
		return Descriptor{
			ID: "a", Version: "1", Entrypoint: "/plugins/a/plugin",
			SHA256: "sha256:00", Signature: "s", Network: NetworkNone, Limits: validLimits(),
		}
	}
	cases := map[string]func(*Descriptor){
		"relative entrypoint":     func(d *Descriptor) { d.Entrypoint = "plugins/a/plugin" },
		"traversing entrypoint":   func(d *Descriptor) { d.Entrypoint = "/plugins/../../etc/shadow" },
		"shell shaped entrypoint": func(d *Descriptor) { d.Entrypoint = "/plugins/a/plugin;rm -rf /" },
		"shell shaped arg":        func(d *Descriptor) { d.Args = []string{"$(id)"} },
		"network enabled":         func(d *Descriptor) { d.Network = "egress" },
		"missing id":              func(d *Descriptor) { d.ID = "" },
		"missing version":         func(d *Descriptor) { d.Version = "" },
		"missing digest":          func(d *Descriptor) { d.SHA256 = "" },
		"missing signature":       func(d *Descriptor) { d.Signature = "" },
		"zero cpu":                func(d *Descriptor) { d.Limits.MaxCPUSeconds = 0 },
		"negative memory":         func(d *Descriptor) { d.Limits.MaxMemoryBytes = -1 },
		"zero pids":               func(d *Descriptor) { d.Limits.MaxPIDs = 0 },
		"zero output":             func(d *Descriptor) { d.Limits.MaxOutputBytes = 0 },
		"zero timeout":            func(d *Descriptor) { d.Limits.TimeoutSeconds = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := base()
			mutate(&d)
			if err := d.Validate(); err == nil {
				t.Fatalf("unsafe descriptor %q unexpectedly accepted", name)
			}
		})
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
}

func TestDescriptorSignatureAndDigest(t *testing.T) {
	key := mustKey(t)
	artifact := []byte("real plugin bytes")
	d := signedDescriptor(t, key, artifact)
	pub := key.Public().(ed25519.PublicKey)

	t.Run("valid signature verifies", func(t *testing.T) {
		if err := d.Validate(); err != nil {
			t.Fatalf("descriptor must be valid: %v", err)
		}
		if err := d.VerifySignature(pub); err != nil {
			t.Fatalf("signature must verify: %v", err)
		}
	})
	t.Run("tampered descriptor fails", func(t *testing.T) {
		tampered := d
		tampered.Entrypoint = "/plugins/example_metric/other"
		if err := tampered.VerifySignature(pub); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("tampered descriptor must fail, got %v", err)
		}
	})
	t.Run("foreign key fails", func(t *testing.T) {
		other := mustKey(t)
		if err := d.VerifySignature(other.Public().(ed25519.PublicKey)); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("foreign key must fail, got %v", err)
		}
	})
	t.Run("artifact digest matches", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "plugin")
		if err := os.WriteFile(path, artifact, 0o700); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
		if err := d.VerifyArtifact(path); err != nil {
			t.Fatalf("matching artifact must verify: %v", err)
		}
	})
	t.Run("changed artifact fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "plugin")
		if err := os.WriteFile(path, append(artifact, 'x'), 0o700); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
		if err := d.VerifyArtifact(path); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("changed artifact must fail, got %v", err)
		}
	})
	t.Run("missing artifact fails closed", func(t *testing.T) {
		if err := d.VerifyArtifact(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("missing artifact must fail closed, got %v", err)
		}
	})
}

func TestLoadPublicKey(t *testing.T) {
	key := mustKey(t)
	pub := key.Public().(ed25519.PublicKey)

	t.Run("raw key", func(t *testing.T) {
		loaded, err := LoadPublicKey(base64.StdEncoding.EncodeToString(pub))
		if err != nil {
			t.Fatalf("raw key: %v", err)
		}
		if !loaded.Equal(pub) {
			t.Fatal("raw key round trip mismatch")
		}
	})
	t.Run("spki key", func(t *testing.T) {
		spki := append(mustHex(t, "302a300506032b6570032100"), pub...)
		loaded, err := LoadPublicKey(base64.StdEncoding.EncodeToString(spki))
		if err != nil {
			t.Fatalf("spki key: %v", err)
		}
		if !loaded.Equal(pub) {
			t.Fatal("spki key round trip mismatch")
		}
	})
	t.Run("missing key fails closed", func(t *testing.T) {
		if _, err := LoadPublicKey("  "); !errors.Is(err, ErrPublicKeyMissing) {
			t.Fatalf("missing key must fail closed, got %v", err)
		}
	})
	t.Run("malformed key fails", func(t *testing.T) {
		if _, err := LoadPublicKey("not-a-key"); !errors.Is(err, ErrPublicKeyInvalid) {
			t.Fatalf("malformed key must fail, got %v", err)
		}
	})
}

func TestResolveRegisteredRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"../escape", "a/b", "a\\b", "a;b", ""} {
		if _, _, err := ResolveRegistered(root, id); !errors.Is(err, ErrDescriptorInvalid) {
			t.Fatalf("id %q must be rejected, got %v", id, err)
		}
	}
}

func TestResolveRegisteredLoadsMatchingID(t *testing.T) {
	key := mustKey(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example_metric")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	d := signedDescriptor(t, key, []byte("artifact"))
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.json"), raw, 0o600); err != nil {
		t.Fatalf("write descriptor: %v", err)
	}
	got, artifact, err := ResolveRegistered(root, "example_metric")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != "example_metric" {
		t.Fatalf("id = %q", got.ID)
	}
	if filepath.Base(artifact) != "plugin" {
		t.Fatalf("artifact = %q", artifact)
	}
}

func TestSanitizeStderr(t *testing.T) {
	raw := "api_key=supersecretvalue\n\x1b[31mtoken: abcdefghijklmnopqrstuvwxyz0123456789\x07" + strings.Repeat("x", 100)
	got := SanitizeStderr(raw, 64)
	if strings.Contains(got, "supersecretvalue") || strings.Contains(got, "abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("secrets leaked: %q", got)
	}
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("control characters survived: %q", got)
	}
	if len(got) > 64 {
		t.Fatalf("output not truncated: %d", len(got))
	}
}

func TestStrictJSONHelpers(t *testing.T) {
	type record struct {
		Name string `json:"name"`
	}
	t.Run("strict decode rejects unknown field", func(t *testing.T) {
		var r record
		if err := DecodeStrict([]byte(`{"name":"a","extra":1}`), &r); err == nil {
			t.Fatal("unknown field unexpectedly accepted")
		}
	})
	t.Run("strict decode rejects trailing data", func(t *testing.T) {
		var r record
		if err := DecodeStrict([]byte(`{"name":"a"}{"name":"b"}`), &r); !errors.Is(err, ErrTrailingData) {
			t.Fatalf("trailing data must be rejected, got %v", err)
		}
	})
	t.Run("ndjson attributes the offending line", func(t *testing.T) {
		raw := []byte("{\"name\":\"a\"}\n{\"name\":\"b\",\"bad\":1}\n")
		err := DecodeNDJSONStrict(raw, func() any { return &record{} }, func(int, any) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Fatalf("want line 2 error, got %v", err)
		}
	})
	t.Run("ndjson rejects an empty stream", func(t *testing.T) {
		err := DecodeNDJSONStrict([]byte("\n\n"), func() any { return &record{} }, func(int, any) error { return nil })
		if err == nil {
			t.Fatal("empty stream must be rejected")
		}
	})
	t.Run("ndjson visits every record", func(t *testing.T) {
		raw := []byte("{\"name\":\"a\"}\n\n{\"name\":\"b\"}\n")
		seen := 0
		err := DecodeNDJSONStrict(raw, func() any { return &record{} }, func(line int, target any) error {
			seen++
			if target.(*record).Name == "" {
				t.Fatalf("line %d lost its record", line)
			}
			return nil
		})
		if err != nil || seen != 2 {
			t.Fatalf("seen=%d err=%v", seen, err)
		}
	})
}

func TestDigestHelpers(t *testing.T) {
	digest := DigestOf([]byte("x"))
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest prefix: %q", digest)
	}
	if got := NormalizeDigest("SHA256:" + strings.ToUpper(strings.TrimPrefix(digest, "sha256:"))); got != strings.TrimPrefix(digest, "sha256:") {
		t.Fatalf("normalize: %q", got)
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return out
}
