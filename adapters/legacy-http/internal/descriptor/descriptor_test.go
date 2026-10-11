package descriptor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	p := write(t, `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","revision":1}`)
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCarriesEndpointCapabilitiesAndLimits(t *testing.T) {
	p := write(t, `{"adapter_id":"a","kind":"legacy-http","endpoint":"https://legacy.example.com","path":"/invoke","capabilities":["invoke"],"limits":{"timeout_seconds":15,"max_response_bytes":1048576},"revision":3}`)
	d, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Endpoint != "https://legacy.example.com" || d.Limits.TimeoutSeconds != 15 || d.Limits.MaxResponseBytes != 1048576 || d.Revision != 3 {
		t.Fatalf("descriptor fields were not preserved: %+v", d)
	}
}

func TestLoadCarriesSignedPlanReference(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	p := write(t, `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","revision":4,"mapping_hash":"h1","plan_path":"/etc/lexagent/plan.json","plan_public_key":"`+base64.StdEncoding.EncodeToString(public)+`"}`)
	d, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.PlanPath != "/etc/lexagent/plan.json" || d.PlanPublicKey == "" {
		t.Fatalf("plan reference was not preserved: %+v", d)
	}
}

func TestLoadRejectsBadPlanReference(t *testing.T) {
	cases := map[string]string{
		"key is not base64":      `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","revision":1,"plan_public_key":"not base64!!"}`,
		"key has the wrong size": `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","revision":1,"plan_public_key":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`,
		"path traverses":         `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","revision":1,"plan_path":"/etc/../secret.json"}`,
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("%s: descriptor was accepted", name)
		}
	}
}

func TestLoadRejectsUnsafeOrUnsupportedDeclarations(t *testing.T) {
	cases := map[string]string{
		"endpoint embeds credentials": `{"adapter_id":"a","kind":"legacy-http","endpoint":"https://user:pass@legacy.example.com","path":"/invoke","revision":1}`,
		"endpoint traverses":          `{"adapter_id":"a","kind":"legacy-http","endpoint":"https://legacy.example.com/../admin","path":"/invoke","revision":1}`,
		"endpoint is not a URL":       `{"adapter_id":"a","kind":"legacy-http","endpoint":"legacy.example.com","path":"/invoke","revision":1}`,
		"endpoint scheme is not http": `{"adapter_id":"a","kind":"legacy-http","endpoint":"file:///etc/passwd","path":"/invoke","revision":1}`,
		"unsupported capability":      `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","teleport"],"revision":1}`,
		"unimplemented capability":    `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","checkpoint"],"revision":1}`,
		"events path is relative":     `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","events"],"events_path":"events","revision":1}`,
		"events path traverses":       `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","events"],"events_path":"/a/../events","revision":1}`,
		"events without a path":       `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","events"],"revision":1}`,
		"negative limit":              `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","limits":{"timeout_seconds":-1},"revision":1}`,
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("%s: descriptor was accepted", name)
		}
	}
}

func TestLoadCarriesEventsCapability(t *testing.T) {
	p := write(t, `{"adapter_id":"a","kind":"legacy-http","path":"/invoke","capabilities":["invoke","events"],"events_path":"/events","revision":2}`)
	d, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.EventsPath != "/events" || len(d.Capabilities) != 2 {
		t.Fatalf("events declaration was not preserved: %+v", d)
	}
}
