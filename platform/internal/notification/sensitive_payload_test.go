package notification

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

type captureSensitiveAdapter struct{ event Event }

func (a *captureSensitiveAdapter) Send(_ context.Context, event Event) error {
	a.event = event
	return nil
}

func TestSensitiveEnrollmentPayloadIsEncryptedUntilChannelDelivery(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	plaintext := []byte(`{"recipient":"alice@example.org","code":"123456"}`)
	envelope, err := SealSensitivePayload(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(envelope, "alice") || strings.Contains(envelope, "123456") {
		t.Fatal("encrypted delivery envelope must not expose contact or code")
	}
	opened, err := OpenSensitivePayload(key, envelope)
	if err != nil || string(opened) != string(plaintext) {
		t.Fatalf("round-trip failed: plaintext=%q err=%v", opened, err)
	}
	wrongKey := []byte(strings.Repeat("x", 32))
	if _, err := OpenSensitivePayload(wrongKey, envelope); err == nil {
		t.Fatal("wrong encryption key must not decrypt delivery material")
	}
	encoded := strings.TrimPrefix(envelope, "v1.")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01 // Flip an actual ciphertext/tag bit; changing a trailing Base64 character may only change unused padding bits.
	tampered := "v1." + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := OpenSensitivePayload(key, tampered); err == nil {
		t.Fatal("tampered envelope must fail authentication")
	}

	inner := &captureSensitiveAdapter{}
	adapter := SensitivePayloadAdapter{Inner: inner, Key: key}
	event := Event{ID: "event-1", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Topic: "identity.enrollment.v1", EventType: EnrollmentVerificationEventType, PartitionKey: "t:alice", Payload: map[string]any{"sealed_delivery": envelope}}
	if err := adapter.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if inner.event.Payload["recipient"] != "alice@example.org" || inner.event.Payload["code"] != "123456" {
		t.Fatalf("channel adapter did not receive decrypted payload: %+v", inner.event.Payload)
	}
}
