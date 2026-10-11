package main

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAccessTokenBoundaries(t *testing.T) {
	signer, err := newAccessTokenSigner(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	user := demoClaims["fixture.user"]
	token, err := signer.sign(user, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := signer.verify(token, now); !ok || got.Username != user.Username {
		t.Fatal("valid token rejected")
	}
	if _, ok := signer.verify(token, now.Add(accessTokenTTL)); ok {
		t.Fatal("expired token accepted")
	}
	if _, ok := signer.verify(token, now.Add(-time.Second)); ok {
		t.Fatal("future token accepted")
	}
	parts := strings.Split(token, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
	if _, ok := signer.verify(strings.Join(parts, "."), now); ok {
		t.Fatal("algorithm substitution accepted")
	}
	parts = strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system.admin"}`))
	if _, ok := signer.verify(strings.Join(parts, "."), now); ok {
		t.Fatal("forged identity accepted")
	}
	other, _ := newAccessTokenSigner("")
	if _, ok := other.verify(token, now); ok {
		t.Fatal("wrong signing key accepted")
	}
	if _, err := newAccessTokenSigner("short"); err == nil {
		t.Fatal("weak key accepted")
	}
	signer.authMode = "oidc"
	if _, ok := signer.verify(token, now); ok {
		t.Fatal("token from another authentication mode accepted")
	}
}
