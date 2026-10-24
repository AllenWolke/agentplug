package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Retain the previous derivation only as an independent compatibility oracle.
func legacyPasswordKey(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac = hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func TestPasswordDerivationPreservesExistingStoredCredentials(t *testing.T) {
	for _, tc := range []struct {
		rounds int
		want   string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
	} {
		if got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), tc.rounds, 32)); got != tc.want {
			t.Fatalf("rounds=%d: %s", tc.rounds, got)
		}
	}
	password := "历史密码-\x00-credential"
	salt := []byte("fixture-salt-16b!")
	old := legacyPasswordKey([]byte(password), salt, enrollmentPasswordIterations)
	stored := "$pbkdf2-sha256$600000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(old)
	if !verifyEnrollmentPassword(stored, password) || verifyEnrollmentPassword(stored, password+"wrong") {
		t.Fatal("stored password compatibility changed")
	}
	if !bytes.Equal(old, pbkdf2SHA256([]byte(password), salt, enrollmentPasswordIterations, 32)) {
		t.Fatal("work factor or digest changed")
	}
	if pbkdf2SHA256([]byte(password), salt, 0, 32) != nil || pbkdf2SHA256([]byte(password), salt, 1, 0) != nil {
		t.Fatal("invalid derivation accepted")
	}
}

func BenchmarkPasswordDerivation600000(b *testing.B) {
	for _, old := range []bool{false, true} {
		name := "standard"
		if old {
			name = "legacy"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if old {
					_ = legacyPasswordKey([]byte("fixture-password"), []byte("fixture-salt-16b!"), enrollmentPasswordIterations)
				} else {
					_ = pbkdf2SHA256([]byte("fixture-password"), []byte("fixture-salt-16b!"), enrollmentPasswordIterations, 32)
				}
			}
		})
	}
}
