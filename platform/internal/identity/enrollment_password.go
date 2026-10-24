package identity

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

const enrollmentPasswordIterations = 600000

// The dummy value uses the same work factor as real credentials. The all-zero
// digest can never match a valid password hash except with negligible odds.
const dummyEnrollmentPasswordHash = "$pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func hashEnrollmentPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := pbkdf2SHA256([]byte(password), salt, enrollmentPasswordIterations, 32)
	if len(derived) != 32 {
		return "", errors.New("password key derivation unavailable")
	}
	return "$pbkdf2-sha256$" + strconv.Itoa(enrollmentPasswordIterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived), nil
}

func verifyEnrollmentPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < 100000 || iterations > 2000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	// Reject degenerate parameters before derivation: the standard library
	// accepts a zero key length and returns an empty key, which callers must
	// never treat as a usable credential digest.
	if iterations < 1 || keyLength < 1 || len(password) == 0 || len(salt) == 0 {
		return nil
	}
	// Keep the identical algorithm, salt, work factor and stored format. The
	// standard implementation resets its HMAC state instead of allocating a
	// fresh HMAC and digest for every one of the 600000 rounds.
	key, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, keyLength)
	if err != nil {
		return nil
	}
	if len(key) != keyLength {
		return nil
	}
	return key
}
