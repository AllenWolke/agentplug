package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const accessTokenTTL = 15 * time.Minute
const refreshTokenTTL = 7 * 24 * time.Hour
const refreshCookie = "lexagent_refresh"

func randomRefreshToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Access tokens are identity assertions. Business authorization is always
// evaluated by the platform against current policy, never against these roles.
type accessClaims struct {
	AuthenticationMode string     `json:"auth_mode"`
	Issuer             string     `json:"iss"`
	Audience           string     `json:"aud"`
	Subject            string     `json:"sub"`
	IssuedAt           int64      `json:"iat"`
	ExpiresAt          int64      `json:"exp"`
	TokenID            string     `json:"jti"`
	User               userClaims `json:"user"`
}

type accessTokenSigner struct {
	key      []byte
	authMode string
}

func newAccessTokenSigner(secret string) (*accessTokenSigner, error) {
	var key []byte
	if secret == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	} else {
		var err error
		key, err = base64.RawURLEncoding.DecodeString(secret)
		if err != nil || len(key) < 32 {
			return nil, errors.New("ACCESS_TOKEN_SIGNING_KEY must be base64url of at least 32 random bytes")
		}
	}
	return &accessTokenSigner{key: key}, nil
}

func (s *accessTokenSigner) sign(user userClaims, now time.Time) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	claims := accessClaims{Issuer: "agentplug-gateway", Audience: "agentplug-browser", Subject: user.Username,
		AuthenticationMode: s.authMode,
		IssuedAt:           now.Unix(), ExpiresAt: now.Add(accessTokenTTL).Unix(), TokenID: base64.RawURLEncoding.EncodeToString(random), User: user}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"at+jwt"}`))
	body := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *accessTokenSigner) verify(token string, now time.Time) (userClaims, bool) {
	if s == nil || len(token) > 16384 {
		return userClaims{}, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return userClaims{}, false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"HS256","typ":"at+jwt"}` {
		return userClaims{}, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return userClaims{}, false
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return userClaims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return userClaims{}, false
	}
	var claims accessClaims
	if json.Unmarshal(raw, &claims) != nil || claims.Issuer != "agentplug-gateway" || claims.Audience != "agentplug-browser" ||
		claims.AuthenticationMode != s.authMode ||
		claims.Subject == "" || claims.Subject != claims.User.Username || claims.User.TenantID == "" || claims.TokenID == "" ||
		claims.IssuedAt > now.Unix() || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > int64(accessTokenTTL/time.Second) {
		return userClaims{}, false
	}
	return claims.User, true
}
