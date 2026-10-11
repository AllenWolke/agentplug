package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oidcStepUpProvider struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Client                                      *http.Client
}
type oidcStepUpDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func oidcHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func (p *oidcStepUpProvider) discovery(ctx context.Context) (oidcStepUpDiscovery, error) {
	var result oidcStepUpDiscovery
	if p == nil || p.Client == nil || !oidcHTTPSURL(p.Issuer) {
		return result, errors.New("OIDC step-up is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(p.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return result, errors.New("OIDC discovery URL is invalid")
	}
	if err := p.readJSON(request, &result, 128<<10); err != nil {
		return result, err
	}
	if result.Issuer != p.Issuer || !oidcHTTPSURL(result.AuthorizationEndpoint) || !oidcHTTPSURL(result.TokenEndpoint) || !oidcHTTPSURL(result.JWKSURI) {
		return result, errors.New("OIDC discovery is invalid")
	}
	return result, nil
}

func (p *oidcStepUpProvider) readJSON(request *http.Request, result any, limit int64) error {
	response, err := p.Client.Do(request)
	if err != nil {
		return errors.New("OIDC provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("OIDC provider rejected request")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, limit))
	if decoder.Decode(result) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("OIDC provider response is invalid")
	}
	return nil
}

func (p *oidcStepUpProvider) exchange(ctx context.Context, discovery oidcStepUpDiscovery, code, verifier string) (string, error) {
	if code == "" || len(code) > 4096 || len(verifier) != 43 {
		return "", errors.New("OIDC authorization response is invalid")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.RedirectURL}, "code_verifier": {verifier}}
	r, err := http.NewRequestWithContext(ctx, "POST", discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("OIDC token URL is invalid")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := p.readJSON(r, &token, 64<<10); err != nil {
		return "", err
	}
	if token.IDToken == "" || len(token.IDToken) > 32<<10 {
		return "", errors.New("OIDC ID Token missing")
	}
	return token.IDToken, nil
}

type oidcFreshClaims struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        json.RawMessage `json:"aud"`
	AuthorizedParty string          `json:"azp"`
	Nonce           string          `json:"nonce"`
	ExpiresAt       int64           `json:"exp"`
	IssuedAt        int64           `json:"iat"`
	NotBefore       int64           `json:"nbf"`
	AuthenticatedAt int64           `json:"auth_time"`
}

func (p *oidcStepUpProvider) verifyFresh(ctx context.Context, discovery oidcStepUpDiscovery, raw, subject, nonce string, started, now time.Time) (oidcFreshClaims, error) {
	var claims oidcFreshClaims
	invalid := func() (oidcFreshClaims, error) {
		return oidcFreshClaims{}, errors.New("fresh OIDC authentication rejected")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 32<<10 {
		return invalid()
	}
	var header struct {
		Algorithm string   `json:"alg"`
		KeyID     string   `json:"kid"`
		Critical  []string `json:"crit"`
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerRaw, &header) != nil || header.Algorithm != "RS256" || len(header.Critical) != 0 {
		return invalid()
	}
	var jwks struct {
		Keys []struct {
			Type       string   `json:"kty"`
			ID         string   `json:"kid"`
			Algorithm  string   `json:"alg"`
			Use        string   `json:"use"`
			Operations []string `json:"key_ops"`
			N          string   `json:"n"`
			E          string   `json:"e"`
		} `json:"keys"`
	}
	r, err := http.NewRequestWithContext(ctx, "GET", discovery.JWKSURI, nil)
	if err != nil {
		return invalid()
	}
	if err := p.readJSON(r, &jwks, 128<<10); err != nil {
		return claims, err
	}
	if len(jwks.Keys) == 0 || len(jwks.Keys) > 32 {
		return invalid()
	}
	var key *rsa.PublicKey
	for _, jwk := range jwks.Keys {
		if jwk.Type != "RSA" || jwk.Algorithm != "" && jwk.Algorithm != "RS256" || jwk.Use != "" && jwk.Use != "sig" || header.KeyID != "" && jwk.ID != header.KeyID {
			continue
		}
		if len(jwk.Operations) > 0 {
			verify := false
			for _, op := range jwk.Operations {
				if op == "verify" {
					verify = true
				}
			}
			if !verify {
				continue
			}
		}
		n, nErr := base64.RawURLEncoding.DecodeString(jwk.N)
		e, eErr := base64.RawURLEncoding.DecodeString(jwk.E)
		if nErr != nil || eErr != nil || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return invalid()
		}
		exponent := new(big.Int).SetBytes(e).Uint64()
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 || key != nil {
			return invalid()
		}
		key = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if key == nil {
		return invalid()
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalid()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return invalid()
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return invalid()
	}
	var audience []string
	var one string
	if json.Unmarshal(claims.Audience, &one) == nil {
		audience = []string{one}
	} else if json.Unmarshal(claims.Audience, &audience) != nil {
		return invalid()
	}
	matched := false
	for _, aud := range audience {
		if aud == p.ClientID {
			matched = true
		}
	}
	if !matched || len(audience) > 1 && claims.AuthorizedParty != p.ClientID || claims.AuthorizedParty != "" && claims.AuthorizedParty != p.ClientID || claims.Issuer != p.Issuer || claims.Subject != subject || claims.Nonce != nonce || nonce == "" || subject == "" || len(subject) > 512 || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt <= claims.IssuedAt || claims.IssuedAt < started.Unix() || claims.IssuedAt > now.Add(5*time.Second).Unix() || claims.NotBefore > now.Add(5*time.Second).Unix() || claims.AuthenticatedAt < started.Unix() || claims.AuthenticatedAt > now.Add(5*time.Second).Unix() || claims.AuthenticatedAt <= 0 || !now.Before(time.Unix(claims.AuthenticatedAt, 0).Add(5*time.Minute)) {
		return invalid()
	}
	return claims, nil
}
