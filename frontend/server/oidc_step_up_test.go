package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func signOIDCFixture(t *testing.T, key *rsa.PrivateKey, claims any, algorithm string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "kid": "fixture-key"})
	payload, _ := json.Marshal(claims)
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCStepUpVerifiesSignedFreshClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "fixture-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	p := &oidcStepUpProvider{Issuer: server.URL, ClientID: "fixture-client", Client: server.Client()}
	discovery := oidcStepUpDiscovery{Issuer: server.URL, JWKSURI: server.URL + "/keys"}
	now := time.Now().UTC().Truncate(time.Second)
	started := now.Add(-time.Second)
	for _, name := range []string{"valid", "wrong-issuer", "wrong-subject", "wrong-audience", "multi-audience-without-azp", "multi-audience-valid", "wrong-azp", "wrong-nonce", "old-auth-time", "missing-auth-time", "future-auth-time", "expired", "bad-signature", "wrong-algorithm"} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"iss": server.URL, "sub": "immutable-subject", "aud": "fixture-client", "nonce": "challenge-nonce", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix()}
			algorithm := "RS256"
			switch name {
			case "wrong-issuer":
				claims["iss"] = "https://other.example"
			case "wrong-subject":
				claims["sub"] = "other-subject"
			case "wrong-audience":
				claims["aud"] = "other-client"
			case "multi-audience-without-azp":
				claims["aud"] = []string{"fixture-client", "other"}
			case "multi-audience-valid":
				claims["aud"] = []string{"fixture-client", "other"}
				claims["azp"] = "fixture-client"
			case "wrong-azp":
				claims["azp"] = "other-client"
			case "wrong-nonce":
				claims["nonce"] = "other-nonce"
			case "old-auth-time":
				claims["auth_time"] = started.Add(-time.Second).Unix()
			case "missing-auth-time":
				delete(claims, "auth_time")
			case "future-auth-time":
				claims["auth_time"] = now.Add(time.Minute).Unix()
			case "expired":
				claims["exp"] = now.Unix()
			case "wrong-algorithm":
				algorithm = "HS256"
			}
			token := signOIDCFixture(t, key, claims, algorithm)
			if name == "bad-signature" {
				parts := strings.Split(token, ".")
				signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				token = strings.Join(parts, ".")
			}
			_, err := p.verifyFresh(t.Context(), discovery, token, "immutable-subject", "challenge-nonce", started, now)
			if (err == nil) != (name == "valid" || name == "multi-audience-valid") {
				t.Fatal("fresh token verification", name, err)
			}
		})
	}
}

func TestOIDCStepUpGatewayFlowAndReplayBoundary(t *testing.T) {
	for _, action := range []string{"administrator.appoint", "delegation.manage", "tool.approval.approve", "tool.approval.revoke"} {
		t.Run(action, func(t *testing.T) { testOIDCStepUpGatewayFlow(t, action) })
	}
}

func testOIDCStepUpGatewayFlow(t *testing.T, action string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var provider *httptest.Server
	providerSecret, err := randomRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	var requestedNonce, pkceHash string
	var fixtureMu sync.Mutex
	exchanges, completions := 0, 0
	provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, 200, oidcStepUpDiscovery{Issuer: provider.URL, AuthorizationEndpoint: provider.URL + "/authorize", TokenEndpoint: provider.URL + "/token", JWKSURI: provider.URL + "/keys"})
		case "/keys":
			writeJSON(w, 200, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "fixture-key", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			fixtureMu.Lock()
			defer fixtureMu.Unlock()
			exchanges++
			if exchanges > 1 {
				w.WriteHeader(400)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			client, secret, ok := r.BasicAuth()
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || client != "fixture-client" || secret != providerSecret || base64.RawURLEncoding.EncodeToString(hash[:]) != pkceHash || r.Form.Get("code") != "one-use-code" {
				t.Error("authorization code exchange lost client/PKCE boundary")
			}
			now := time.Now()
			claims := map[string]any{"iss": provider.URL, "sub": "immutable-subject", "aud": "fixture-client", "nonce": requestedNonce, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix()}
			writeJSON(w, 200, map[string]string{"id_token": signOIDCFixture(t, key, claims, "RS256")})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	challengeToken, _ := randomRefreshToken()
	nonce, _ := randomRefreshToken()
	proof, _ := randomRefreshToken()
	start := time.Now().UTC().Truncate(time.Second)
	expires := start.Add(5 * time.Minute)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "gateway-fixture" || r.Header.Get("X-Browser-Module") != "" {
			t.Error("OIDC bridge lost private gateway boundary")
		}
		switch r.URL.Path {
		case "/modules/identity/internal/oidc/step-up:challenge":
			writeJSON(w, 200, oidcStepUpChallengeResult{Token: challengeToken, Nonce: nonce, Issuer: provider.URL, Subject: "immutable-subject", StartedAt: start, ExpiresAt: expires})
		case "/modules/identity/internal/browser-sessions/validate":
			w.WriteHeader(200)
		case "/modules/identity/internal/oidc/step-up:complete":
			fixtureMu.Lock()
			defer fixtureMu.Unlock()
			completions++
			var input map[string]any
			if json.NewDecoder(r.Body).Decode(&input) != nil || input["nonce"] != nonce || input["challenge_token"] != challengeToken || input["subject"] != "immutable-subject" || input["action"] != action || input["request_digest"] != strings.Repeat("a", 64) {
				t.Error("unverified or substituted step-up assertion forwarded")
			}
			writeJSON(w, 200, map[string]any{"step_up_token": proof, "expires_at": expires})
		default:
			http.NotFound(w, r)
		}
	}))
	defer platform.Close()
	target, _ := url.Parse(platform.URL)
	signer, err := newAccessTokenSigner("")
	if err != nil {
		t.Fatal(err)
	}
	signer.authMode = "oidc"
	g := &gateway{platformTarget: target, platformToken: "gateway-fixture", secureCookie: true, authMode: "oidc", oidcTrusted: true, oidcIssuer: provider.URL, httpClient: platform.Client(), accessSigner: signer, oidcStepUp: &oidcStepUpProvider{Issuer: provider.URL, ClientID: "fixture-client", ClientSecret: providerSecret, Client: provider.Client()}}
	server := httptest.NewTLSServer(http.HandlerFunc(g.serveHTTP))
	defer server.Close()
	g.oidcStepUp.RedirectURL = server.URL + oidcStepUpCallback
	user := userClaims{Username: "actual-admin", TenantID: "t", DepartmentID: "d", ApplicationID: "a", TokenVersion: 4, SessionID: strings.Repeat("b", 64)}
	access, err := signer.sign(user, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	gatewayURL, _ := url.Parse(server.URL)
	jar.SetCookies(gatewayURL, []*http.Cookie{{Name: sessionCookie, Value: access, Path: "/", Secure: true}})
	body, _ := json.Marshal(map[string]string{"action": action, "request_digest": strings.Repeat("a", 64)})
	r, err := http.NewRequest("POST", server.URL+"/auth/step-up/oidc/start", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", "https://attacker.example")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("cross-origin step-up accepted")
	}
	r, _ = http.NewRequest("POST", server.URL+"/auth/step-up/oidc/start", bytes.NewReader(body))
	r.Header.Set("Origin", server.URL)
	resp, err = client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	var begin map[string]string
	if json.NewDecoder(resp.Body).Decode(&begin) != nil || resp.StatusCode != 200 {
		t.Fatal("flow did not begin", resp.StatusCode)
	}
	resp.Body.Close()
	authorization, _ := url.Parse(begin["authorization_url"])
	params := authorization.Query()
	fixtureMu.Lock()
	requestedNonce, pkceHash = params.Get("nonce"), params.Get("code_challenge")
	fixtureMu.Unlock()
	if params.Get("max_age") != "0" || params.Get("prompt") != "login" || params.Get("code_challenge_method") != "S256" || requestedNonce != nonce || params.Get("state") != begin["state"] || params.Get("redirect_uri") != g.oidcStepUp.RedirectURL {
		t.Fatal("fresh authentication request missing mandatory boundaries")
	}
	callbackURL, _ := url.Parse(g.oidcStepUp.RedirectURL)
	cookies := jar.Cookies(callbackURL)
	var saved *http.Cookie
	for _, c := range cookies {
		if c.Name == oidcStepUpCookie {
			saved = c
			flow, err := g.openOIDCState(c.Value)
			if err != nil || flow.User.Username != user.Username || strings.Contains(c.Value, challengeToken) {
				t.Fatal("flow state protection failed", err)
			}
		}
	}
	if saved == nil {
		t.Fatal("protected state cookie missing")
	}
	resp, err = client.Get(g.oidcStepUp.RedirectURL + "?state=attacker&code=one-use-code")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fixtureMu.Lock()
	exchangeCount := exchanges
	fixtureMu.Unlock()
	if resp.StatusCode != 401 || exchangeCount != 0 {
		t.Fatal("state mismatch reached provider")
	}
	callback := g.oidcStepUp.RedirectURL + "?state=" + url.QueryEscape(begin["state"]) + "&code=one-use-code"
	// A valid signed login in a different workspace cannot finish the old flow.
	other := user
	other.ApplicationID = "different-workspace"
	otherAccess, err := signer.sign(other, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(gatewayURL, []*http.Cookie{{Name: sessionCookie, Value: otherAccess, Path: "/", Secure: true}})
	resp, err = client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	rejected, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fixtureMu.Lock()
	exchangeCount = exchanges
	fixtureMu.Unlock()
	if !strings.Contains(string(rejected), "OIDC_STEP_UP_FAILED") || strings.Contains(string(rejected), proof) || exchangeCount != 0 {
		t.Fatal("changed browser workspace reached provider or received a proof")
	}
	jar.SetCookies(gatewayURL, []*http.Cookie{{Name: sessionCookie, Value: access, Path: "/", Secure: true}})
	saved.Path, saved.Secure = "/auth/step-up/oidc", true
	jar.SetCookies(callbackURL, []*http.Cookie{saved})
	resp, err = client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fixtureMu.Lock()
	completionCount := completions
	fixtureMu.Unlock()
	if resp.StatusCode != 200 || !strings.Contains(string(html), proof) || strings.Contains(string(html), challengeToken) || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || completionCount != 1 {
		t.Fatal("verified proof not returned through protected same-origin result", string(html))
	}
	// Restoring a captured encrypted cookie does not restore the one-use code.
	saved.Path = "/auth/step-up/oidc"
	saved.Secure = true
	jar.SetCookies(callbackURL, []*http.Cookie{saved})
	resp, err = client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	html, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fixtureMu.Lock()
	completionCount = completions
	fixtureMu.Unlock()
	if strings.Contains(string(html), proof) || completionCount != 1 {
		t.Fatal("callback replay minted a proof")
	}
}

func TestOIDCStepUpConfigurationIsOptionalAndComplete(t *testing.T) {
	for _, name := range []string{"disabled", "valid", "partial", "http-callback", "wrong-path", "callback-query", "http-issuer"} {
		t.Run(name, func(t *testing.T) {
			issuer := "https://issuer.example/realm"
			id, secret, callback := "fixture-client", "fixture", "https://console.example"+oidcStepUpCallback
			switch name {
			case "disabled":
				id, secret, callback = "", "", ""
			case "partial":
				secret = ""
			case "http-callback":
				callback = "http://console.example" + oidcStepUpCallback
			case "wrong-path":
				callback = "https://console.example/oauth2/callback"
			case "callback-query":
				callback += "?state=untrusted"
			case "http-issuer":
				issuer = "http://issuer.example/realm"
			}
			t.Setenv("OIDC_STEP_UP_CLIENT_ID", id)
			t.Setenv("OIDC_STEP_UP_CLIENT_SECRET", secret)
			t.Setenv("OIDC_STEP_UP_REDIRECT_URL", callback)
			provider, err := loadOIDCStepUpProvider(issuer)
			if (err == nil) != (name == "disabled" || name == "valid") || (name == "disabled" && provider != nil) {
				t.Fatal("OIDC fresh-auth configuration boundary", name, err)
			}
		})
	}
}
