package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const oidcStepUpCookie = "agentplug_oidc_step_up"
const oidcStepUpCallback = "/auth/step-up/oidc/callback"

type oidcStepUpState struct {
	State, Verifier, ChallengeToken, Nonce, Issuer, Subject, Action, RequestDigest string
	User                                                                           userClaims
	StartedAt, ExpiresAt                                                           time.Time
}
type oidcStepUpChallengeResult struct {
	Token     string    `json:"challenge_token"`
	Nonce     string    `json:"nonce"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func loadOIDCStepUpProvider(issuer string) (*oidcStepUpProvider, error) {
	id, secret, redirect := strings.TrimSpace(envOr("OIDC_STEP_UP_CLIENT_ID", "")), strings.TrimSpace(envOr("OIDC_STEP_UP_CLIENT_SECRET", "")), strings.TrimSpace(envOr("OIDC_STEP_UP_REDIRECT_URL", ""))
	if id == "" && secret == "" && redirect == "" {
		return nil, nil
	}
	u, err := url.Parse(redirect)
	if id == "" || secret == "" || !oidcHTTPSURL(issuer) || !oidcHTTPSURL(redirect) || err != nil || u.Path != oidcStepUpCallback || u.RawQuery != "" {
		return nil, errors.New("OIDC step-up requires client credentials and an HTTPS callback URL")
	}
	return &oidcStepUpProvider{Issuer: issuer, ClientID: id, ClientSecret: secret, RedirectURL: redirect, Client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (g *gateway) oidcStateCipher() (cipher.AEAD, error) {
	if g.accessSigner == nil || len(g.accessSigner.key) < 32 {
		return nil, errors.New("OIDC state protection unavailable")
	}
	key := sha256.Sum256(append([]byte("agentplug.oidc-step-up-state.v1\x00"), g.accessSigner.key...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (g *gateway) sealOIDCState(state oidcStepUpState) (string, error) {
	aead, err := g.oidcStateCipher()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	result := base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, raw, []byte(g.oidcStepUp.RedirectURL)))
	if len(result) > 3800 {
		return "", errors.New("OIDC state exceeds cookie limit")
	}
	return result, nil
}
func (g *gateway) openOIDCState(raw string) (oidcStepUpState, error) {
	var result oidcStepUpState
	if len(raw) > 3800 {
		return result, errors.New("OIDC state invalid")
	}
	aead, err := g.oidcStateCipher()
	if err != nil {
		return result, err
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(data) < aead.NonceSize()+aead.Overhead() {
		return result, errors.New("OIDC state invalid")
	}
	data, err = aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(g.oidcStepUp.RedirectURL))
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, errors.New("OIDC state invalid")
	}
	return result, nil
}

func oidcUserScope(user userClaims) map[string]string {
	return map[string]string{"PrincipalType": "user", "PrincipalID": user.Username, "TenantID": user.TenantID, "DepartmentID": user.DepartmentID, "ApplicationID": user.ApplicationID}
}
func sameOIDCStepUpActor(a, b userClaims) bool {
	return a.Username == b.Username && a.TenantID == b.TenantID && a.DepartmentID == b.DepartmentID && a.ApplicationID == b.ApplicationID && a.SessionID == b.SessionID && a.TokenVersion == b.TokenVersion
}

func (g *gateway) callOIDCStepUp(r *http.Request, operation string, input map[string]any, result any) (int, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return 500, err
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/oidc/step-up:" + operation
	request, err := http.NewRequestWithContext(r.Context(), "POST", endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return 503, errors.New("step-up service unavailable")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.httpClient.Do(request)
	if err != nil {
		return 503, errors.New("step-up service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return response.StatusCode, errors.New("step-up request rejected")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8192))
	if decoder.Decode(result) != nil || decoder.Decode(new(any)) != io.EOF {
		return 502, errors.New("step-up response invalid")
	}
	return 200, nil
}

func (g *gateway) stepUpMethod(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := g.authenticate(r); !ok {
		w.Header().Set("X-Authentication-Error", "access_token_invalid")
		writeJSON(w, 401, map[string]string{"message": "请先登录"})
		return
	}
	method := "local"
	available := true
	if g.authMode == "oidc" {
		method = "oidc"
		available = g.oidcStepUp != nil
	}
	writeJSON(w, 200, map[string]any{"method": method, "available": available})
}

func (g *gateway) beginOIDCStepUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !g.sameBrowserOrigin(r) {
		writeJSON(w, 403, map[string]string{"message": "请求来源不受信任"})
		return
	}
	if g.authMode != "oidc" || g.oidcStepUp == nil {
		writeJSON(w, 503, map[string]string{"message": "OIDC 再次认证尚未配置"})
		return
	}
	callback, _ := url.Parse(g.oidcStepUp.RedirectURL)
	if !strings.EqualFold(callback.Host, r.Host) || !g.secureCookie {
		writeJSON(w, 403, map[string]string{"message": "再次认证回调与当前站点不匹配"})
		return
	}
	user, ok := g.authenticate(r)
	if !ok {
		w.Header().Set("X-Authentication-Error", "access_token_invalid")
		writeJSON(w, 401, map[string]string{"message": "请先登录"})
		return
	}
	if user.TokenVersion == 0 || user.SessionID == "" {
		writeJSON(w, 401, map[string]string{"message": "需要有效的持久登录会话"})
		return
	}
	var input struct {
		Action string `json:"action"`
		Digest string `json:"request_digest"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !validOIDCStepUpAction(input.Action) {
		writeJSON(w, 400, map[string]string{"message": "再次认证操作无效"})
		return
	}
	digest, err := hex.DecodeString(input.Digest)
	if err != nil || len(digest) != 32 {
		writeJSON(w, 400, map[string]string{"message": "再次认证摘要无效"})
		return
	}
	discovery, err := g.oidcStepUp.discovery(r.Context())
	if err != nil {
		writeJSON(w, 503, map[string]string{"message": "OIDC 认证服务暂不可用"})
		return
	}
	var challenge oidcStepUpChallengeResult
	status, err := g.callOIDCStepUp(r, "challenge", map[string]any{"scope": oidcUserScope(user), "session_id": user.SessionID, "auth_revision": user.TokenVersion, "action": input.Action, "request_digest": input.Digest}, &challenge)
	if err != nil {
		writeJSON(w, status, map[string]string{"message": "无法启动再次认证，请检查当前会话和操作资格"})
		return
	}
	now := time.Now()
	if challenge.Issuer != g.oidcIssuer || challenge.Subject == "" || len(challenge.Token) != 43 || len(challenge.Nonce) != 43 || challenge.StartedAt.After(now.Add(5*time.Second)) || !now.Before(challenge.ExpiresAt) || challenge.ExpiresAt.Sub(challenge.StartedAt) > 5*time.Minute {
		writeJSON(w, 502, map[string]string{"message": "再次认证服务响应异常"})
		return
	}
	state, err := randomRefreshToken()
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "启动再次认证失败"})
		return
	}
	verifier, err := randomRefreshToken()
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "启动再次认证失败"})
		return
	}
	user.Roles = nil
	flow := oidcStepUpState{State: state, Verifier: verifier, ChallengeToken: challenge.Token, Nonce: challenge.Nonce, Issuer: challenge.Issuer, Subject: challenge.Subject, Action: input.Action, RequestDigest: input.Digest, User: user, StartedAt: challenge.StartedAt, ExpiresAt: challenge.ExpiresAt}
	cookie, err := g.sealOIDCState(flow)
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "无法保护再次认证状态"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStepUpCookie, Value: cookie, Path: "/auth/step-up/oidc", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 300, Expires: flow.ExpiresAt})
	endpoint, _ := url.Parse(discovery.AuthorizationEndpoint)
	params := endpoint.Query()
	hash := sha256.Sum256([]byte(verifier))
	for key, value := range map[string]string{"response_type": "code", "client_id": g.oidcStepUp.ClientID, "redirect_uri": g.oidcStepUp.RedirectURL, "scope": "openid", "state": state, "nonce": flow.Nonce, "prompt": "login", "max_age": "0", "code_challenge": base64.RawURLEncoding.EncodeToString(hash[:]), "code_challenge_method": "S256"} {
		params.Set(key, value)
	}
	endpoint.RawQuery = params.Encode()
	writeJSON(w, 200, map[string]string{"authorization_url": endpoint.String(), "state": state})
}

func validOIDCStepUpAction(action string) bool {
	return action == "administrator.appoint" || action == "delegation.manage" || action == "tool.approval.approve" || action == "tool.approval.revoke"
}

func (g *gateway) completeOIDCStepUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if g.authMode != "oidc" || g.oidcStepUp == nil {
		http.NotFound(w, r)
		return
	}
	callback, _ := url.Parse(g.oidcStepUp.RedirectURL)
	if !strings.EqualFold(callback.Host, r.Host) {
		writeJSON(w, 403, map[string]string{"message": "回调站点无效"})
		return
	}
	cookie, err := r.Cookie(oidcStepUpCookie)
	if err != nil {
		writeJSON(w, 401, map[string]string{"message": "再次认证状态无效"})
		return
	}
	flow, err := g.openOIDCState(cookie.Value)
	query := r.URL.Query()
	if err != nil || len(query["state"]) != 1 || query.Get("state") != flow.State || flow.State == "" || !time.Now().Before(flow.ExpiresAt) {
		writeJSON(w, 401, map[string]string{"message": "再次认证状态无效或已过期"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStepUpCookie, Path: "/auth/step-up/oidc", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	fail := func() { g.oidcStepUpResult(w, flow.State, map[string]any{"error": "OIDC_STEP_UP_FAILED"}) }
	user, ok := g.authenticate(r)
	if !ok || !sameOIDCStepUpActor(user, flow.User) || flow.Issuer != g.oidcIssuer || len(query["code"]) != 1 || query.Get("error") != "" {
		fail()
		return
	}
	if err := g.validateBrowserSession(r, user); err != nil {
		fail()
		return
	}
	discovery, err := g.oidcStepUp.discovery(r.Context())
	if err != nil {
		fail()
		return
	}
	token, err := g.oidcStepUp.exchange(r.Context(), discovery, query.Get("code"), flow.Verifier)
	if err != nil {
		fail()
		return
	}
	claims, err := g.oidcStepUp.verifyFresh(r.Context(), discovery, token, flow.Subject, flow.Nonce, flow.StartedAt, time.Now())
	if err != nil {
		fail()
		return
	}
	var proof struct {
		Token     string    `json:"step_up_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_, err = g.callOIDCStepUp(r, "complete", map[string]any{"scope": oidcUserScope(user), "session_id": user.SessionID, "auth_revision": user.TokenVersion, "action": flow.Action, "request_digest": flow.RequestDigest, "challenge_token": flow.ChallengeToken, "issuer": claims.Issuer, "subject": claims.Subject, "nonce": claims.Nonce, "authenticated_at": time.Unix(claims.AuthenticatedAt, 0).UTC()}, &proof)
	if err != nil || len(proof.Token) != 43 || !time.Now().Before(proof.ExpiresAt) || proof.ExpiresAt.After(flow.ExpiresAt) {
		fail()
		return
	}
	g.oidcStepUpResult(w, flow.State, map[string]any{"step_up_token": proof.Token, "expires_at": proof.ExpiresAt})
}

func (g *gateway) oidcStepUpResult(w http.ResponseWriter, state string, result map[string]any) {
	result["type"], result["state"] = "agentplug.oidc.step-up", state
	data, err := json.Marshal(result)
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "再次认证响应失败"})
		return
	}
	callback, _ := url.Parse(g.oidcStepUp.RedirectURL)
	origin, _ := json.Marshal(callback.Scheme + "://" + callback.Host)
	nonce, err := randomRefreshToken()
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "再次认证响应失败"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>再次认证</title><p>认证结果已返回原窗口；如窗口已关闭，请重新办理。</p><script nonce="%s">if(window.opener){window.opener.postMessage(%s,%s);window.close();}</script></html>`, nonce, data, origin)
}
