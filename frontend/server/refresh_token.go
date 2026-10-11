package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type verifiedOIDCSubjectKey struct{}

func (g *gateway) validateBrowserSession(r *http.Request, user userClaims) error {
	body, err := json.Marshal(map[string]any{"scope": map[string]string{"PrincipalType": "user", "PrincipalID": user.Username, "TenantID": user.TenantID, "DepartmentID": user.DepartmentID, "ApplicationID": user.ApplicationID}, "session_id": user.SessionID, "auth_revision": user.TokenVersion})
	if err != nil {
		return err
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/browser-sessions/validate"
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return errRemoteRefreshRejected
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("authentication session service unavailable")
	}
	return nil
}

var errRemoteRefreshRejected = errors.New("refresh session rejected")
var errRemoteWorkspaceForbidden = errors.New("workspace forbidden")

func gatewayRefreshHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Transitional demo credentials are process-local; real local credentials use
// Identity's durable session families. No raw refresh tokens are kept in either.
func (s *sessionStore) rotate(token string) (string, userClaims, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := gatewayRefreshHash(token)
	value, ok := s.items[hash]
	if !ok || s.revoked[value.Family] || !time.Now().Before(value.ExpiresAt) {
		return "", userClaims{}, time.Time{}, errors.New("refresh rejected")
	}
	if value.Used {
		s.revoked[value.Family] = true
		return "", userClaims{}, time.Time{}, errors.New("refresh replay")
	}
	next, err := randomRefreshToken()
	if err != nil {
		return "", userClaims{}, time.Time{}, err
	}
	value.Used = true
	s.items[hash] = value
	value.Used = false
	s.items[gatewayRefreshHash(next)] = value
	return next, value.User, value.ExpiresAt, nil
}

type platformRefreshResult struct {
	SessionID            string    `json:"session_id"`
	AuthenticationMethod string    `json:"authentication_method"`
	RefreshToken         string    `json:"refresh_token"`
	ExpiresAt            time.Time `json:"expires_at"`
	Identity             struct {
		Username      string   `json:"username"`
		DisplayName   string   `json:"display_name"`
		TenantID      string   `json:"tenant_id"`
		DepartmentID  string   `json:"department_id"`
		ApplicationID string   `json:"application_id"`
		Roles         []string `json:"roles"`
		AuthRevision  uint64   `json:"auth_revision"`
	} `json:"identity"`
}

func (g *gateway) platformRefresh(r *http.Request, operation string, input map[string]any) (platformRefreshResult, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return platformRefreshResult{}, err
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/refresh-sessions"
	if operation != "create" {
		endpoint.Path += ":" + operation
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return platformRefreshResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.httpClient.Do(request)
	if err != nil {
		return platformRefreshResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusForbidden {
			return platformRefreshResult{}, errRemoteWorkspaceForbidden
		}
		if response.StatusCode == http.StatusUnauthorized {
			return platformRefreshResult{}, errRemoteRefreshRejected
		}
		return platformRefreshResult{}, errors.New("refresh session service rejected request")
	}
	var result platformRefreshResult
	if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&result) != nil {
		return result, errors.New("invalid refresh response")
	}
	if operation != "revoke" {
		decoded, err := hex.DecodeString(result.SessionID)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != result.SessionID {
			return platformRefreshResult{}, errors.New("refresh response omitted durable session identity")
		}
	}
	return result, nil
}

func (g *gateway) issueLoginTokens(w http.ResponseWriter, r *http.Request, user userClaims) error {
	var refresh string
	expires := time.Now().Add(refreshTokenTTL)
	if user.TokenVersion > 0 {
		result, err := g.platformRefresh(r, "create", map[string]any{"username": user.Username, "tenant_id": user.TenantID, "department_id": user.DepartmentID, "application_id": user.ApplicationID, "auth_revision": user.TokenVersion})
		if err != nil {
			return err
		}
		if result.AuthenticationMethod != "local" || result.RefreshToken == "" || result.Identity.Username != user.Username || result.Identity.AuthRevision != user.TokenVersion {
			return errors.New("invalid refresh identity")
		}
		refresh = "local." + result.RefreshToken
		user.SessionID = result.SessionID
		expires = result.ExpiresAt
	} else {
		token, err := g.sessions.create(user)
		if err != nil {
			return err
		}
		refresh = "demo." + token
	}
	return g.setTokenCookies(w, user, refresh, expires)
}

func (g *gateway) setTokenCookies(w http.ResponseWriter, user userClaims, refresh string, expires time.Time) error {
	if refresh == "" || !expires.After(time.Now()) || expires.After(time.Now().Add(refreshTokenTTL+time.Minute)) {
		return errors.New("invalid refresh lifetime")
	}
	access, err := g.accessSigner.sign(user, time.Now())
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: access, Path: "/", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(accessTokenTTL / time.Second)})
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: refresh, Path: "/auth", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: max(1, int(time.Until(expires).Seconds())), Expires: expires})
	return nil
}

func (g *gateway) refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !g.sameBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "请求来源不受信任"})
		return
	}
	cookie, err := r.Cookie(refreshCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "刷新会话无效"})
		return
	}
	var user userClaims
	var next string
	var expires time.Time
	durable := false
	if strings.HasPrefix(cookie.Value, "demo.") && g.authMode == "demo" {
		next, user, expires, err = g.sessions.rotate(strings.TrimPrefix(cookie.Value, "demo."))
		next = "demo." + next
	} else if (strings.HasPrefix(cookie.Value, "local.") && (g.authMode == "demo" || g.authMode == "local")) || (strings.HasPrefix(cookie.Value, "oidc.") && g.authMode == "oidc" && g.oidcTrusted) {
		durable = true
		var result platformRefreshResult
		prefix, raw, _ := strings.Cut(cookie.Value, ".")
		result, err = g.platformRefresh(r, "rotate", map[string]any{"refresh_token": raw})
		if err == nil {
			i := result.Identity
			if result.AuthenticationMethod != prefix || i.Username == "" || i.TenantID == "" || i.AuthRevision == 0 || result.RefreshToken == "" {
				err = errors.New("invalid refresh identity")
			}
			user = userClaims{Username: i.Username, DisplayName: i.DisplayName, TenantID: i.TenantID, DepartmentID: i.DepartmentID, ApplicationID: i.ApplicationID, Roles: i.Roles, TokenVersion: i.AuthRevision, SessionID: result.SessionID}
			next = prefix + "." + result.RefreshToken
			expires = result.ExpiresAt
		}
	} else {
		err = errors.New("invalid refresh credential")
	}
	if err != nil {
		if durable && !errors.Is(err, errRemoteRefreshRejected) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "刷新服务暂不可用，请稍后重试"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "刷新会话失效，请重新登录"})
		return
	}
	if g.setTokenCookies(w, user, next, expires) != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "签发访问凭证失败"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}
