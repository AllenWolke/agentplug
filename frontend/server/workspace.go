package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func (g *gateway) switchWorkspace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !g.sameBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "请求来源不受信任"})
		return
	}
	user, ok := g.authenticate(r)
	if !ok || user.TokenVersion == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "请使用持久登录会话切换工作空间"})
		return
	}
	cookie, err := r.Cookie(refreshCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "刷新会话无效"})
		return
	}
	prefix, raw, _ := strings.Cut(cookie.Value, ".")
	if prefix != "local" && prefix != "oidc" || prefix == "oidc" && g.authMode != "oidc" || prefix == "local" && g.authMode == "oidc" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "刷新会话无效"})
		return
	}
	var target struct {
		TenantID      string `json:"tenant_id"`
		DepartmentID  string `json:"department_id"`
		ApplicationID string `json:"application_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&target) != nil || decoder.Decode(new(any)) != io.EOF || target.TenantID == "" || target.DepartmentID == "" || target.ApplicationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "工作空间参数无效"})
		return
	}
	result, err := g.platformRefresh(r, "workspace", map[string]any{"refresh_token": raw, "username": user.Username, "auth_revision": user.TokenVersion, "tenant_id": target.TenantID, "department_id": target.DepartmentID, "application_id": target.ApplicationID})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errRemoteWorkspaceForbidden) {
			status = http.StatusForbidden
		}
		if errors.Is(err, errRemoteRefreshRejected) {
			status = http.StatusUnauthorized
		}
		writeJSON(w, status, map[string]string{"message": "工作空间切换未完成，请检查成员资格或重试"})
		return
	}
	i := result.Identity
	if result.AuthenticationMethod != prefix || result.RefreshToken == "" || i.Username != user.Username || i.AuthRevision != user.TokenVersion || i.TenantID != target.TenantID || i.DepartmentID != target.DepartmentID || i.ApplicationID != target.ApplicationID {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "工作空间服务响应异常"})
		return
	}
	next := userClaims{Username: i.Username, DisplayName: i.DisplayName, TenantID: i.TenantID, DepartmentID: i.DepartmentID, ApplicationID: i.ApplicationID, Roles: i.Roles, TokenVersion: i.AuthRevision, SessionID: result.SessionID}
	if g.setTokenCookies(w, next, prefix+"."+result.RefreshToken, result.ExpiresAt) != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "签发工作空间凭证失败"})
		return
	}
	writeJSON(w, http.StatusOK, next)
}
