package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// Operations metadata uses current platform authority as well as a signed
// authentication assertion. Revoked role bindings cannot survive in JWT roles.
func (g *gateway) currentMonitorPermission(r *http.Request, user userClaims) (bool, error) {
	raw, err := json.Marshal(map[string]any{"action": "platform.monitor", "scope": map[string]string{"scope_type": "application", "tenant_id": user.TenantID, "department_id": user.DepartmentID, "application_id": user.ApplicationID}})
	if err != nil {
		return false, err
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/permissions:explain"
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Authentication-Session", user.SessionID)
	request.Header.Set("X-Authentication-Revision", strconv.FormatUint(user.TokenVersion, 10))
	request.Header.Set("X-Tenant-ID", user.TenantID)
	request.Header.Set("X-Department-ID", user.DepartmentID)
	request.Header.Set("X-Application-ID", user.ApplicationID)
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", user.Username)
	response, err := g.httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if response.StatusCode != http.StatusOK {
		return false, errors.New("current monitor permission unavailable")
	}
	var decision struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&decision); err != nil {
		return false, err
	}
	return decision.Allowed, nil
}
