// Package sharedkernel contains only stable cross-module value objects.
// sharedkernel 只包含跨模块稳定值对象，不包含业务实体、ORM 模型或外部客户端。
package sharedkernel

import "errors"

var ErrInvalidScope = errors.New("invalid scope")

// Scope identifies the trusted execution boundary.
// Scope 标识可信的租户、应用、用户和安装实例边界。
type Scope struct {
	TenantID           string
	DepartmentID       string
	ApplicationID      string
	AgentInstanceID    string
	AgentID            string
	PrincipalID        string
	PrincipalType      string
	InstallationID     string
	AgentVersionID     string
	SessionID          string
	RunID              string
	ParentRunID        string
	AuthorizationEpoch uint64
	TraceID            string
}

// Validate rejects an incomplete execution scope before it reaches a module.
// Validate 在 Scope 进入模块前拒绝不完整的执行上下文。
func (s Scope) Validate() error {
	if s.TenantID == "" || s.DepartmentID == "" || s.ApplicationID == "" || s.PrincipalID == "" {
		return ErrInvalidScope
	}
	return nil
}

// ValidateTrusted enforces the complete Agent Execution v2 boundary. The
// lighter Validate method remains available to internal domain fixtures, while
// HTTP/remote entry points must carry the full identity and replay context.
// ValidateTrusted 用于 HTTP/远程入口，要求完整身份、会话和重放上下文。
func (s Scope) ValidateTrusted() error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.AgentInstanceID == "" || s.AgentID == "" || s.AgentVersionID == "" || s.InstallationID == "" || s.PrincipalType == "" || s.SessionID == "" || s.RunID == "" || s.TraceID == "" || s.AuthorizationEpoch == 0 {
		return ErrInvalidScope
	}
	if s.PrincipalType != "user" && s.PrincipalType != "service_principal" {
		return ErrInvalidScope
	}
	return nil
}
