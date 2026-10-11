package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net"
	"strings"
)

func (a capabilityExecutionAuthority) AuthenticateWorkload(ctx context.Context, scope sharedkernel.Scope, clientID, secret, peer string) error {
	store, ok := a.identity.(interface {
		PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error)
		ResolveWorkloadIdentity(context.Context, sharedkernel.Scope) (identity.WorkloadBinding, error)
		GetMachineCredential(context.Context, string, string) (identity.MachineCredential, error)
	})
	if !ok {
		return identity.ErrPermissionDenied
	}
	caller, err := store.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil {
		return err
	}
	if caller.Mode == "legacy" || caller.Mode == "shadow" {
		return nil
	}
	if caller.Mode != "v2" || scope.ValidateTrusted() != nil || scope.AgentInstanceID != scope.InstallationID || clientID == "" || len(secret) < 32 || len(secret) > 512 || strings.TrimSpace(secret) != secret {
		return identity.ErrPermissionDenied
	}
	binding, err := store.ResolveWorkloadIdentity(ctx, scope)
	if err != nil {
		return err
	}
	if binding.Status != "active" || binding.Revision == 0 || binding.PrincipalID != clientID || binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID || binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID || binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID {
		return identity.ErrPermissionDenied
	}
	credential, err := store.GetMachineCredential(ctx, scope.TenantID, clientID)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(secret))
	provided := hex.EncodeToString(hash[:])
	if credential.Status != "active" || credential.Revision == 0 || credential.TenantID != scope.TenantID || credential.PrincipalID != clientID || subtle.ConstantTimeCompare([]byte(provided), []byte(credential.SecretHash)) != 1 {
		return identity.ErrPermissionDenied
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return identity.ErrPermissionDenied
	}
	ip := net.ParseIP(host)
	allowed := false
	for _, cidr := range credential.NetworkCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			allowed = true
		}
	}
	if !allowed {
		return identity.ErrPermissionDenied
	}
	executor, err := store.PermissionSnapshot(ctx, identity.PrincipalServicePrincipal, clientID)
	if err != nil {
		return err
	}
	if executor.Mode != "v2" || !executor.Principal.IsActive || executor.Principal.Type != identity.PrincipalServicePrincipal || executor.Principal.ID != clientID || executor.Principal.TenantID != scope.TenantID {
		return identity.ErrPermissionDenied
	}
	return nil
}
