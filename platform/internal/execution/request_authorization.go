package execution

import (
	"errors"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Creation input, durable execution and signed continuation share immutable
// Scope. Current authority is checked through the separate owner receipt.
func bindRunAuthorization(run platformruntime.Run, request *contract.ExecuteRequest) error {
	if request == nil || run.Scope.ValidateTrusted() != nil {
		return errors.New("run authorization unavailable")
	}
	s := request.Scope
	original := sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentInstanceID: s.AgentInstanceID, AgentID: s.AgentID, PrincipalID: s.PrincipalID, PrincipalType: s.PrincipalType, InstallationID: s.InstallationID, AgentVersionID: s.AgentVersionID, SessionID: s.SessionID, RunID: s.RunID, ParentRunID: s.ParentRunID, AuthorizationEpoch: s.AuthorizationEpoch, TraceID: s.TraceID}
	if original != run.Scope {
		return errors.New("run authorization scope differs")
	}
	return nil
}
