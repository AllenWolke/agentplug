package identity

import (
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// 最高管理权不构成本人业务增权的批准。自助申请与管理员直接办理使用同一人员分离边界。
// 本人可申请退出普通业务身份；撤销 deny 会扩大权限，因此不属于自行减权。
func authorizeSelfAuthorizationChange(actor sharedkernel.Scope, command AuthorizationChangeCommand, target PermissionSnapshot) error {
	if command.SubjectType != PrincipalUser || !strings.EqualFold(actor.PrincipalID, command.SubjectID) {
		return nil
	}
	if command.Preset != nil || command.AgentSelection != nil || len(command.Bindings) != 0 || len(command.Grants) != 0 || len(command.Assignments) != 0 {
		return ErrPermissionDenied
	}
	for _, membership := range command.Memberships {
		if membership.Status == "active" {
			return ErrPermissionDenied
		}
	}
	for _, id := range command.RevokeGrantIDs {
		for _, grant := range target.Grants {
			if grant.ID == id && grant.Effect == "deny" {
				return ErrPermissionDenied
			}
		}
	}
	return nil
}
