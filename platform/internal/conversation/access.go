package conversation

import "context"

// SessionResource excludes titles, previews, messages and export payloads.
// It is read from authoritative persistence before a protected operation.
type SessionResource struct {
	ID, OwnerID, PrincipalType, InstallationID, AgentID, AgentVersionID string
	MessageCount                                                        int
}

type HistoryDataClause struct {
	InstallationID, Type string
	IDs                  []string
}

type HistoryAccessPlan struct {
	Legacy      bool
	Allow, Deny []HistoryDataClause
}

type AccessControl interface {
	ReadPlan(context.Context, Scope) (HistoryAccessPlan, error)
	Authorize(context.Context, Scope, SessionResource, string) error
}

type SessionPermissionProjector interface {
	Project(context.Context, Scope, []Summary) ([]Summary, error)
}

func (m *Module) projectPermissions(ctx context.Context, scope Scope, items []Summary) ([]Summary, error) {
	if projector, ok := m.access.(SessionPermissionProjector); ok {
		return projector.Project(ctx, scope, items)
	}
	return items, nil
}

type AuthorizedHistoryReader interface {
	GetSessionResource(context.Context, Scope, string) (SessionResource, error)
	ListAuthorized(context.Context, Scope, Query, HistoryAccessPlan) (Page, error)
	GetExportSessionID(context.Context, Scope, string) (string, error)
}

func (m *Module) SetAccessControl(control AccessControl) { m.access = control }

func (m *Module) authorizeSession(ctx context.Context, scope Scope, id, action string) (Scope, error) {
	if m.access == nil {
		return scope, nil
	}
	reader, ok := m.store.(AuthorizedHistoryReader)
	if !ok {
		return Scope{}, ErrForbidden
	}
	resource, err := reader.GetSessionResource(ctx, scope, id)
	if err != nil {
		return Scope{}, err
	}
	if action == "run-or-continue" {
		action = "history.continue"
		if resource.MessageCount == 0 {
			action = "run"
		}
	}
	if err := m.access.Authorize(ctx, scope, resource, action); err != nil {
		return Scope{}, err
	}
	// Cross-owner reads preserve the authenticated actor. Mutations keep the
	// existing ownership boundary until their actor/source provenance is stored.
	if action == "history.read" {
		scope.historyOwnerID = resource.OwnerID
	}
	return scope, nil
}

func sessionRouteAction(parts []string, method string) string {
	if len(parts) == 1 && method == "GET" {
		return "history.read"
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "resume":
			if method == "POST" {
				return "history.continue"
			}
		case "runs":
			if method == "POST" {
				return "run-or-continue"
			}
		case "messages":
			if method == "GET" {
				return "history.read"
			}
			if method == "POST" {
				return "history.continue"
			}
		case "shares":
			if method == "POST" {
				return "history.share"
			}
		}
	}
	if len(parts) == 4 && parts[1] == "messages" {
		if parts[3] == "regenerate" && method == "POST" {
			return "history.regenerate"
		}
		if parts[3] == "revisions" {
			if method == "GET" {
				return "history.read"
			}
			if method == "POST" {
				return "history.revise"
			}
		}
	}
	return ""
}
