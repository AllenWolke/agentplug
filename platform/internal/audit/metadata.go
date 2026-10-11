package audit

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrMetadataForbidden = errors.New("audit metadata access forbidden")

type MetadataScope struct {
	Type          string `json:"type"`
	TenantID      string `json:"tenant_id,omitempty"`
	DepartmentID  string `json:"department_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
}

func (s MetadataScope) Validate() error {
	for _, value := range []string{s.TenantID, s.DepartmentID, s.ApplicationID} {
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "*\x00") {
			return ErrInvalidEvent
		}
	}
	valid := false
	switch s.Type {
	case "global":
		valid = s.TenantID == "" && s.DepartmentID == "" && s.ApplicationID == ""
	case "tenant":
		valid = s.TenantID != "" && s.DepartmentID == "" && s.ApplicationID == ""
	case "department":
		valid = s.TenantID != "" && s.DepartmentID != "" && s.ApplicationID == ""
	case "application":
		valid = s.TenantID != "" && s.DepartmentID != "" && s.ApplicationID != ""
	}
	if !valid {
		return ErrInvalidEvent
	}
	return nil
}

func (s MetadataScope) contains(event Event) bool {
	return (s.TenantID == "" || s.TenantID == event.TenantID) && (s.DepartmentID == "" || s.DepartmentID == event.DepartmentID) && (s.ApplicationID == "" || s.ApplicationID == event.ApplicationID)
}

type MetadataQuery struct {
	Scope           MetadataScope
	TaskID, TraceID string
	Page, PageSize  int
}

type MetadataReader interface {
	ListMetadata(context.Context, MetadataQuery) (Page, error)
}

type MetadataAuthorizer func(context.Context, sharedkernel.Scope, MetadataScope) error

func (m *Module) SetMetadataAuthorizer(check MetadataAuthorizer) { m.authorizeMetadata = check }
