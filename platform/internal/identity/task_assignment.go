package identity

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Assignment is a scoped, action-specific administrative fact. It supplies no
// role or Grant and never gives every action access to a selected task.
type TaskAssignment struct {
	ID           string          `json:"id"`
	SubjectID    string          `json:"subject_id"`
	TaskID       string          `json:"task_id"`
	Action       string          `json:"action"`
	Scope        ManagementScope `json:"scope"`
	Status       string          `json:"status"`
	Revision     uint64          `json:"revision"`
	SourceID     string          `json:"source_id"`
	DelegationID string          `json:"delegation_id,omitempty"`
	TaskObject   *DataObject     `json:"task_object,omitempty"`
	Validity
}

type PermissionTaskResolver interface {
	ResolvePermissionTask(context.Context, sharedkernel.Scope, ManagementScope, string) (DataObject, error)
}

func canonicalAssignmentObject(object DataObject) DataObject {
	object.AssignedTo = nil
	object.Participants = append([]string(nil), object.Participants...)
	if object.OwnerID != "" {
		object.Participants = append(object.Participants, object.OwnerID)
	}
	if object.ActorID != "" {
		object.Participants = append(object.Participants, object.ActorID)
	}
	slices.Sort(object.Participants)
	object.Participants = slices.Compact(object.Participants)
	if object.ActorID == "" {
		object.ActorID = object.OwnerID
	}
	return object
}

func assignmentObjectEqual(expected, actual DataObject) bool {
	expected, actual = canonicalAssignmentObject(expected), canonicalAssignmentObject(actual)
	a, _ := json.Marshal(expected)
	b, _ := json.Marshal(actual)
	return string(a) == string(b)
}

func (a TaskAssignment) matches(subject, action string, scope ManagementScope, now time.Time) bool {
	return a.SubjectID == subject && a.Action == action && a.Status == "active" && a.Revision > 0 && a.Scope.Type == "agent_installation" && a.Scope.Validate() == nil && a.Scope == scope && a.Validity.Validate() == nil && a.Effective(now) && a.TaskID != "" && !strings.ContainsAny(a.TaskID, "*\x00") && a.SourceID != "" && a.TaskObject != nil && a.TaskObject.ID == a.TaskID && a.TaskObject.Scope == a.Scope && a.TaskObject.OwnerID != ""
}

func assignedObjects(snapshot PermissionSnapshot, action string, scope ManagementScope, now time.Time) []DataObject {
	objects := []DataObject{}
	if snapshot.Principal.Type != PrincipalUser {
		return objects
	}
	for _, assignment := range snapshot.Assignments {
		if assignment.matches(snapshot.Principal.ID, action, scope, now) {
			objects = append(objects, canonicalAssignmentObject(*assignment.TaskObject))
		}
	}
	return objects
}

func assignedObjectMatches(snapshot PermissionSnapshot, query PermissionQuery) bool {
	if query.Object == nil {
		return false
	}
	for _, object := range assignedObjects(snapshot, query.Action, query.Scope, query.Now) {
		if assignmentObjectEqual(object, *query.Object) {
			return true
		}
	}
	return false
}
