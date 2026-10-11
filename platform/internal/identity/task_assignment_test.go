package identity

import (
	"testing"
	"time"
)

func assignmentPolicyFixture() (PermissionSnapshot, PermissionQuery) {
	s, q := permissionFixture()
	s.Bindings[0].RoleCode = "reviewer"
	s.Grants[0].Action, s.Grants[0].DataScope = "business.content.read", DataScope{Type: "assigned_task"}
	q.Action = "business.content.read"
	q.Scope.Type, q.Scope.ResourceID = "agent_installation", q.ResourceID
	object := DataObject{ID: "actual-task", OwnerID: "other-owner", ActorID: "other-actor", Participants: []string{"other-owner", "other-actor"}, Scope: q.Scope}
	q.Object = &object
	s.Assignments = []TaskAssignment{{ID: "assignment", SubjectID: s.Principal.ID, TaskID: object.ID, Action: q.Action, Scope: q.Scope, Status: "active", Revision: 1, SourceID: "admin-change", TaskObject: &object}}
	return s, q
}

func TestTaskAssignmentRequiresIndependentFactsAndCurrentMetadata(t *testing.T) {
	for _, name := range []string{"valid", "spoofed-array", "no-role", "no-grant", "revoked", "wrong-action", "wrong-scope", "owner-changed", "actor-changed", "future", "expired", "machine"} {
		t.Run(name, func(t *testing.T) {
			s, q := assignmentPolicyFixture()
			object := *q.Object
			q.Object = &object
			switch name {
			case "spoofed-array":
				s.Assignments = nil
				q.Object.AssignedTo = []string{s.Principal.ID}
			case "no-role":
				s.Bindings = nil
			case "no-grant":
				s.Grants = nil
			case "revoked":
				s.Assignments[0].Status = "revoked"
			case "wrong-action":
				s.Assignments[0].Action = "business.review"
			case "wrong-scope":
				s.Assignments[0].Scope.ResourceID = "another-installation"
			case "owner-changed":
				q.Object.OwnerID = "new-owner"
			case "actor-changed":
				q.Object.ActorID = "new-actor"
			case "future":
				future := q.Now.Add(time.Second)
				s.Assignments[0].StartsAt = &future
			case "expired":
				end := q.Now
				s.Assignments[0].ExpiresAt = &end
			case "machine":
				s.Principal.Type = PrincipalServicePrincipal
				s.Grants[0].SubjectType = PrincipalServicePrincipal
			}
			decision, err := EvaluatePermission(s, q)
			if err != nil || decision.Allowed != (name == "valid") {
				t.Fatal(decision, err)
			}
		})
	}
}

func TestTaskAssignmentDataPlanAndExpiryFingerprint(t *testing.T) {
	s, q := assignmentPolicyFixture()
	app := q.Scope
	app.Type, app.ResourceID = "application", ""
	plan, err := CompileResourceDataPlan(s, q.Action, app, q.Now)
	if err != nil || len(plan.Allow) != 1 || len(plan.Allow[0].AssignedObjects) != 1 {
		t.Fatal(plan, err)
	}
	end := q.Now.Add(time.Second)
	s.Assignments[0].ExpiresAt = &end
	before, err := EffectivePermissionSnapshotDigest(s, q.Now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := EffectivePermissionSnapshotDigest(s, end)
	if err != nil || before == after {
		t.Fatal("assignment expiry did not change effective fingerprint", err)
	}
	plan, err = CompileResourceDataPlan(s, q.Action, app, end)
	if err != nil || len(plan.Allow) != 0 {
		t.Fatal("expired assignment in read plan", plan, err)
	}
	second := s.Assignments[0]
	second.ID, second.SourceID, second.ExpiresAt = "other-fact", "other-source", nil
	s.Assignments = append(s.Assignments, second)
	plan, err = CompileResourceDataPlan(s, q.Action, app, end)
	if err != nil || len(plan.Allow) != 1 {
		t.Fatal("live alternate assignment lost", plan, err)
	}
}

func TestTaskAssignmentCannotBypassReviewSeparation(t *testing.T) {
	s, q := assignmentPolicyFixture()
	q.Action, s.Grants[0].Action, s.Assignments[0].Action = "business.review", "business.review", "business.review"
	object := *q.Object
	object.ActorID = s.Principal.ID
	q.Object = &object
	s.Assignments[0].TaskObject = &object
	decision, err := EvaluatePermission(s, q)
	if err != nil || decision.Reason != "SELF_REVIEW_DENIED" {
		t.Fatal(decision, err)
	}
}
