package runtime

import (
	"errors"
	"testing"
	"time"
)

func TestWorkerLeaseRenewalKeepsCommandRevisionAndFencesReplacedOwner(t *testing.T) {
	s := NewStore()
	created, err := s.Create(CreateRequest{ID: "fenced-run", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "fenced", Fingerprint: "body"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claimed, err := s.AcquireLease(created.Run.ID, "owner-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := s.TransitionLeased(claimed.ID, StatusAccepted, StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := s.Heartbeat(running.ID, "owner-a", running.Revision, now.Add(time.Second), time.Minute)
	if err != nil || renewed.Revision != running.Revision {
		t.Fatalf("heartbeat changed command revision: %+v %v", renewed, err)
	}
	// A stolen or expired lease must never permit worker terminal writes.
	// 过期或已被接管的租约不能提交终态。
	if _, err := s.TransitionLeased(running.ID, StatusRunning, StatusSucceeded, running.Revision, "owner-b"); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("foreign owner committed: %v", err)
	}
	if _, err := s.Heartbeat(running.ID, "owner-a", running.Revision, renewed.LeaseUntil, time.Minute); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expired heartbeat accepted: %v", err)
	}
	completed, err := s.TransitionLeased(running.ID, StatusRunning, StatusSucceeded, running.Revision, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireLease(completed.ID, "owner-c", now, time.Minute); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("terminal run claimed: %v", err)
	}
	if _, err := s.Heartbeat(completed.ID, "owner-a", completed.Revision, now, time.Minute); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("terminal run renewed: %v", err)
	}
}
