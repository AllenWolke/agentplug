package agentcoordination

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// DelegationAuthorityProof is an internal, admission-produced snapshot. It
// contains only IAM version numbers and immutable route identities, never a
// token or user supplied authority. Each edge is checked against current IAM
// before a delegated Run can dispatch or use a capability.
type DelegationAuthorityProof struct {
	Version                string                         `json:"version"`
	RootRunID              string                         `json:"root_run_id"`
	RootInstallationID     string                         `json:"root_installation_id"`
	RootPrincipalType      string                         `json:"root_principal_type"`
	RootPrincipalID        string                         `json:"root_principal_id"`
	RootAuthorizationEpoch uint64                         `json:"root_authorization_epoch"`
	RootMachinePrincipalID string                         `json:"root_machine_principal_id"`
	RootMachineRunEpoch    uint64                         `json:"root_machine_run_epoch"`
	Edges                  []DelegationAuthorityProofEdge `json:"edges"`
}

type DelegationAuthorityProofEdge struct {
	ParentRunID                string `json:"parent_run_id"`
	ChildRunID                 string `json:"child_run_id"`
	ParentInstallationID       string `json:"parent_installation_id"`
	ParentMachinePrincipalID   string `json:"parent_machine_principal_id"`
	TargetInstallationID       string `json:"target_installation_id"`
	TargetAgentID              string `json:"target_agent_id"`
	TargetVersionID            string `json:"target_version_id"`
	TargetManifestHash         string `json:"target_manifest_hash"`
	CallerDelegateEpoch        uint64 `json:"caller_delegate_epoch"`
	ParentMachineDelegateEpoch uint64 `json:"parent_machine_delegate_epoch"`
	TargetMachinePrincipalID   string `json:"target_machine_principal_id"`
	TargetMachineRunEpoch      uint64 `json:"target_machine_run_epoch"`
}

type RootMachineAuthorityStamp struct {
	RootRunID              string `json:"root_run_id"`
	RootInstallationID     string `json:"root_installation_id"`
	RootPrincipalType      string `json:"root_principal_type"`
	RootPrincipalID        string `json:"root_principal_id"`
	RootAuthorizationEpoch uint64 `json:"root_authorization_epoch"`
	MachinePrincipalID     string `json:"machine_principal_id"`
	MachineRunEpoch        uint64 `json:"machine_run_epoch"`
}

func validRootMachineAuthorityStamp(stamp RootMachineAuthorityStamp) bool {
	return stamp.RootRunID != "" && stamp.RootInstallationID != "" && stamp.RootPrincipalType != "" && stamp.RootPrincipalID != "" && stamp.RootAuthorizationEpoch > 0 && stamp.MachinePrincipalID != "" && stamp.MachineRunEpoch > 0
}

func ValidDelegationAuthorityProof(proof DelegationAuthorityProof) bool {
	if proof.Version != "agent-delegation-authority/v1" || proof.RootRunID == "" || proof.RootInstallationID == "" || proof.RootPrincipalType == "" || proof.RootPrincipalID == "" || proof.RootAuthorizationEpoch == 0 || proof.RootMachinePrincipalID == "" || proof.RootMachineRunEpoch == 0 || len(proof.Edges) < 1 || len(proof.Edges) > 4 {
		return false
	}
	seenRuns := map[string]bool{proof.RootRunID: true}
	parentRunID := proof.RootRunID
	parentInstallation := proof.RootInstallationID
	parentMachineID := proof.RootMachinePrincipalID
	for _, edge := range proof.Edges {
		if edge.ParentRunID != parentRunID || edge.ChildRunID == "" || edge.ParentInstallationID != parentInstallation || edge.ParentMachinePrincipalID != parentMachineID || edge.TargetInstallationID == "" || edge.TargetAgentID == "" || edge.TargetVersionID == "" || edge.TargetManifestHash == "" || edge.CallerDelegateEpoch == 0 || edge.ParentMachineDelegateEpoch == 0 || edge.TargetMachinePrincipalID == "" || edge.TargetMachineRunEpoch == 0 || seenRuns[edge.ChildRunID] {
			return false
		}
		seenRuns[edge.ChildRunID] = true
		parentRunID, parentInstallation = edge.ChildRunID, edge.TargetInstallationID
		parentMachineID = edge.TargetMachinePrincipalID
	}
	return true
}

func validDelegationAuthorityJSON(raw string) bool {
	if raw == "" || len(raw) > 32768 {
		return false
	}
	var proof DelegationAuthorityProof
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&proof) == nil && decoder.Decode(new(any)) == io.EOF && ValidDelegationAuthorityProof(proof)
}

// EnsureDelegationAuthoritySchema is an explicit forward migration. It must be
// called only by the platform migration command, never at service startup.
func (s *SQLRouteStore) EnsureDelegationAuthoritySchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	_, err := s.db.ExecContext(ctx, `ALTER TABLE platform_agent_child_reservation ADD COLUMN IF NOT EXISTS delegation_authority_json TEXT CHECK(octet_length(delegation_authority_json)<=32768);
CREATE TABLE IF NOT EXISTS platform_agent_delegation_root_authority (
 root_run_id VARCHAR(128) PRIMARY KEY, root_installation_id VARCHAR(128) NOT NULL,
 root_principal_type VARCHAR(64) NOT NULL, root_principal_id VARCHAR(128) NOT NULL,
 root_authorization_epoch NUMERIC(20,0) NOT NULL CHECK(root_authorization_epoch>0),
 machine_principal_id VARCHAR(128) NOT NULL,
 machine_run_epoch NUMERIC(20,0) NOT NULL CHECK(machine_run_epoch>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());`)
	return err
}

// PinRootMachineAuthorityTx is called from the trusted dispatcher immediately
// before the root Agent receives its first execution. A machine permission
// change therefore invalidates later delegated descendants even though a Run
// Scope carries only the caller's epoch.
func (s *SQLRouteStore) PinRootMachineAuthorityTx(ctx context.Context, tx *sql.Tx, stamp RootMachineAuthorityStamp) error {
	if s == nil || tx == nil || !validRootMachineAuthorityStamp(stamp) {
		return ErrDenied
	}
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_delegation_root_authority(root_run_id,root_installation_id,root_principal_type,root_principal_id,root_authorization_epoch,machine_principal_id,machine_run_epoch) VALUES(?,?,?,?,?,?,?) ON CONFLICT(root_run_id) DO NOTHING`), stamp.RootRunID, stamp.RootInstallationID, stamp.RootPrincipalType, stamp.RootPrincipalID, stamp.RootAuthorizationEpoch, stamp.MachinePrincipalID, stamp.MachineRunEpoch)
	if err != nil {
		return err
	}
	var saved RootMachineAuthorityStamp
	// The stamp is immutable: DO NOTHING preserves the initial authority and
	// exact comparison rejects changes. Shared read fencing lets heartbeats
	// coexist with child admission reading that same authority.
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,root_installation_id,root_principal_type,root_principal_id,root_authorization_epoch,machine_principal_id,machine_run_epoch FROM platform_agent_delegation_root_authority WHERE root_run_id=? FOR SHARE`), stamp.RootRunID).Scan(&saved.RootRunID, &saved.RootInstallationID, &saved.RootPrincipalType, &saved.RootPrincipalID, &saved.RootAuthorizationEpoch, &saved.MachinePrincipalID, &saved.MachineRunEpoch)
	if err != nil || saved != stamp {
		return ErrDenied
	}
	return nil
}

func (s *SQLRouteStore) RootMachineAuthorityTx(ctx context.Context, tx *sql.Tx, rootRunID string) (RootMachineAuthorityStamp, error) {
	var stamp RootMachineAuthorityStamp
	if s == nil || tx == nil || rootRunID == "" {
		return stamp, ErrDenied
	}
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,root_installation_id,root_principal_type,root_principal_id,root_authorization_epoch,machine_principal_id,machine_run_epoch FROM platform_agent_delegation_root_authority WHERE root_run_id=? FOR SHARE`), rootRunID).Scan(&stamp.RootRunID, &stamp.RootInstallationID, &stamp.RootPrincipalType, &stamp.RootPrincipalID, &stamp.RootAuthorizationEpoch, &stamp.MachinePrincipalID, &stamp.MachineRunEpoch)
	if lockWaitError(err) {
		return RootMachineAuthorityStamp{}, err
	}
	if err != nil || !validRootMachineAuthorityStamp(stamp) {
		return RootMachineAuthorityStamp{}, ErrDenied
	}
	return stamp, nil
}

// DelegationAuthorityProofTx is deliberately internal to the composition
// layer. A caller must first establish the exact persisted child edge.
func (s *SQLRouteStore) DelegationAuthorityProofTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) (DelegationAuthorityProof, error) {
	return s.delegationAuthorityProofTx(ctx, tx, parent, child, depth, false)
}

// DelegationAuthorityProofForDisclosureTx permits terminal recorded edges so
// the caller can disclose a child result under current live IAM. It does not
// make a terminal child dispatchable or renew its lease.
func (s *SQLRouteStore) DelegationAuthorityProofForDisclosureTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) (DelegationAuthorityProof, error) {
	return s.delegationAuthorityProofTx(ctx, tx, parent, child, depth, true)
}

func (s *SQLRouteStore) delegationAuthorityProofTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, recorded bool) (DelegationAuthorityProof, error) {
	var proof DelegationAuthorityProof
	check := (*SQLRouteStore).CheckChildEdgeTx
	if recorded {
		check = (*SQLRouteStore).CheckRecordedChildEdgeTx
	}
	if s == nil || tx == nil {
		return proof, ErrDenied
	}
	if err := check(s, ctx, tx, parent, child, depth); err != nil {
		if lockWaitError(err) {
			return proof, err
		}
		return proof, ErrDenied
	}
	var raw string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.delegation_authority_json FROM platform_agent_child_reservation c JOIN platform_agent_route r ON r.parent_key=c.parent_key AND r.operation_key=c.operation_key WHERE c.parent_key=? AND r.parent_run_id=? AND c.child_run_id=? FOR SHARE OF r,c`), routeScopeKey(parent), parent.RunID, child.RunID).Scan(&raw)
	if lockWaitError(err) {
		return proof, err
	}
	if err != nil || !validDelegationAuthorityJSON(raw) {
		return proof, ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || !ValidDelegationAuthorityProof(proof) || len(proof.Edges) != depth {
		return DelegationAuthorityProof{}, ErrDenied
	}
	last := proof.Edges[len(proof.Edges)-1]
	if last.ParentRunID != parent.RunID || last.ChildRunID != child.RunID || last.ParentInstallationID != parent.InstallationID || last.TargetInstallationID != child.InstallationID || last.TargetAgentID != child.AgentID || last.TargetVersionID != child.AgentVersionID {
		return DelegationAuthorityProof{}, ErrDenied
	}
	return proof, nil
}
