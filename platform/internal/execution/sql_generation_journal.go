package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

const (
	generationJournalProtocolEpoch   = 1
	generationJournalProtocolVersion = "platform-generation-journal/v1"
)

// GenerationDispatchJournalEntry is the non-secret identity of one command
// prepared for an external transport. Empty PolicyHash is explicit: callers
// may use it only when the compatibility path cannot supply a policy digest.
// The request and resume digests are read from the locked Run, never accepted
// from the caller.
type GenerationDispatchJournalEntry struct {
	RunID             string
	ClaimRevision     uint64
	ExecutionRevision uint64
	Transport         string
	Operation         string
	BodyHash          string
	PolicyHash        string
}

// EnsureGenerationJournalSchema creates only the journal tables. It is an
// explicit deployment migration port and is not called from runtime paths.
func (s *SQLStore) EnsureGenerationJournalSchema(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return platformruntime.ErrInvalidRequest
	}
	const claimDDL = `CREATE TABLE IF NOT EXISTS platform_execution_generation_claim_journal (
 run_id VARCHAR(128) NOT NULL,
 protocol_epoch INTEGER NOT NULL CHECK (protocol_epoch > 0),
 protocol_version VARCHAR(64) NOT NULL,
 prior_status VARCHAR(16) NOT NULL CHECK (prior_status IN ('accepted','running')),
 prior_revision NUMERIC(20,0) NOT NULL CHECK (prior_revision >= 0 AND prior_revision <= 18446744073709551615),
 claim_revision NUMERIC(20,0) NOT NULL CHECK (claim_revision >= 1 AND claim_revision <= 18446744073709551615),
 lease_token_hash VARCHAR(64) NOT NULL CHECK (length(lease_token_hash)=64),
 request_hash VARCHAR(64) NOT NULL CHECK (length(request_hash)=64),
 resume_input_hash VARCHAR(64) NOT NULL CHECK (length(resume_input_hash)=64),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (run_id, claim_revision),
 CHECK (claim_revision = prior_revision + 1)
);`
	const dispatchDDL = `CREATE TABLE IF NOT EXISTS platform_execution_generation_dispatch_journal (
 run_id VARCHAR(128) NOT NULL,
 protocol_epoch INTEGER NOT NULL CHECK (protocol_epoch > 0),
 protocol_version VARCHAR(64) NOT NULL,
 claim_revision NUMERIC(20,0) NOT NULL CHECK (claim_revision >= 1 AND claim_revision <= 18446744073709551615),
 execution_revision NUMERIC(20,0) NOT NULL CHECK (execution_revision >= 1 AND execution_revision <= 18446744073709551615),
 transport VARCHAR(32) NOT NULL,
 operation VARCHAR(16) NOT NULL CHECK (operation IN ('invoke','run','resume')),
 body_hash VARCHAR(64) NOT NULL CHECK (length(body_hash)=64),
 policy_hash VARCHAR(64) NOT NULL,
 lease_token_hash VARCHAR(64) NOT NULL CHECK (length(lease_token_hash)=64),
 request_hash VARCHAR(64) NOT NULL CHECK (length(request_hash)=64),
 resume_input_hash VARCHAR(64) NOT NULL CHECK (length(resume_input_hash)=64),
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (run_id, execution_revision, claim_revision, transport, operation, body_hash, policy_hash),
 CHECK (policy_hash = '' OR length(policy_hash)=64),
 CHECK (execution_revision = claim_revision OR execution_revision = claim_revision + 1),
 FOREIGN KEY (run_id, claim_revision) REFERENCES platform_execution_generation_claim_journal(run_id, claim_revision)
);`
	if _, err := s.db.ExecContext(ctx, claimDDL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, dispatchDDL); err != nil {
		return err
	}
	const mutationFunctionDDL = `CREATE OR REPLACE FUNCTION platform_execution_generation_journal_reject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'generation journal is append-only' USING ERRCODE='55000';
 RETURN NULL;
END;
$$;`
	if _, err := s.db.ExecContext(ctx, mutationFunctionDDL); err != nil {
		return err
	}
	const mutationTriggerDDL = `DO $generation_journal_triggers$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_row_mutation' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_claim_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_claim_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_truncate' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_claim_no_truncate BEFORE TRUNCATE ON platform_execution_generation_claim_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_row_mutation' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_dispatch_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_truncate' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_truncate BEFORE TRUNCATE ON platform_execution_generation_dispatch_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
END;
$generation_journal_triggers$;`
	_, err := s.db.ExecContext(ctx, mutationTriggerDDL)
	return err
}

// RecordGenerationClaimTx appends the lease claim to the caller's existing
// Run/Session transaction. priorStatus and priorRevision are the values read
// while that transaction already held the Run UPDATE lock, before its claim
// revision increment. For the first dispatch this records accepted/1 ->
// claimed/2; TransitionLeased then creates running/3, which a dispatch journal
// entry links to claim revision 2. Reclaimed running Runs instead link the
// claimed revision directly to their execution revision.
func (s *SQLStore) RecordGenerationClaimTx(ctx context.Context, tx *sql.Tx, runID string, priorStatus platformruntime.Status, priorRevision uint64) error {
	if s == nil || s.db == nil || tx == nil || ctx == nil || runID == "" || len(runID) > 128 || priorRevision == ^uint64(0) {
		return platformruntime.ErrInvalidRequest
	}
	if priorStatus != platformruntime.StatusAccepted && priorStatus != platformruntime.StatusRunning {
		return platformruntime.ErrInvalidTransition
	}

	run, err := readExecutionRun(ctx, tx, runID, " FOR UPDATE")
	if err != nil {
		return err
	}
	if run.Scope.ValidateTrusted() != nil || run.Status != priorStatus || run.Revision != priorRevision+1 || run.LeaseToken == "" || !run.LeaseUntil.After(time.Time{}) {
		return platformruntime.ErrLeaseConflict
	}
	if err := checkGenerationJournalLeaseTx(ctx, tx, run); err != nil {
		return err
	}
	leaseHash := generationJournalHash([]byte(run.LeaseToken))
	requestHash := generationJournalHash(run.RequestJSON)
	resumeHash := generationJournalHash(run.ResumeInputJSON)

	result, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_generation_claim_journal
 (run_id,protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash,recorded_at)
 VALUES (?,?,?,?,?,?,?,?,?,clock_timestamp()) ON CONFLICT (run_id,claim_revision) DO NOTHING`),
		run.ID, generationJournalProtocolEpoch, generationJournalProtocolVersion, priorStatus, priorRevision, run.Revision, leaseHash, requestHash, resumeHash)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return nil
	}

	var epoch int
	var version, oldStatus, oldLeaseHash, oldRequestHash, oldResumeHash string
	var oldRevision, oldClaimRevision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash
 FROM platform_execution_generation_claim_journal WHERE run_id=? AND claim_revision=?`), run.ID, run.Revision).
		Scan(&epoch, &version, &oldStatus, &oldRevision, &oldClaimRevision, &oldLeaseHash, &oldRequestHash, &oldResumeHash)
	if err != nil {
		return err
	}
	if epoch != generationJournalProtocolEpoch || version != generationJournalProtocolVersion || oldStatus != string(priorStatus) || oldRevision != priorRevision || oldClaimRevision != run.Revision || oldLeaseHash != leaseHash || oldRequestHash != requestHash || oldResumeHash != resumeHash {
		return platformruntime.ErrRevisionConflict
	}
	return nil
}

// RecordGenerationDispatchTx appends a pre-send command fact under the active
// Run and Session locks. The caller must commit this transaction before it
// invokes the external transport. Same-generation commands with different
// verified bodies remain separate immutable rows; exact repeats are idempotent.
func (s *SQLStore) RecordGenerationDispatchTx(ctx context.Context, tx *sql.Tx, entry GenerationDispatchJournalEntry, leaseToken string) error {
	if s == nil || s.db == nil || tx == nil || ctx == nil || leaseToken == "" || !validGenerationJournalDispatch(entry) {
		return platformruntime.ErrInvalidRequest
	}
	run, err := readExecutionRun(ctx, tx, entry.RunID, " FOR UPDATE")
	if err != nil {
		return err
	}
	if run.Scope.ValidateTrusted() != nil || run.Status != platformruntime.StatusRunning || run.Revision != entry.ExecutionRevision || run.LeaseToken != leaseToken {
		return platformruntime.ErrLeaseConflict
	}
	if err := checkGenerationJournalLeaseTx(ctx, tx, run); err != nil {
		return err
	}
	leaseHash := generationJournalHash([]byte(run.LeaseToken))
	requestHash := generationJournalHash(run.RequestJSON)
	resumeHash := generationJournalHash(run.ResumeInputJSON)

	var (
		epoch                                                  int
		version, priorStatus, claimLeaseHash, claimRequestHash string
		claimResumeHash                                        string
		priorRevision, claimRevision                           uint64
	)
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash
 FROM platform_execution_generation_claim_journal WHERE run_id=? AND claim_revision=? FOR SHARE`), entry.RunID, entry.ClaimRevision).
		Scan(&epoch, &version, &priorStatus, &priorRevision, &claimRevision, &claimLeaseHash, &claimRequestHash, &claimResumeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	if err != nil {
		return err
	}
	if epoch != generationJournalProtocolEpoch || version != generationJournalProtocolVersion || claimRevision != entry.ClaimRevision || priorRevision+1 != claimRevision || claimLeaseHash != leaseHash || claimRequestHash != requestHash || claimResumeHash != resumeHash {
		return platformruntime.ErrLeaseConflict
	}
	switch priorStatus {
	case string(platformruntime.StatusAccepted):
		if claimRevision == ^uint64(0) || entry.ExecutionRevision != claimRevision+1 {
			return platformruntime.ErrRevisionConflict
		}
	case string(platformruntime.StatusRunning):
		if entry.ExecutionRevision != claimRevision {
			return platformruntime.ErrRevisionConflict
		}
	default:
		return platformruntime.ErrInvalidTransition
	}

	result, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_generation_dispatch_journal
 (run_id,protocol_epoch,protocol_version,claim_revision,execution_revision,transport,operation,body_hash,policy_hash,lease_token_hash,request_hash,resume_input_hash,recorded_at)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,clock_timestamp())
 ON CONFLICT (run_id,execution_revision,claim_revision,transport,operation,body_hash,policy_hash) DO NOTHING`),
		entry.RunID, generationJournalProtocolEpoch, generationJournalProtocolVersion, entry.ClaimRevision, entry.ExecutionRevision, entry.Transport, entry.Operation, entry.BodyHash, entry.PolicyHash, leaseHash, requestHash, resumeHash)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return nil
	}

	var oldEpoch int
	var oldVersion, oldTransport, oldOperation, oldBodyHash, oldPolicyHash string
	var oldLeaseHash, oldRequestHash, oldResumeHash string
	var oldClaimRevision, oldExecutionRevision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT protocol_epoch,protocol_version,claim_revision,execution_revision,transport,operation,body_hash,policy_hash,lease_token_hash,request_hash,resume_input_hash
 FROM platform_execution_generation_dispatch_journal
 WHERE run_id=? AND execution_revision=? AND claim_revision=? AND transport=? AND operation=? AND body_hash=? AND policy_hash=?`),
		entry.RunID, entry.ExecutionRevision, entry.ClaimRevision, entry.Transport, entry.Operation, entry.BodyHash, entry.PolicyHash).
		Scan(&oldEpoch, &oldVersion, &oldClaimRevision, &oldExecutionRevision, &oldTransport, &oldOperation, &oldBodyHash, &oldPolicyHash, &oldLeaseHash, &oldRequestHash, &oldResumeHash)
	if err != nil {
		return err
	}
	if oldEpoch != generationJournalProtocolEpoch || oldVersion != generationJournalProtocolVersion || oldClaimRevision != entry.ClaimRevision || oldExecutionRevision != entry.ExecutionRevision || oldTransport != entry.Transport || oldOperation != entry.Operation || oldBodyHash != entry.BodyHash || oldPolicyHash != entry.PolicyHash || oldLeaseHash != leaseHash || oldRequestHash != requestHash || oldResumeHash != resumeHash {
		return platformruntime.ErrRevisionConflict
	}
	return nil
}

// RecordGenerationDispatchForRunTx derives the unique claim revision from the
// locked current Run and its immutable claim journal. The caller cannot select
// a generation by supplying a revision: accepted claims map claim+1 to the
// running execution revision, while claims made from an already-running Run
// map directly to that revision.
func (s *SQLStore) RecordGenerationDispatchForRunTx(ctx context.Context, tx *sql.Tx, expected platformruntime.Run, transport, operation, bodyHash, policyHash string) error {
	if s == nil || s.db == nil || tx == nil || ctx == nil || expected.ID == "" || expected.Revision == 0 || expected.LeaseToken == "" {
		return platformruntime.ErrInvalidRequest
	}
	actual, err := readExecutionRun(ctx, tx, expected.ID, " FOR UPDATE")
	if err != nil {
		return err
	}
	// Heartbeats extend the current lease without changing the command revision
	// or token. The caller's earlier deadline may legitimately be stale; only
	// the locked current Run/Session deadlines determine whether dispatch is live.
	if actual.Scope.ValidateTrusted() != nil || actual.Scope != expected.Scope || actual.Status != platformruntime.StatusRunning || expected.Status != platformruntime.StatusRunning || actual.Revision != expected.Revision || actual.LeaseToken != expected.LeaseToken || generationJournalHash(actual.RequestJSON) != generationJournalHash(expected.RequestJSON) || generationJournalHash(actual.ResumeInputJSON) != generationJournalHash(expected.ResumeInputJSON) {
		return platformruntime.ErrLeaseConflict
	}
	if err := checkGenerationJournalLeaseTx(ctx, tx, actual); err != nil {
		return err
	}
	leaseHash := generationJournalHash([]byte(actual.LeaseToken))
	requestHash := generationJournalHash(actual.RequestJSON)
	resumeHash := generationJournalHash(actual.ResumeInputJSON)
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT claim_revision
 FROM platform_execution_generation_claim_journal
 WHERE run_id=? AND protocol_epoch=? AND protocol_version=? AND lease_token_hash=? AND request_hash=? AND resume_input_hash=?
 AND ((prior_status='accepted' AND claim_revision=?) OR (prior_status='running' AND claim_revision=?))
 ORDER BY claim_revision LIMIT 2 FOR SHARE`),
		actual.ID, generationJournalProtocolEpoch, generationJournalProtocolVersion, leaseHash, requestHash, resumeHash, actual.Revision-1, actual.Revision)
	if err != nil {
		return err
	}
	var claimRevision uint64
	count := 0
	for rows.Next() {
		if err := rows.Scan(&claimRevision); err != nil {
			_ = rows.Close()
			return err
		}
		count++
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if closeErr != nil {
		return closeErr
	}
	if count != 1 {
		return platformruntime.ErrLeaseConflict
	}
	return s.RecordGenerationDispatchTx(ctx, tx, GenerationDispatchJournalEntry{
		RunID: actual.ID, ClaimRevision: claimRevision, ExecutionRevision: actual.Revision,
		Transport: transport, Operation: operation, BodyHash: bodyHash, PolicyHash: policyHash,
	}, actual.LeaseToken)
}

// RecordCompatibilityDispatch records the legacy HTTP command in its own
// transaction. A positive current-epoch claim is required; old rows without
// one are never backfilled or treated as safe to send.
func (s *SQLStore) RecordCompatibilityDispatch(ctx context.Context, expected platformruntime.Run, operation, bodyHash, policyHash string) error {
	if s == nil || s.db == nil || ctx == nil {
		return platformruntime.ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.RecordGenerationDispatchForRunTx(ctx, tx, expected, "compat-http-v2", operation, bodyHash, policyHash); err != nil {
		return err
	}
	return tx.Commit()
}

func checkGenerationJournalLeaseTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) error {
	var owner, token string
	var sessionUntil sql.NullTime
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token,lease_until FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(run.Scope)).
		Scan(&owner, &token, &sessionUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if !run.LeaseUntil.After(now) || owner != run.ID || token != run.LeaseToken || !sessionUntil.Valid || !sessionUntil.Time.Equal(run.LeaseUntil) || !sessionUntil.Time.After(now) {
		return platformruntime.ErrLeaseConflict
	}
	return nil
}

func validGenerationJournalDispatch(entry GenerationDispatchJournalEntry) bool {
	if entry.RunID == "" || len(entry.RunID) > 128 || entry.ClaimRevision == 0 || entry.ExecutionRevision == 0 {
		return false
	}
	if entry.Operation != "invoke" && entry.Operation != "run" && entry.Operation != "resume" {
		return false
	}
	if entry.Transport == "" || len(entry.Transport) > 32 {
		return false
	}
	for _, r := range entry.Transport {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	if !validGenerationJournalHash(entry.BodyHash) || entry.PolicyHash != "" && !validGenerationJournalHash(entry.PolicyHash) {
		return false
	}
	return true
}

func validGenerationJournalHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func generationJournalHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
