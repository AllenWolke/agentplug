package evaluationproduct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

// PutEvaluationOutput persists an opaque Agent result under the complete
// tenant/department/application scope. Duplicate delivery is accepted only
// when the stable artifact identity and payload match byte-for-byte.
// PutEvaluationOutput 按完整租户/部门/应用作用域保存 Agent 输出；只有稳定身份与载荷逐字节一致时才接受重复投递。
func (s *SQLStore) PutEvaluationOutput(ctx context.Context, scope Scope, runID string, caseIndex int, idempotencyKey string, payload []byte) (ArtifactReference, error) {
	if s == nil || s.db == nil || !scope.valid() || !validID(runID) || caseIndex < 0 || !validID(idempotencyKey) ||
		len(payload) == 0 || len(payload) > 1<<20 || !json.Valid(payload) {
		return ArtifactReference{}, ErrInvalid
	}
	caseID := evaluationArtifactCaseID(runID, caseIndex)
	digest := sha256.Sum256(payload)
	digestText := hex.EncodeToString(digest[:])
	material, err := json.Marshal(struct {
		Scope  Scope  `json:"scope"`
		RunID  string `json:"run_id"`
		CaseID string `json:"case_id"`
		Key    string `json:"key"`
	}{scope, runID, caseID, idempotencyKey})
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("encode evaluation artifact identity: %w", err)
	}
	identityHash := sha256.Sum256(material)
	artifactID := "eval-artifact-" + hex.EncodeToString(identityHash[:16])
	_, insertErr := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_evaluation_product_output_artifact
		(tenant_id,department_id,application_id,run_id,case_id,artifact_id,sha256,size_bytes,payload,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID, caseID,
		artifactID, digestText, len(payload), payload, time.Now().UTC())
	if insertErr != nil {
		var currentID, currentDigest string
		var currentSize int64
		var currentPayload []byte
		queryErr := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT artifact_id,sha256,size_bytes,payload FROM platform_evaluation_product_output_artifact
			WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? AND case_id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID, caseID).
			Scan(&currentID, &currentDigest, &currentSize, &currentPayload)
		if queryErr != nil || currentID != artifactID || currentDigest != digestText || currentSize != int64(len(payload)) || !bytes.Equal(currentPayload, payload) {
			return ArtifactReference{}, fmt.Errorf("evaluation artifact idempotency conflict: %w", insertErr)
		}
	}
	return ArtifactReference{ID: artifactID, SHA256: digestText, Size: int64(len(payload))}, nil
}

func evaluationArtifactCaseID(runID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("evaluation-case-artifact:%s:%d", runID, index)))
	return "case-" + hex.EncodeToString(sum[:16])
}

var _ ArtifactWriter = (*SQLStore)(nil)
