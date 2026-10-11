package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sqlutil"
)

func modelCommandFingerprint(messages []modelgateway.Message, temperature float64, maxTokens int, promptHash string, model policyasset.ModelPolicy, names []string, embedding bool, skillBindings ...map[string]SkillModelBinding) (string, error) {
	var bindings map[string]SkillModelBinding
	if len(skillBindings) > 0 {
		bindings = skillBindings[0]
	}
	raw, err := json.Marshal(struct {
		Messages       any                          `json:"messages"`
		Temperature    float64                      `json:"temperature"`
		MaxTokens      int                          `json:"max_tokens"`
		PromptHash     string                       `json:"prompt_template_hash"`
		Model          string                       `json:"model"`
		ModelVersionID string                       `json:"model_version_id"`
		FunctionNames  []string                     `json:"function_names,omitempty"`
		SkillBindings  map[string]SkillModelBinding `json:"skill_bindings,omitempty"`
	}{messages, temperature, maxTokens, promptHash, model.Model, model.ModelVersionID, names, bindings})
	if err != nil {
		return "", err
	}
	if embedding {
		raw = append([]byte("model.embed:"), raw...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

type modelReceiptReadStore interface {
	LookupModelInvocation(context.Context, string, string) (ModelInvocation, bool, error)
}

func (s *memoryModelInvocationStore) LookupModelInvocation(_ context.Context, scope, key string) (ModelInvocation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[scope+"\x00"+key]
	// Do not expose pending response/recovery internals; only finalized receipts.
	if record.Status != "completed" {
		record.Response = nil
	}
	return cloneInvocation(record), found, nil
}
func (s *SQLModelInvocationStore) LookupModelInvocation(ctx context.Context, scope, key string) (ModelInvocation, bool, error) {
	record := ModelInvocation{ScopeHash: scope, Key: key}
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,cost_cents FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, key).Scan(&record.Fingerprint, &record.Status, &raw, &record.CostCents)
	if errors.Is(err, sql.ErrNoRows) {
		return ModelInvocation{}, false, nil
	}
	if err != nil {
		return ModelInvocation{}, false, err
	}
	if record.Status == "completed" {
		decoder := json.NewDecoder(bytes.NewBufferString(raw.String))
		decoder.UseNumber()
		if !raw.Valid || decoder.Decode(&record.Response) != nil || record.Response == nil || decoder.Decode(new(any)) != io.EOF {
			return ModelInvocation{}, false, errors.New("invalid model receipt")
		}
	}
	return record, true, nil
}
func (m *Module) modelReceipt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	m.modelReceiptAuthorized(w, r, op, r.URL.Path == "/internal/model/embed/receipt")
}

// Trusted composition callers use the same receipt checks without a provider
// invocation, budget reservation, billing repair or fabricated no-charge proof.
func (m *Module) modelReceiptAuthorized(w http.ResponseWriter, r *http.Request, op envelope, embedding bool) {
	if embedding {
		selected, err := op.Policy.Model.ForEmbedding()
		if err != nil {
			m.error(w, 403, "MODEL_SELECTION_MISMATCH", "published embedding target required", op.Context.TraceID)
			return
		}
		op.Policy.Model = selected
	}
	var input struct {
		Texts              []string                     `json:"texts"`
		EmbeddingPurpose   string                       `json:"input_purpose,omitempty"`
		Messages           []modelgateway.Message       `json:"messages"`
		FunctionNames      []string                     `json:"function_names"`
		SkillBindings      map[string]SkillModelBinding `json:"skill_bindings"`
		PromptTemplateHash string                       `json:"prompt_template_hash"`
		IdempotencyKey     string                       `json:"idempotency_key"`
		Temperature        float64                      `json:"temperature"`
		MaxTokens          int                          `json:"max_tokens"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !embedding && (len(input.Messages) == 0 || len(input.Texts) != 0) || input.IdempotencyKey == "" || len(input.IdempotencyKey) > 255 || input.MaxTokens < 0 || input.Temperature < 0 || input.Temperature > 2 {
		m.error(w, 400, "INVALID_REQUEST", "exact generation input required", op.Context.TraceID)
		return
	}
	if input.EmbeddingPurpose != "" && (!embedding || (input.EmbeddingPurpose != "query" && input.EmbeddingPurpose != "document")) {
		m.error(w, 400, "INVALID_REQUEST", "invalid embedding input purpose", op.Context.TraceID)
		return
	}
	if embedding {
		if len(input.Messages) != 0 || len(input.Texts) < 1 || len(input.Texts) > 128 || len(input.FunctionNames) != 0 || len(input.SkillBindings) != 0 {
			m.error(w, 400, "INVALID_REQUEST", "exact bounded embedding input required", op.Context.TraceID)
			return
		}
		bytes := 0
		for _, text := range input.Texts {
			bytes += len(text)
			if strings.TrimSpace(text) == "" || bytes > 1024*1024 {
				m.error(w, 400, "INVALID_REQUEST", "invalid embedding text batch", op.Context.TraceID)
				return
			}
			input.Messages = append(input.Messages, modelgateway.Message{Role: "user", Content: text})
		}
		input.PromptTemplateHash, input.MaxTokens, input.Temperature = op.Policy.Prompt.TemplateHash, 1, 0
	}
	if !validSkillModelBindings(input.SkillBindings) {
		m.error(w, 400, "INVALID_REQUEST", "invalid skill dependencies", op.Context.TraceID)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, input.SkillBindings))
	if !m.currentCapability(w, r, op) {
		return
	}
	if op.Policy.Prompt.TemplateHash != "" && input.PromptTemplateHash != op.Policy.Prompt.TemplateHash {
		m.error(w, 403, "PROMPT_VERSION_DENIED", "published prompt required", op.Context.TraceID)
		return
	}
	if input.MaxTokens == 0 {
		input.MaxTokens = op.Policy.Model.MaxTokens
	}
	if op.Policy.Model.MaxTokens > 0 && input.MaxTokens > op.Policy.Model.MaxTokens || !embedding && (modelgateway.ValidateFunctionRequest(op.Policy.Tool, input.FunctionNames, input.Messages) != nil || validateModelContextLimit(op.Policy.Model, input.Messages, op.Policy.Tool, input.FunctionNames) != nil) {
		m.error(w, 403, "MODEL_POLICY_DENIED", "generation policy denied", op.Context.TraceID)
		return
	}
	checkModel := func() bool {
		if m.modelAccess == nil {
			return true
		}
		selection, err := m.modelAccess.ResolveModel(r.Context(), scopeFromHarness(op.Context), op.Policy.Model.ModelVersionID)
		provider := strings.ToLower(strings.TrimSpace(op.Policy.Model.Provider))
		if provider == "" {
			provider = "local"
		}
		return err == nil && selection.ModelVersionID == op.Policy.Model.ModelVersionID && selection.ProviderID != "" && selection.ProviderKey != "" && selection.ModelID != "" && selection.ModelKey != "" && sameModelSelection(provider, op.Policy.Model.Model, selection) && (selection.TrustZone != modelgovernance.TrustExternal || op.Policy.Model.AllowExternal)
	}
	if !checkModel() {
		m.error(w, 403, "MODEL_ACCESS_DENIED", "current model approval denied", op.Context.TraceID)
		return
	}
	fingerprint, err := modelCommandFingerprint(input.Messages, input.Temperature, input.MaxTokens, input.PromptTemplateHash, op.Policy.Model, input.FunctionNames, embedding, input.SkillBindings)
	if err != nil {
		m.error(w, 400, "INVALID_REQUEST", "invalid generation input", op.Context.TraceID)
		return
	}
	if embedding {
		// Match the original encoding command; query/document receipts cannot cross.
		// 恢复必须匹配原编码用途，不能交叉读取查询和文档向量回执。
		fingerprint = modelPurposeFingerprint(fingerprint, input.EmbeddingPurpose)
	}
	store, available := m.modelStore.(modelReceiptReadStore)
	if !available {
		m.error(w, 503, "MODEL_RECEIPT_UNAVAILABLE", "receipt lookup unavailable", op.Context.TraceID)
		return
	}
	record, found, err := store.LookupModelInvocation(r.Context(), capabilityScopeHash(op.Context), input.IdempotencyKey)
	if err != nil {
		m.error(w, 503, "MODEL_RECEIPT_UNAVAILABLE", "receipt lookup failed", op.Context.TraceID)
		return
	}
	status := "not_found"
	var receipt map[string]any
	if found {
		if record.Fingerprint != fingerprint {
			m.error(w, 409, "MODEL_IDEMPOTENCY_CONFLICT", "generation input changed", op.Context.TraceID)
			return
		}
		status = record.Status
		switch status {
		case "completed":
			receipt = record.Response
		case "running", "failed", "reconcile":
		default:
			m.error(w, 502, "MODEL_RECEIPT_INVALID", "unknown ledger status", op.Context.TraceID)
			return
		}
	}
	if !checkModel() {
		m.error(w, 403, "MODEL_ACCESS_DENIED", "current model approval denied", op.Context.TraceID)
		return
	}
	if receipt != nil {
		var valid bool
		receipt, valid = m.withRuntimeBudget(w, r, op, receipt)
		if !valid {
			return
		}
	}
	m.currentResult(w, r, op, map[string]any{"version": "model-receipt/v1", "idempotency_key": input.IdempotencyKey, "status": status, "receipt": receipt})
}
