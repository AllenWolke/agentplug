package evaluationproduct

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	agenteval "github.com/lexagent/agent-evaluation"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var caseIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// evaluationCase separates the Agent-visible input from reviewer-owned gold.
// The runner must never hand expected labels to an Agent invocation.
// evaluationCase 将 Agent 可见输入与人工金标隔离；Runner 绝不能把标准答案传给 Agent。
type evaluationCase struct {
	CaseID   string              `json:"case_id"`
	Input    json.RawMessage     `json:"input"`
	Expected json.RawMessage     `json:"expected"`
	Split    string              `json:"split,omitempty"`
	Weight   *float64            `json:"weight,omitempty"`
	Reuse    *CaseReuseReference `json:"reuse,omitempty"`
}

func decodeEvaluationCase(raw json.RawMessage) (evaluationCase, error) {
	var sample evaluationCase
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sample); err != nil {
		return evaluationCase{}, ErrInvalid
	}
	var extra any
	input, expected := bytes.TrimSpace(sample.Input), bytes.TrimSpace(sample.Expected)
	if decoder.Decode(&extra) != io.EOF || !caseIDPattern.MatchString(sample.CaseID) ||
		len(input) == 0 || len(expected) == 0 || input[0] != '{' || expected[0] != '{' ||
		(sample.Split != "" && sample.Split != "train" && sample.Split != "dev" && sample.Split != "test" && sample.Split != "frozen") ||
		(sample.Weight != nil && *sample.Weight <= 0) ||
		(sample.Reuse != nil && !validCaseReuseReference(*sample.Reuse)) {
		return evaluationCase{}, ErrInvalid
	}
	return sample, nil
}

func validID(value string) bool { return idPattern.MatchString(value) }

func validKind(kind Kind) bool {
	switch kind {
	case KindDataset, KindSuite, KindMetric, KindRun, KindCaseResult, KindEvidence, KindReview, KindBaseline, KindFeedback:
		return true
	default:
		return false
	}
}

func validateResource(row Resource) error {
	if !row.Scope.valid() || !validKind(row.Kind) || !validID(row.ID) || row.Revision == 0 || strings.TrimSpace(row.Status) == "" || len(row.Status) > 24 || len(row.Data) == 0 || len(row.Data) > MaxBodySize || !json.Valid(row.Data) {
		return ErrInvalid
	}
	return nil
}

func contentHash(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	// PostgreSQL JSONB may reorder object members when it stores and
	// returns a payload. Hash the semantic JSON tree with sorted object keys so
	// dataset and metric digests survive a durable SQL round trip. UseNumber
	// avoids lossy float64 conversion for large integral fields.
	// PostgreSQL JSONB 读写时可能重排对象字段；先按语义树和稳定键序规范化，
	// 确保数据集/指标哈希经过 SQL 持久化往返后仍一致。UseNumber 避免大整数精度损失。
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return "", ErrInvalid
		}
		return "", err
	}
	data, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateDataset(data DatasetData) error {
	if strings.TrimSpace(data.Name) == "" || len(data.Name) > 128 || strings.TrimSpace(data.Version) == "" || len(data.Version) > 32 || len(data.Cases) == 0 || len(data.Cases) > 10000 {
		return ErrInvalid
	}
	switch data.SourceType {
	case "manual_gold", "synthetic_generated", "imported_redacted", "public_reference":
	default:
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(data.Cases))
	reused := 0
	for _, raw := range data.Cases {
		if len(raw) == 0 || len(raw) > (384+4)<<10 || !json.Valid(raw) {
			return ErrInvalid
		}
		sample, err := decodeEvaluationCase(raw)
		if err != nil {
			return err
		}
		if sample.Reuse != nil {
			reused++
			if reused > 1000 {
				return ErrInvalid
			}
		}
		// Preserve the original 64 KiB case contract. Only the existing bounded
		// versioned judge inputs may use their own envelope, with <=4 KiB labels.
		if len(raw) > 64<<10 {
			var judge agenteval.JudgeInput
			decoder := json.NewDecoder(bytes.NewReader(sample.Input))
			decoder.DisallowUnknownFields()
			if len(raw)-len(sample.Input) > 4<<10 || decoder.Decode(&judge) != nil || decoder.Decode(new(any)) != io.EOF ||
				(judge.Version != agenteval.JudgeInputV2 && judge.Version != agenteval.JudgeInputV3) ||
				judge.Validate() != nil || data.SourceType != "imported_redacted" {
				return ErrInvalid
			}
		}
		if _, duplicated := seen[sample.CaseID]; duplicated {
			return ErrInvalid
		}
		seen[sample.CaseID] = struct{}{}
	}
	return nil
}

func validateMetric(data MetricData) error {
	if !validID(data.MetricID) || strings.TrimSpace(data.Version) == "" || len(data.Version) > 32 || strings.TrimSpace(data.Name) == "" || len(data.Name) > 128 || len(data.Formula) == 0 || len(data.Formula) > 16<<10 || !json.Valid(data.Formula) {
		return ErrInvalid
	}
	switch data.Kind {
	case "agent_assertions", "independent_verdict", "exact_match", "contains", "numeric_tolerance", "recall_at_k", "precision_at_k", "mrr", "ndcg", "citation_accuracy", "grounding", "custom_deterministic":
	default:
		return ErrInvalid
	}
	if data.Kind == "independent_verdict" {
		if _, err := parseIndependentVerdictFormula(data.Formula); err != nil {
			return ErrInvalid
		}
	}
	if data.Kind == "custom_deterministic" {
		if !validID(data.PluginID) || strings.TrimSpace(data.PluginVersion) == "" || len(data.PluginVersion) > 64 || !validSHA256(data.PluginDigest) {
			return ErrInvalid
		}
	} else if data.PluginID != "" || data.PluginVersion != "" || data.PluginDigest != "" {
		return ErrInvalid
	}
	if data.Kind == "recall_at_k" || data.Kind == "precision_at_k" || data.Kind == "mrr" || data.Kind == "ndcg" || data.Kind == "citation_accuracy" || data.Kind == "grounding" || data.Kind == "custom_deterministic" {
		var formula remoteMetricFormula
		decoder := json.NewDecoder(bytes.NewReader(data.Formula))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&formula) != nil {
			return ErrInvalid
		}
		if !formula.validFor(data.Kind) {
			return ErrInvalid
		}
	}
	return nil
}
