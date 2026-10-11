package agenteval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const RubricVersion = "agent-eval-rubric/v1"
const JudgementVersion = "agent-eval-judgement/v1"

type Rubric struct {
	Version  string            `json:"version"`
	ID       string            `json:"id"`
	Criteria map[string]string `json:"criteria"`
}
type Verdict struct {
	MetricID string   `json:"metric_id"`
	Value    *bool    `json:"value"`
	Evidence []string `json:"evidence"`
	Reason   string   `json:"reason"`
}
type Judgement struct {
	Version                  string       `json:"version"`
	Source                   string       `json:"source"`
	SourceRunID              string       `json:"source_run_id"`
	SourceOutputHash         string       `json:"source_output_hash"`
	SourceRedactedOutputHash string       `json:"source_redacted_output_hash"`
	Rubric                   Rubric       `json:"rubric"`
	RubricHash               string       `json:"rubric_hash"`
	ExpectedHash             string       `json:"expected_hash,omitempty"`
	Verdicts                 []Verdict    `json:"verdicts"`
	JudgeRunID               string       `json:"judge_run_id,omitempty"`
	JudgeVersionID           string       `json:"judge_version_id,omitempty"`
	ScoringModel             string       `json:"scoring_model,omitempty"`
	ScoringModelVersion      string       `json:"scoring_model_version,omitempty"`
	ReviewerID               string       `json:"reviewer_id,omitempty"`
	ReviewEvidenceID         string       `json:"review_evidence_id,omitempty"`
	Measurements             Measurements `json:"measurements"`
}
type JudgeInput struct {
	Version          string                     `json:"version"`
	SourceRunID      string                     `json:"source_run_id"`
	SourceOutputHash string                     `json:"source_output_hash"`
	Rubric           Rubric                     `json:"rubric"`
	RubricHash       string                     `json:"rubric_hash"`
	Evidence         map[string]json.RawMessage `json:"evidence"`
}

type SourceReference struct {
	RunID              string `json:"run_id"`
	OutputHash         string `json:"output_hash"`
	RedactedOutputHash string `json:"redacted_output_hash"`
}

func (in JudgeInput) SourceReference() (SourceReference, error) {
	return in.sourceReference(false)
}
func (in JudgeInput) HumanSourceReference() (SourceReference, error) { return in.sourceReference(true) }
func (in JudgeInput) sourceReference(human bool) (SourceReference, error) {
	if err := in.validate(human); err != nil {
		return SourceReference{}, err
	}
	output, ok := in.Evidence["output"]
	if !ok {
		return SourceReference{}, errors.New("frozen actual output is required")
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(output))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return SourceReference{}, errors.New("invalid frozen output")
	}
	b, _ := json.Marshal(Sanitize(value))
	h := sha256.Sum256(b)
	return SourceReference{RunID: in.SourceRunID, OutputHash: in.SourceOutputHash, RedactedOutputHash: hex.EncodeToString(h[:])}, nil
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Sequence counters belong to a Run, not the entire collaboration tree.
func EventReference(rootRunID string, event Event) string {
	if event.StepID != "" && reviewIDPattern.MatchString("step:"+event.StepID) {
		return "step:" + event.StepID
	}
	if event.Seq == 0 {
		return ""
	}
	if event.RunID == "" || event.RunID == rootRunID {
		return "event:" + fmt.Sprint(event.Seq)
	}
	b, _ := json.Marshal([]any{event.RunID, event.Seq})
	h := sha256.Sum256(b)
	return "event-" + hex.EncodeToString(h[:])
}

var reviewIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Safety absence, execution/billing counters and human acceptance cannot be
// certified by an LLM. A model may flag a violation for further review.
func ModelReviewable(id string) bool {
	return id == "domain_correctness" || id == "task_success" || id == "plan_correctness" || id == "replan_success" || id == "early_stop_accuracy" || id == "groundedness" || id == "faithfulness" || id == "citation_accuracy" || id == "context_precision" || id == "context_recall" || id == "memory_precision"
}

// Human review may evaluate explicit safety/state/reliability test
// opportunities, but cannot fabricate objective timing or billing counters.
func HumanReviewable(id string) bool {
	if ModelReviewable(id) || id == "human_acceptance" {
		return true
	}
	switch id {
	case "prompt_injection_resistance", "state_consistency", "checkpoint_resume_success", "memory_pollution", "duplicate_action", "permission_violation", "sensitive_data_leakage", "unsafe_tool_call", "prompt_injection_attack_success", "unauthorized_data_access", "failure_recovery", "retry_success", "timeout_handling", "resume_success", "handoff", "dlq", "unknown_side_effect_handling":
		return true
	}
	return false
}
func RubricDigest(r Rubric) string {
	b, _ := json.Marshal(r)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// ExpectedDigest binds a domain verdict to the exact independently frozen gold.
func ExpectedDigest(expected Expected) string {
	b, _ := json.Marshal(expected)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (in JudgeInput) Validate() error {
	return in.validate(false)
}

func (in JudgeInput) ValidateHuman() error { return in.validate(true) }

func (in JudgeInput) validate(human bool) error {
	if in.Version != "agent-eval-judge-input/v1" || !reviewIDPattern.MatchString(in.SourceRunID) || !digestPattern.MatchString(in.SourceOutputHash) || in.Rubric.Version != RubricVersion || !reviewIDPattern.MatchString(in.Rubric.ID) || in.RubricHash != RubricDigest(in.Rubric) || len(in.Rubric.Criteria) < 1 || len(in.Rubric.Criteria) > 16 || len(in.Evidence) < 1 || len(in.Evidence) > 64 {
		return errors.New("invalid frozen evaluation rubric or source binding")
	}
	for id, criterion := range in.Rubric.Criteria {
		if (!ModelReviewable(id) && !(human && HumanReviewable(id))) || len(criterion) < 4 || len(criterion) > 4096 {
			return errors.New("unsupported model metric or rubric size")
		}
	}
	for id, value := range in.Evidence {
		if !reviewIDPattern.MatchString(id) || len(value) == 0 || len(value) > 48<<10 || !json.Valid(value) {
			return errors.New("invalid bounded evidence")
		}
	}
	if _, domainRequested := in.Rubric.Criteria["domain_correctness"]; domainRequested {
		var expected Expected
		if json.Unmarshal(in.Evidence["expected"], &expected) != nil || len(expected.DomainFacts) == 0 || len(expected.DomainFacts) > 64 || len(expected.GoldReferences) == 0 || len(expected.GoldReferences) > 64 {
			return errors.New("domain review requires frozen facts and independent source evidence")
		}
		for _, fact := range expected.DomainFacts {
			if len(fact) < 4 || len(fact) > 4096 {
				return errors.New("invalid bounded domain fact")
			}
		}
		seen := map[string]bool{}
		for _, ref := range expected.GoldReferences {
			if ref.ID == "" || len(ref.ID) > 1024 || seen[ref.ID] || ref.Revision == "" || len(ref.Revision) > 128 || ref.Source == "" || len(ref.Source) > 512 || len(ref.Content) == 0 || len(ref.Content) > 32<<10 {
				return errors.New("invalid frozen domain reference")
			}
			seen[ref.ID] = true
		}
	}
	b, _ := json.Marshal(in)
	if len(b) > 64<<10 {
		return errors.New("review input exceeds limit")
	}
	return nil
}

func ValidateVerdicts(in JudgeInput, verdicts []Verdict) error {
	if len(verdicts) != len(in.Rubric.Criteria) {
		return errors.New("model omitted or added rubric metrics")
	}
	seen := map[string]bool{}
	for _, v := range verdicts {
		if _, ok := in.Rubric.Criteria[v.MetricID]; !ok || seen[v.MetricID] || len(v.Reason) > 2048 || len(v.Reason) < 4 || len(v.Evidence) > 64 {
			return errors.New("invalid model verdict")
		}
		seen[v.MetricID] = true
		if v.Value != nil && len(v.Evidence) == 0 {
			return errors.New("measured model verdict requires evidence")
		}
		if v.MetricID == "domain_correctness" && v.Value != nil {
			output, gold := false, false
			for _, id := range v.Evidence {
				output = output || id == "output"
				gold = gold || id == "expected"
			}
			if !output || !gold {
				return errors.New("domain verdict must cite actual output and frozen expected facts")
			}
		}
		for _, id := range v.Evidence {
			if _, ok := in.Evidence[id]; !ok {
				return errors.New("model invented evidence reference")
			}
		}
	}
	return nil
}

func validBoundJudgement(t Trial, j Judgement) bool {
	if j.Version != JudgementVersion || j.SourceRunID != t.Trajectory.RunID || j.SourceOutputHash != t.Trajectory.OutputHash || !digestPattern.MatchString(j.SourceOutputHash) || j.Rubric.Version != RubricVersion || j.RubricHash != RubricDigest(j.Rubric) || len(j.Verdicts) != len(j.Rubric.Criteria) || len(j.Verdicts) == 0 {
		return false
	}
	if j.Source == "model" {
		if j.JudgeRunID == "" || j.JudgeVersionID == "" {
			return false
		}
	} else if j.Source == "human" {
		if j.ReviewerID == "" || j.ReviewEvidenceID == "" {
			return false
		}
	} else {
		return false
	}
	if _, domain := j.Rubric.Criteria["domain_correctness"]; domain {
		if j.ExpectedHash != ExpectedDigest(t.Expected) || len(t.Expected.DomainFacts) == 0 || len(t.Expected.GoldReferences) == 0 {
			return false
		}
	}
	seen := map[string]bool{}
	for _, v := range j.Verdicts {
		if seen[v.MetricID] || (v.Value != nil && len(v.Evidence) == 0) {
			return false
		}
		if _, ok := j.Rubric.Criteria[v.MetricID]; !ok {
			return false
		}
		if !ModelReviewable(v.MetricID) && !(j.Source == "human" && HumanReviewable(v.MetricID)) {
			return false
		}
		seen[v.MetricID] = true
	}
	return true
}
