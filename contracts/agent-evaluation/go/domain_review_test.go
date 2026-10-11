package agenteval

import (
	"encoding/json"
	"testing"
)

func domainInput() JudgeInput {
	in := reviewInput()
	in.Rubric.Criteria = map[string]string{"domain_correctness": "Compare every material answer claim against frozen source facts; polarity, conditions and revision must remain correct. Return null if evidence is insufficient."}
	in.RubricHash = RubricDigest(in.Rubric)
	expected := Expected{DomainFacts: []string{"Only completed and authorized indexes may become active."}, GoldReferences: []GoldReference{{ID: "gold-1", Revision: "1", Source: "reviewed teaching source", Content: "Only completed and authorized indexes may become active."}}}
	in.Evidence["expected"], _ = json.Marshal(expected)
	return in
}
func TestDomainReviewRequiresIndependentFrozenGold(t *testing.T) {
	in := domainInput()
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "empty facts", "empty references", "missing revision", "duplicate references"} {
		t.Run(name, func(t *testing.T) {
			bad := domainInput()
			var e Expected
			_ = json.Unmarshal(bad.Evidence["expected"], &e)
			switch name {
			case "missing":
				delete(bad.Evidence, "expected")
			case "empty facts":
				e.DomainFacts = nil
			case "empty references":
				e.GoldReferences = nil
			case "missing revision":
				e.GoldReferences[0].Revision = ""
			case "duplicate references":
				e.GoldReferences = append(e.GoldReferences, e.GoldReferences[0])
			}
			if name != "missing" {
				bad.Evidence["expected"], _ = json.Marshal(e)
			}
			if bad.Validate() == nil {
				t.Fatal("missing independent domain evidence accepted")
			}
		})
	}
}
func TestDomainVerdictMustReferenceOutputAndExpected(t *testing.T) {
	in := domainInput()
	yes := true
	for _, ids := range [][]string{{"output"}, {"expected"}, {"invented"}, {"output", "expected"}} {
		err := ValidateVerdicts(in, []Verdict{{MetricID: "domain_correctness", Value: &yes, Evidence: ids, Reason: "Compared complete claims, conditions and negation against frozen gold."}})
		want := len(ids) == 2
		if (err == nil) != want {
			t.Fatalf("evidence=%v err=%v", ids, err)
		}
	}
	if err := ValidateVerdicts(in, []Verdict{{MetricID: "domain_correctness", Value: nil, Reason: "Evidence is insufficient."}}); err != nil {
		t.Fatal(err)
	}
}
func TestDomainScoreNeverInfersPassFromExecutionOrCitation(t *testing.T) {
	v := trial()
	v.Trajectory.OutputHash = reviewInput().SourceOutputHash
	if metric(t, Score([]Trial{v}), "domain_correctness").Status != "missing" {
		t.Fatal("execution manufactured domain correctness")
	}
	in := domainInput()
	_ = json.Unmarshal(in.Evidence["expected"], &v.Expected)
	no := false
	v.Judgements = []Judgement{{Version: JudgementVersion, Source: "model", SourceRunID: v.Trajectory.RunID, SourceOutputHash: v.Trajectory.OutputHash, Rubric: in.Rubric, RubricHash: in.RubricHash, ExpectedHash: ExpectedDigest(v.Expected), JudgeRunID: "domain-judge", JudgeVersionID: "domain-judge-v1", Verdicts: []Verdict{{MetricID: "domain_correctness", Value: &no, Evidence: []string{"output", "expected"}, Reason: "The answer reverses the index publication condition."}}}}
	report := Score([]Trial{v})
	if report.QualityGate != "FAIL" {
		t.Fatal("negative independent domain verdict did not block quality")
	}
	scored := metric(t, report, "domain_correctness")
	if scored.Value == nil || *scored.Value != 0 {
		t.Fatal("negative domain verdict lost")
	}
	v.Judgements[0].Verdicts[0].Value = nil
	if metric(t, Score([]Trial{v}), "domain_correctness").Status != "missing" {
		t.Fatal("unknown verdict became pass or zero")
	}
}

func TestDomainJudgementCannotBeReusedWithDifferentGold(t *testing.T) {
	v := trial()
	v.Trajectory.OutputHash = reviewInput().SourceOutputHash
	in := domainInput()
	_ = json.Unmarshal(in.Evidence["expected"], &v.Expected)
	yes := true
	v.Judgements = []Judgement{{Version: JudgementVersion, Source: "model", SourceRunID: v.Trajectory.RunID, SourceOutputHash: v.Trajectory.OutputHash, Rubric: in.Rubric, RubricHash: in.RubricHash, ExpectedHash: ExpectedDigest(v.Expected), JudgeRunID: "bound-domain-judge", JudgeVersionID: "domain-judge-v1", Verdicts: []Verdict{{MetricID: "domain_correctness", Value: &yes, Evidence: []string{"output", "expected"}, Reason: "The output preserves frozen source conditions"}}}}
	if metric(t, Score([]Trial{v}), "domain_correctness").Status != "measured" {
		t.Fatal("matching gold rejected")
	}
	v.Expected.DomainFacts = []string{"A different and unsupported domain fact"}
	if metric(t, Score([]Trial{v}), "domain_correctness").Status != "missing" {
		t.Fatal("a positive verdict was reused against altered gold")
	}
	v.Judgements[0].ExpectedHash = ""
	if metric(t, Score([]Trial{v}), "domain_correctness").Status != "missing" {
		t.Fatal("unbound domain verdict was accepted")
	}
}
