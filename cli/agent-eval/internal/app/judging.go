package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lexagent/agent-eval/internal/client"
	agenteval "github.com/lexagent/agent-evaluation"
)

func PrepareModelReview(ctx context.Context, c *client.Client, installation string, runIDs []string, rubric agenteval.Rubric, expected agenteval.Expected, budget Budget, workspace *client.Workspace, dir string, out io.Writer) error {
	found, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	var target Target
	for _, a := range found.Items {
		if a.InstallationID == installation && a.Health == "online" && a.CanEvaluate && a.AgentID == "agent-eval-judge" {
			target = Target{InstallationID: a.InstallationID, AgentID: a.AgentID, VersionID: a.VersionID, Revision: a.Revision}
		}
	}
	if target.InstallationID == "" {
		return errors.New("registered, healthy and authorized agent-eval-judge installation required")
	}
	seen := map[string]bool{}
	for i, id := range runIDs {
		if seen[id] {
			return errors.New("duplicate source Run")
		}
		seen[id] = true
		t, err := c.Trajectory(ctx, id)
		if err != nil {
			return err
		}
		if len(t.Output) == 0 {
			return errors.New("source output unavailable; grading is blocked")
		}
		frozen := agenteval.JudgeInput{Version: "agent-eval-judge-input/v1", SourceRunID: id, SourceOutputHash: t.OutputHash, Rubric: rubric, RubricHash: agenteval.RubricDigest(rubric), Evidence: map[string]json.RawMessage{"output": t.Output}}
		gold, _ := json.Marshal(expected)
		frozen.Evidence["expected"] = gold
		for _, event := range agenteval.ReviewEvidenceEvents(t.Events) {
			// A derived dataset inherits this source Run's permission only.
			// Evaluate child evidence separately with its own source binding.
			if event.RunID != "" && event.RunID != t.RunID {
				continue
			}
			if reference := agenteval.EventReference(t.RunID, event); reference != "" {
				b, _ := json.Marshal(event)
				frozen.Evidence[reference] = b
			}
			if len(frozen.Evidence) == 32 {
				break
			}
		}
		if err := frozen.Validate(); err != nil {
			return err
		}
		b, _ := json.Marshal(frozen)
		var input map[string]any
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber()
		if decoder.Decode(&input) != nil {
			return errors.New("invalid grading input")
		}
		target.Cases = append(target.Cases, Case{CaseID: fmt.Sprintf("judge-%d", i+1), Input: input, Expected: agenteval.Expected{Assertions: []agenteval.Assertion{{Path: "judgement.version", Op: "equals", Value: agenteval.JudgementVersion}, {Path: "judgement.source_run_id", Op: "equals", Value: id}, {Path: "judgement.source_output_hash", Op: "equals", Value: t.OutputHash}}}})
	}
	cfg := Config{Version: "agent-eval-suite/v1", Mode: "offline", Workspace: workspace, Repeat: 1, Concurrency: 1, Budget: budget, TimeoutSeconds: 1800, DatasetSource: "imported_redacted", Targets: []Target{target}}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "grading.json")
	if _, err := os.Stat(path); err == nil {
		return errors.New("grading.json already exists; preserve the frozen review batch")
	}
	if err := writeJSON(path, cfg); err != nil {
		return err
	}
	if _, err := LoadConfig(path); err != nil {
		return err
	}
	fmt.Fprintln(out, "评分配置已冻结："+path+"；使用prepare、另一位审核者review/publish、bind、run执行。模型判定不授予安全或发布资格。")
	return nil
}

func AttachReviews(ctx context.Context, c *client.Client, trials []agenteval.Trial, judgeRuns, feedbackIDs []string) error {
	byID := map[string]int{}
	for i, t := range trials {
		byID[t.Trajectory.RunID] = i
	}
	appendReview := func(j agenteval.Judgement) error {
		i, ok := byID[j.SourceRunID]
		if !ok || j.Version != agenteval.JudgementVersion || j.SourceOutputHash != trials[i].Trajectory.OutputHash || j.RubricHash != agenteval.RubricDigest(j.Rubric) {
			return errors.New("judgement source or frozen rubric mismatch")
		}
		if _, domain := j.Rubric.Criteria["domain_correctness"]; domain && j.ExpectedHash != agenteval.ExpectedDigest(trials[i].Expected) {
			return errors.New("domain judgement does not match the independently frozen expected evidence")
		}
		// Reading the original again makes current revocation authoritative.
		current, err := c.Trajectory(ctx, j.SourceRunID)
		if err != nil {
			return err
		}
		if current.OutputHash != j.SourceOutputHash {
			return errors.New("original Run output changed")
		}
		trials[i].Judgements = append(trials[i].Judgements, j)
		return nil
	}
	seen := map[string]bool{}
	for _, id := range judgeRuns {
		if seen[id] {
			return errors.New("duplicate grading Run")
		}
		seen[id] = true
		t, err := c.Trajectory(ctx, id)
		if err != nil {
			return err
		}
		if t.Status != "succeeded" || t.Agent.AgentID != "agent-eval-judge" {
			return errors.New("grading Run did not succeed under the registered grader")
		}
		var output struct {
			Schema    string              `json:"schema"`
			Judgement agenteval.Judgement `json:"judgement"`
		}
		if json.Unmarshal(t.Output, &output) != nil || output.Schema != "schema://agent-eval-judge/output/v1" || output.Judgement.Source != "model" || output.Judgement.JudgeRunID != id || output.Judgement.JudgeVersionID != t.Agent.VersionID {
			return errors.New("invalid platform grading receipt")
		}
		output.Judgement.Measurements = t.Measurements
		if err := appendReview(output.Judgement); err != nil {
			return err
		}
	}
	for _, id := range feedbackIDs {
		if seen[id] {
			return errors.New("duplicate feedback")
		}
		seen[id] = true
		r, err := c.GetResource(ctx, "feedback", id)
		if err != nil {
			return err
		}
		var j agenteval.Judgement
		if json.Unmarshal(r.Data, &j) != nil || r.Status != "completed" || j.Source != "human" || j.ReviewEvidenceID != id || j.ReviewerID == "" {
			return errors.New("invalid authenticated human feedback")
		}
		if err := appendReview(j); err != nil {
			return err
		}
	}
	return nil
}
