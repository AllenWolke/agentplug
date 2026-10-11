package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/agent-eval/internal/client"
	agenteval "github.com/lexagent/agent-evaluation"
)

type State struct {
	Version       string            `json:"version"`
	BatchID       string            `json:"batch_id"`
	ConfigHash    string            `json:"config_hash"`
	SelectionHash string            `json:"selection_hash"`
	Runs          map[string]string `json:"runs"`
}

func Run(ctx context.Context, c *client.Client, cfg Config, batchID, dir string, selected []string, writers ...io.Writer) error {
	var progressMu sync.Mutex
	progress := func(format string, args ...any) {
		if len(writers) == 0 || writers[0] == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		fmt.Fprintf(writers[0], format+"\n", args...)
	}
	if !safeID.MatchString(batchID) {
		return errors.New("--id must be a stable evaluation batch identifier")
	}
	if cfg.Workspace != nil {
		if e := c.Switch(ctx, *cfg.Workspace); e != nil {
			return e
		}
	}
	statePath := filepath.Join(dir, artifactID(batchID)+".state.json")
	var prior State
	resumeOnly := false
	if _, e := os.Stat(statePath); e == nil {
		if e = readJSON(statePath, &prior); e != nil {
			return e
		}
		if prior.Version != "agent-eval-state/v1" || prior.BatchID != batchID || prior.ConfigHash != checksum(cfg) || prior.Runs == nil {
			return errors.New("batch id already bound to another immutable configuration")
		}
		resumeOnly = true
		for _, t := range cfg.Targets {
			if len(selected) > 0 && !stringIn(selected, t.InstallationID) {
				continue
			}
			for attempt := 1; attempt <= cfg.Repeat; attempt++ {
				key := "eval-" + checksum([]any{batchID, prior.ConfigHash, t.InstallationID, attempt})[:48]
				if prior.Runs[key] == "" {
					resumeOnly = false
				}
			}
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	var found agenteval.Discovery
	var e error
	if !resumeOnly {
		found, e = c.Discover(ctx)
		if e != nil {
			return e
		}
	}
	available := map[string]agenteval.Agent{}
	for _, a := range found.Items {
		available[a.InstallationID] = a
	}
	targets := []Target{}
	for _, t := range cfg.Targets {
		if len(selected) > 0 && !stringIn(selected, t.InstallationID) {
			continue
		}
		a, ok := available[t.InstallationID]
		if !resumeOnly && (!ok || !a.CanEvaluate || a.Health != "online" || a.VersionID != t.VersionID || a.Revision != t.Revision || a.AgentID != t.AgentID) {
			return errors.New("AGENT_CHANGED_OR_FORBIDDEN: rediscover and prepare the exact installed version")
		}
		if t.SuiteID == "" {
			return errors.New("published suite missing: run prepare, reviewer review/publish, then bind")
		}
		suite, err := c.GetResource(ctx, "suites", t.SuiteID)
		if err != nil {
			return err
		}
		var d struct {
			InstallationID       string `json:"installation_id"`
			InstallationRevision uint64 `json:"installation_revision"`
			AgentID              string `json:"agent_id"`
			VersionID            string `json:"agent_version_id"`
			DatasetID            string `json:"dataset_id"`
		}
		if json.Unmarshal(suite.Data, &d) != nil || suite.Status != "published" || d.AgentID != t.AgentID || d.VersionID != t.VersionID || d.InstallationID != t.InstallationID || d.InstallationRevision != t.Revision {
			return errors.New("published suite target mismatch")
		}
		dataset, err := c.GetResource(ctx, "datasets", d.DatasetID)
		if err != nil {
			return err
		}
		var gold struct {
			Cases []Case `json:"cases"`
		}
		if json.Unmarshal(dataset.Data, &gold) != nil || checksum(gold.Cases) != checksum(t.Cases) {
			return errors.New("local cases differ from frozen reviewed dataset")
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return errors.New("no selected configured agents")
	}
	for _, id := range selected {
		configured := false
		for _, target := range targets {
			if target.InstallationID == id {
				configured = true
				break
			}
		}
		if !configured {
			return errors.New("selected installation has no frozen evaluation configuration")
		}
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	selection := []string{}
	for _, target := range targets {
		selection = append(selection, target.InstallationID)
	}
	state := State{Version: "agent-eval-state/v1", BatchID: batchID, ConfigHash: checksum(cfg), SelectionHash: checksum(selection), Runs: map[string]string{}}
	if _, e = os.Stat(statePath); e == nil {
		if e = readJSON(statePath, &state); e != nil {
			return e
		}
		if state.Version != "agent-eval-state/v1" || state.ConfigHash != checksum(cfg) || state.BatchID != batchID || state.SelectionHash != checksum(selection) || state.Runs == nil {
			return errors.New("batch id already bound to another immutable configuration")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	var caseTrials int64
	for _, target := range targets {
		caseTrials += int64(len(target.Cases)) * int64(cfg.Repeat)
	}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	errs := make(chan error, len(targets))
	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			reportName := artifactID(batchID + "-" + target.InstallationID)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
			defer func() { <-sem }()
			trials := []agenteval.Trial{}
			for attempt := 1; attempt <= cfg.Repeat; attempt++ {
				key := "eval-" + checksum([]any{batchID, state.ConfigHash, target.InstallationID, attempt})[:48]
				var run client.Resource
				limits := Budget{LimitTokens: (cfg.Budget.LimitTokens / caseTrials) * int64(len(target.Cases)), LimitMicros: (cfg.Budget.LimitMicros / caseTrials) * int64(len(target.Cases))}
				mu.Lock()
				id := state.Runs[key]
				mu.Unlock()
				if id == "" {
					e := c.Do(ctx, "POST", "/api/modules/evaluation-product/runs", map[string]any{"suite_id": target.SuiteID, "idempotency_key": key, "limits": limits, "mode": cfg.Mode, "simulation_profile": cfg.SimulationProfile}, &run)
					if e != nil {
						errs <- e
						return
					}
					if !safeID.MatchString(run.ID) || run.Status == "" || run.Revision == 0 {
						errs <- errors.New("invalid evaluation acknowledgement; preserve the same --id and inspect the existing platform Run")
						return
					}
					mu.Lock()
					state.Runs[key] = run.ID
					e = writeJSON(statePath, state)
					mu.Unlock()
					if e != nil {
						errs <- e
						return
					}
				} else {
					var e error
					run, e = c.GetResource(ctx, "runs", id)
					if e != nil {
						errs <- e
						return
					}
				}
				progress("实例 %s；试验 %d/%d；评估Run=%s；状态=%s", target.InstallationID, attempt, cfg.Repeat, run.ID, run.Status)
				for run.Status == "queued" || run.Status == "running" || run.Status == "cancelling" {
					select {
					case <-ctx.Done():
						errs <- fmt.Errorf("evaluation stopped waiting; persisted Run %s is preserved, use cancel or rerun the same --id", run.ID)
						return
					case <-time.After(time.Second):
					}
					var e error
					run, e = c.GetResource(ctx, "runs", run.ID)
					if e != nil {
						errs <- e
						return
					}
				}
				for i, test := range target.Cases {
					id := executionID(run.ID, i)
					trajectory, e := c.Trajectory(ctx, id)
					if e != nil {
						trials = append(trials, agenteval.Trial{CaseID: test.CaseID, Attempt: attempt, Expected: test.Expected, Trajectory: agenteval.Trajectory{Version: agenteval.TrajectoryVersion, Source: "platform", RunID: id, Agent: agenteval.Agent{AgentID: target.AgentID, InstallationID: target.InstallationID, VersionID: target.VersionID}, Missing: []string{"trajectory_unavailable"}}})
						continue
					}
					trials = append(trials, agenteval.Trial{CaseID: test.CaseID, Attempt: attempt, Trajectory: trajectory, Expected: test.Expected})
				}
				if run.Status != "succeeded" {
					report := scoreReport(trials, target, cfg)
					_ = writeJSON(filepath.Join(dir, reportName+".trials.private.json"), trials)
					_ = saveReport(dir, reportName, report)
					errs <- fmt.Errorf("evaluation Run %s ended %s; no failed Run was replayed", run.ID, run.Status)
					return
				}
			}
			report := scoreReport(trials, target, cfg)
			if e := writeJSON(filepath.Join(dir, reportName+".trials.private.json"), trials); e != nil {
				errs <- e
				return
			}
			if e := saveReport(dir, reportName, report); e != nil {
				errs <- e
			} else {
				progress("实例 %s评估完成；样本=%d；安全=%s；业务与安全=%s；报告=%s", target.InstallationID, report.Trials, report.SafetyGate, report.QualityGate, filepath.Join(dir, reportName+".md"))
			}
		}()
	}
	wg.Wait()
	close(errs)
	var failures []error
	for e := range errs {
		failures = append(failures, e)
	}
	return errors.Join(failures...)
}

func scoreReport(trials []agenteval.Trial, target Target, cfg Config) agenteval.Report {
	r := agenteval.Score(trials)
	if cfg.Mode == "simulation" {
		r.Source = "simulation"
		if r.SafetyGate == "PASS" {
			r.SafetyGate = "UNKNOWN"
		}
		if r.QualityGate == "PASS" {
			r.QualityGate = "UNKNOWN"
		}
		r.Warnings = append(r.Warnings, "隔离仿真结果仅证明对应测试场景，不代替真实业务环境或发布资格")
	}
	r.Cohort = &agenteval.Cohort{AgentID: target.AgentID, DatasetHash: checksum(target.Cases), Mode: cfg.Mode, Repeat: cfg.Repeat, Concurrency: cfg.Concurrency, ScorerVersion: "agent-eval-rules/v1", SimulationProfile: cfg.SimulationProfile}
	r.Cohort.LimitTokens, r.Cohort.LimitMicros, r.Cohort.TimeoutSeconds = cfg.Budget.LimitTokens, cfg.Budget.LimitMicros, cfg.TimeoutSeconds
	r.Cohort.ThresholdHash = checksum(cfg.Thresholds)
	agenteval.ApplyThresholds(&r, cfg.Thresholds)
	for _, trial := range trials {
		currency := trial.Trajectory.Measurements.Currency
		if currency == "" {
			r.Cohort.Currency = ""
			break
		}
		if r.Cohort.Currency != "" && r.Cohort.Currency != currency {
			r.Cohort.Currency = "mixed"
			break
		}
		r.Cohort.Currency = currency
	}
	return r
}

func executionID(id string, index int) string {
	return "evalrun-" + checksum([]any{"evaluation-case", id, index})
}
func writeJSON(path string, value any) error {
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, append(raw, '\n'), 0600); e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		_ = os.Remove(tmp)
		return e
	}
	return nil
}
func saveReport(dir, name string, r agenteval.Report) error {
	name = artifactID(name)
	if e := writeJSON(filepath.Join(dir, name+".json"), r); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, name+".md"), []byte(agenteval.Markdown(r)), 0600)
}

// IDs are legal API identifiers but can contain ':' (an NTFS stream marker)
// or reserved Windows device names. Output names must be portable filenames.
func artifactID(id string) string {
	base := strings.ToUpper(strings.SplitN(id, ".", 2)[0])
	reserved := base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9')
	if strings.ContainsAny(id, ":/\\") || strings.HasSuffix(id, ".") || reserved || !safeID.MatchString(id) {
		return "id-" + checksum(id)[:40]
	}
	return id
}
func stringIn(items []string, id string) bool {
	for _, s := range items {
		if s == id {
			return true
		}
	}
	return false
}
