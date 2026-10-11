package app

import (
	"bytes"
	"encoding/json"
	agenteval "github.com/lexagent/agent-evaluation"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func online(id string) agenteval.Agent {
	return agenteval.Agent{AgentID: "example-go-operations", InstallationID: id, VersionID: "go-version", Revision: 7, Health: "online", CanEvaluate: true}
}
func TestSelectionSingleMultiAllAndDenied(t *testing.T) {
	items := []agenteval.Agent{online("a"), online("b"), {InstallationID: "c", Health: "offline"}}
	for _, test := range []struct {
		value string
		count int
		fails bool
	}{{"1", 1, false}, {"1,2,1", 2, false}, {"all", 2, false}, {"3", 0, true}, {"0", 0, true}, {"bad", 0, true}, {"", 0, true}} {
		got, e := Select(items, test.value)
		if (e != nil) != test.fails || (!test.fails && len(got) != test.count) {
			t.Fatalf("%q got=%v err=%v", test.value, got, e)
		}
	}
}
func TestInitPinsCurrentInstallationAndPreservesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if e := InitConfig([]agenteval.Agent{online("a"), online("b")}, []string{"b"}, dir, &out); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig(filepath.Join(dir, "evaluation.json"))
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Targets) != 1 || c.Targets[0].InstallationID != "b" || c.Targets[0].Revision != 7 || c.Repeat != 3 || c.Concurrency != 1 {
		t.Fatalf("wrong snapshot %+v", c)
	}
	if e := InitConfig([]agenteval.Agent{online("b")}, nil, dir, &out); e == nil {
		t.Fatal("overwrote frozen config")
	}
}
func TestMalformedGoldAndForgedPolicyRejected(t *testing.T) {
	base := Config{Version: "agent-eval-suite/v1", Mode: "offline", Repeat: 3, Concurrency: 1, Budget: Budget{LimitTokens: 100}, Targets: []Target{{InstallationID: "a", AgentID: "agent", VersionID: "v", Revision: 1, Cases: []Case{{CaseID: "case", Input: map[string]any{}, Expected: agenteval.Expected{Assertions: []agenteval.Assertion{{Path: "x", Op: "equals", Value: "y"}}}}}}}}
	for _, mode := range []string{"valid", "static-safety", "forged-policy", "bad-case", "unknown-op"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var cfg Config
			json.Unmarshal(raw, &cfg)
			switch mode {
			case "static-safety":
				cfg.Targets[0].Cases[0].Expected.ReviewedChecks = map[string]bool{"permission_violation": false}
			case "forged-policy":
				cfg.Targets[0].Cases[0].Input["policy_snapshot"] = map[string]any{}
			case "bad-case":
				cfg.Targets[0].Cases[0].CaseID = "case:bad"
			case "unknown-op":
				cfg.Targets[0].Cases[0].Expected.Assertions[0].Op = "magic"
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if e := writeJSON(path, cfg); e != nil {
				t.Fatal(e)
			}
			_, e := LoadConfig(path)
			if (e != nil) != (mode != "valid") {
				t.Fatalf("validation %s=%v", mode, e)
			}
		})
	}
}
func TestCompareRequiresImmutableCohort(t *testing.T) {
	dir := t.TempDir()
	a := agenteval.Report{Version: agenteval.ReportVersion, Cohort: &agenteval.Cohort{AgentID: "agent", DatasetHash: "hash", Mode: "offline", Repeat: 3, Concurrency: 1, ScorerVersion: "rules/v1"}}
	b := a
	b.Cohort = &agenteval.Cohort{AgentID: "agent", DatasetHash: "different", Mode: "offline", Repeat: 3, Concurrency: 1, ScorerVersion: "rules/v1"}
	p, q := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	writeJSON(p, a)
	writeJSON(q, b)
	var out bytes.Buffer
	if e := Compare(p, q, &out); e == nil {
		t.Fatal("compared another dataset")
	}
	b.Cohort = a.Cohort
	writeJSON(q, b)
	if e := Compare(p, q, &out); e != nil {
		t.Fatal(e)
	}
}
func TestAtomicStateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for i := 0; i < 3; i++ {
		if e := writeJSON(path, map[string]any{"revision": i}); e != nil {
			t.Fatal(e)
		}
	}
	var value map[string]any
	if e := readJSON(path, &value); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path + ".tmp"); !os.IsNotExist(e) {
		t.Fatal("temporary state left behind")
	}
}

func TestPortableArtifactIdentifiersDoNotOpenNTFSStreams(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range []string{"batch:stream", "CON", "con.txt", "NUL", "COM1", "LPT9", "batch.", "batch/escape"} {
		name := artifactID(id)
		if name == id || strings.ContainsAny(name, ":/\\") || strings.HasSuffix(name, ".") || seen[name] {
			t.Fatal("unsafe or colliding artifact name", id, name)
		}
		seen[name] = true
	}
	if artifactID("regular-batch") != "regular-batch" {
		t.Fatal("normal portable identifier changed")
	}
}

func TestHistoricalComparePinsWorkloadAndRejectsUncontrolledLatency(t *testing.T) {
	trajectory := agenteval.Trajectory{Source: "platform", RunID: "r", BusinessInputHash: "hash", Agent: agenteval.Agent{AgentID: "agent", VersionID: "v1"}}
	a := agenteval.Report{Version: agenteval.ReportVersion, Cohort: historicalCohort([]agenteval.Trial{{Trajectory: trajectory}}, agenteval.Expected{})}
	trajectory.Agent.VersionID = "v2"
	b := a
	b.Cohort = historicalCohort([]agenteval.Trial{{Trajectory: trajectory}}, agenteval.Expected{})
	value := 10.
	a.Metrics = []agenteval.Metric{{ID: "average_latency", Dimension: "cost_latency", Value: &value, Unit: "ms", Status: "measured"}}
	b.Metrics = a.Metrics
	p, q := filepath.Join(t.TempDir(), "a.json"), filepath.Join(t.TempDir(), "b.json")
	if writeJSON(p, a) != nil || writeJSON(q, b) != nil {
		t.Fatal("fixture write failed")
	}
	var out bytes.Buffer
	if Compare(p, q, &out) != nil || !strings.Contains(out.String(), "受控性能") {
		t.Fatal("historical performance incorrectly compared")
	}
	trajectory.BusinessInputHash = "other-workload"
	b.Cohort = historicalCohort([]agenteval.Trial{{Trajectory: trajectory}}, agenteval.Expected{})
	writeJSON(q, b)
	if Compare(p, q, &out) == nil {
		t.Fatal("different historical workloads compared")
	}
}
