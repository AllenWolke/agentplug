package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/lexagent/agent-eval/internal/client"
	agenteval "github.com/lexagent/agent-evaluation"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var caseID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Budget struct {
	LimitTokens int64 `json:"limit_tokens"`
	LimitMicros int64 `json:"limit_micros"`
}
type Case struct {
	CaseID   string             `json:"case_id"`
	Input    map[string]any     `json:"input"`
	Expected agenteval.Expected `json:"expected"`
}
type Target struct {
	InstallationID string `json:"installation_id"`
	AgentID        string `json:"agent_id"`
	VersionID      string `json:"version_id"`
	Revision       uint64 `json:"revision"`
	SuiteID        string `json:"suite_id,omitempty"`
	DatasetID      string `json:"dataset_id,omitempty"`
	MetricID       string `json:"metric_id,omitempty"`
	Cases          []Case `json:"cases"`
}
type Config struct {
	Version           string                `json:"version"`
	Mode              string                `json:"mode"`
	Workspace         *client.Workspace     `json:"workspace,omitempty"`
	Repeat            int                   `json:"repeat"`
	Concurrency       int                   `json:"concurrency"`
	Budget            Budget                `json:"budget"`
	Targets           []Target              `json:"targets"`
	SimulationProfile string                `json:"simulation_profile,omitempty"`
	TimeoutSeconds    int                   `json:"timeout_seconds,omitempty"`
	DatasetSource     string                `json:"dataset_source,omitempty"`
	Thresholds        []agenteval.Threshold `json:"thresholds,omitempty"`
}

func readJSON(path string, out any) error {
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, (4<<20)+1))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid configuration, unknown fields, trailing data or size limit exceeded")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if e := readJSON(path, &cfg); e != nil {
		return cfg, e
	}
	if cfg.Repeat == 0 {
		cfg.Repeat = 3
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 1
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 1800
	}
	if cfg.Version != "agent-eval-suite/v1" || (cfg.Mode != "offline" && cfg.Mode != "simulation") || cfg.Repeat < 1 || cfg.Repeat > 100 || cfg.Concurrency < 1 || cfg.Concurrency > 16 || cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 86400 || cfg.Budget.LimitTokens <= 0 || cfg.Budget.LimitMicros < 0 || len(cfg.Targets) == 0 || len(cfg.Targets) > 100 {
		return cfg, errors.New("invalid suite mode, budget, targets or limits")
	}
	seen := map[string]bool{}
	if err := agenteval.ValidateThresholds(cfg.Thresholds); err != nil {
		return cfg, err
	}
	if cfg.DatasetSource != "" && cfg.DatasetSource != "manual_gold" && cfg.DatasetSource != "imported_redacted" && cfg.DatasetSource != "synthetic_generated" {
		return cfg, errors.New("invalid dataset source")
	}
	if cfg.Mode == "simulation" && (cfg.Workspace == nil || !safeID.MatchString(cfg.SimulationProfile)) {
		return cfg, errors.New("simulation requires an explicit test workspace and operator-approved profile")
	}
	if cfg.Mode == "offline" && cfg.SimulationProfile != "" {
		return cfg, errors.New("offline mode cannot supply a simulation profile")
	}
	var totalCases int64
	for _, target := range cfg.Targets {
		if !safeID.MatchString(target.InstallationID) || !safeID.MatchString(target.AgentID) || !safeID.MatchString(target.VersionID) || target.Revision == 0 || len(target.Cases) == 0 || len(target.Cases) > 10000 || seen[target.InstallationID] {
			return cfg, errors.New("targets require unique frozen installation/version/revision and cases")
		}
		seen[target.InstallationID] = true
		totalCases += int64(len(target.Cases)) * int64(cfg.Repeat)
		ids := map[string]bool{}
		for _, c := range target.Cases {
			if !caseID.MatchString(c.CaseID) || ids[c.CaseID] || c.Input == nil {
				return cfg, errors.New("invalid or duplicate case")
			}
			ids[c.CaseID] = true
			if _, forged := c.Input["policy_snapshot"]; forged {
				return cfg, errors.New("case input cannot supply platform policy_snapshot")
			}
			if len(c.Expected.ReviewedChecks) > 0 {
				return cfg, errors.New("reviewed_checks are Run outcomes, not static gold; provide evidence-backed review instead")
			}
			for _, assertion := range c.Expected.Assertions {
				switch assertion.Op {
				case "equals", "exists", "contains", "gte", "lte":
				default:
					return cfg, errors.New("unsupported business assertion operator")
				}
			}
			if raw, e := json.Marshal(c); e != nil || len(raw) > 64<<10 {
				return cfg, errors.New("case exceeds platform 64KiB limit")
			}
		}
	}
	if cfg.Budget.LimitTokens < totalCases {
		return cfg, errors.New("token budget must allocate at least one token to each planned case trial")
	}
	return cfg, nil
}
func checksum(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
