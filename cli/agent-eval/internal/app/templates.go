package app

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/agent-eval/internal/client"
	"io"
	"os"
	"path/filepath"

	agenteval "github.com/lexagent/agent-evaluation"
)

//go:embed templates/*.json
var caseTemplates embed.FS

// InitConfig freezes discovered bindings and writes editable gold. It does not
// publish a Suite or guess the acceptance criteria of an unfamiliar business.
func InitConfig(items []agenteval.Agent, selected []string, dir string, out io.Writer, workspaces ...*client.Workspace) error {
	cfg := Config{Version: "agent-eval-suite/v1", Mode: "offline", Repeat: 3, Concurrency: 1, TimeoutSeconds: 1800, Budget: Budget{LimitTokens: 180000, LimitMicros: 10000000}, Targets: []Target{}}
	if len(workspaces) > 0 {
		cfg.Workspace = workspaces[0]
	}
	matched := map[string]bool{}
	for _, agent := range items {
		if len(selected) > 0 && !stringIn(selected, agent.InstallationID) {
			continue
		}
		if !agent.CanEvaluate || agent.Health != "online" {
			if len(selected) > 0 {
				return errors.New("selected installation is not currently evaluable")
			}
			continue
		}
		target := Target{InstallationID: agent.InstallationID, AgentID: agent.AgentID, VersionID: agent.VersionID, Revision: agent.Revision}
		name := "generic"
		switch agent.AgentID {
		case "example-go-operations":
			name = "go"
		case "example-python-documents":
			name = "python"
		case "example-java-tickets":
			name = "java"
		case "agent-eval-simulation":
			name = "simulation"
		}
		raw, e := caseTemplates.ReadFile("templates/" + name + ".json")
		if e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &target.Cases); e != nil {
			return e
		}
		cfg.Targets = append(cfg.Targets, target)
		matched[agent.InstallationID] = true
	}
	for _, target := range cfg.Targets {
		if target.AgentID == "agent-eval-simulation" {
			if len(cfg.Targets) != 1 {
				return errors.New("simulation fixtures must be evaluated in a separate explicit test workspace")
			}
			cfg.Mode, cfg.DatasetSource, cfg.SimulationProfile = "simulation", "synthetic_generated", "operator-approved-profile-required"
		}
	}
	for _, id := range selected {
		if !matched[id] {
			return errors.New("selected installation was not discovered")
		}
	}
	if len(cfg.Targets) == 0 {
		return errors.New("no evaluable online installations")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(dir, "evaluation.json")
	if _, e := os.Stat(path); e == nil {
		return errors.New("evaluation.json already exists; choose another output directory to preserve the frozen configuration")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := writeJSON(path, cfg); e != nil {
		return e
	}
	fmt.Fprintf(out, "已冻结%d个在线实例；配置：%s\n", len(cfg.Targets), path)
	fmt.Fprintln(out, "示例金标为教学起点。确认业务约束、所需证据和预算后执行 prepare，再由另一位授权审核者 review/publish，最后 bind/run。")
	return nil
}
