package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/evaluationproduct"
)

func TestSimulationRequiresOperatorConfigurationAndValidPins(t *testing.T) {
	p, e := loadEvaluationSimulationProfiles("", "", nil, nil)
	if e != nil || p.AuthorizeEvaluationMode(context.Background(), evaluationproduct.Actor{}, evaluationproduct.RunData{Mode: "simulation"}, evaluationproduct.SuiteData{}) != evaluationproduct.ErrUnavailable {
		t.Fatal("unconfigured simulation admitted")
	}
	dir := t.TempDir()
	bindingFile := filepath.Join(dir, "bindings.json")
	b := []byte(`[]`)
	if os.WriteFile(bindingFile, b, 0600) != nil {
		t.Fatal("fixture write")
	}
	hash := sha256.Sum256(b)
	base := evaluationSimulationProfile{ID: "test", Purpose: "evaluation_test", Scope: evaluationproduct.Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "isolated-test-app"}, AgentID: "fixture", VersionID: "v1", InstallationID: "installation", InstallationRevision: 1, PolicyHash: strings.Repeat("a", 64), BindingsFileHash: hex.EncodeToString(hash[:]), ToolNames: []string{"api.eval_fixture"}}
	for _, mode := range []string{"valid", "changed-binding", "bad-policy", "duplicate-tool", "bad-scope"} {
		t.Run(mode, func(t *testing.T) {
			profile := base
			switch mode {
			case "changed-binding":
				profile.BindingsFileHash = strings.Repeat("b", 64)
			case "bad-policy":
				profile.PolicyHash = strings.Repeat("g", 64)
			case "duplicate-tool":
				profile.ToolNames = []string{"api.eval_fixture", "api.eval_fixture"}
			case "bad-scope":
				profile.Scope.ApplicationID = "../../production"
			}
			file := filepath.Join(dir, "profile.json")
			raw, _ := json.Marshal([]evaluationSimulationProfile{profile})
			if os.WriteFile(file, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			_, e := loadEvaluationSimulationProfiles(file, bindingFile, nil, nil)
			if (e != nil) != (mode != "valid") {
				t.Fatal("invalid isolation pin validation", e)
			}
		})
	}
}
func TestEvaluationTimeoutConfigurationIsBoundedAndLeaseSafe(t *testing.T) {
	t.Setenv("PLATFORM_EVALUATION_CASE_TIMEOUT", "180s")
	t.Setenv("PLATFORM_EVALUATION_LEASE_DURATION", "")
	p, e := evaluationRunnerOptions()
	if e != nil || p.CaseTimeout*2 >= p.LeaseDuration {
		t.Fatal("case can outlive its lease", e)
	}
	for _, value := range []string{"invalid", "0s", "1h"} {
		t.Setenv("PLATFORM_EVALUATION_CASE_TIMEOUT", value)
		if _, e := evaluationRunnerOptions(); e == nil {
			t.Fatal("invalid timeout accepted")
		}
	}
	t.Setenv("PLATFORM_EVALUATION_CASE_TIMEOUT", "180s")
	t.Setenv("PLATFORM_EVALUATION_LEASE_DURATION", "180s")
	if _, e := evaluationRunnerOptions(); e == nil {
		t.Fatal("unsafe lease accepted")
	}
}
