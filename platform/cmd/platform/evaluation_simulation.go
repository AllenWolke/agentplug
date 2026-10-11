package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type evaluationSimulationProfile struct {
	ID                   string                  `json:"id"`
	Scope                evaluationproduct.Scope `json:"scope"`
	Purpose              string                  `json:"purpose"`
	AgentID              string                  `json:"agent_id"`
	VersionID            string                  `json:"agent_version_id"`
	InstallationID       string                  `json:"installation_id"`
	InstallationRevision uint64                  `json:"installation_revision"`
	PolicyHash           string                  `json:"policy_hash"`
	BindingsFileHash     string                  `json:"bindings_file_hash"`
	ToolNames            []string                `json:"tool_names"`
}
type evaluationSimulationAdmission struct {
	profiles     map[string]evaluationSimulationProfile
	bindings     []capability.APIBinding
	bindingsHash string
	catalog      *catalog.Module
	policies     policyasset.Resolver
}

var evaluationSimulationID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func evaluationRunnerOptions() (evaluationproduct.RunnerOptions, error) {
	options := evaluationproduct.RunnerOptions{CaseTimeout: 45 * time.Second, LeaseDuration: 2 * time.Minute}
	if raw := os.Getenv("PLATFORM_EVALUATION_CASE_TIMEOUT"); raw != "" {
		d, e := time.ParseDuration(raw)
		if e != nil || d < time.Second || d > 10*time.Minute {
			return options, errors.New("invalid evaluation case timeout")
		}
		options.CaseTimeout = d
		if d*2 >= options.LeaseDuration {
			options.LeaseDuration = d*2 + 30*time.Second
		}
	}
	if raw := os.Getenv("PLATFORM_EVALUATION_LEASE_DURATION"); raw != "" {
		d, e := time.ParseDuration(raw)
		if e != nil || d < 10*time.Second || d > 30*time.Minute || options.CaseTimeout*2 >= d {
			return options, errors.New("invalid evaluation lease duration")
		}
		options.LeaseDuration = d
	}
	return options, nil
}

func loadEvaluationSimulationProfiles(file, bindingsFile string, module *catalog.Module, policies policyasset.Resolver) (*evaluationSimulationAdmission, error) {
	p := &evaluationSimulationAdmission{profiles: map[string]evaluationSimulationProfile{}, catalog: module, policies: policies}
	if file == "" {
		return p, nil
	}
	read := func(path string, out any) ([]byte, error) {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if e != nil || len(b) > 1<<20 {
			return nil, errors.New("evaluation simulation configuration too large")
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
			return nil, errors.New("invalid evaluation simulation configuration")
		}
		return b, nil
	}
	var profiles []evaluationSimulationProfile
	if _, e := read(file, &profiles); e != nil {
		return nil, e
	}
	b, e := read(bindingsFile, &p.bindings)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(b)
	p.bindingsHash = hex.EncodeToString(digest[:])
	if len(profiles) < 1 || len(profiles) > 100 {
		return nil, errors.New("simulation profiles require 1 to 100 entries")
	}
	for _, profile := range profiles {
		if profile.ID == "" || profile.Purpose != "evaluation_test" || profile.Scope.TenantID == "" || profile.Scope.DepartmentID == "" || profile.Scope.ApplicationID == "" || profile.AgentID == "" || profile.VersionID == "" || profile.InstallationID == "" || profile.InstallationRevision == 0 || len(profile.PolicyHash) != 64 || profile.BindingsFileHash != p.bindingsHash || len(profile.ToolNames) == 0 || len(profile.ToolNames) > 32 || p.profiles[profile.ID].ID != "" {
			return nil, errors.New("simulation profile must pin isolated scope, installation, policy and provider configuration")
		}
		for _, id := range []string{profile.ID, profile.Scope.TenantID, profile.Scope.DepartmentID, profile.Scope.ApplicationID, profile.AgentID, profile.VersionID, profile.InstallationID} {
			if !evaluationSimulationID.MatchString(id) {
				return nil, errors.New("invalid simulation identifier")
			}
		}
		if _, e := hex.DecodeString(profile.PolicyHash); e != nil {
			return nil, errors.New("invalid simulation policy digest")
		}
		seenTools := map[string]bool{}
		for _, name := range profile.ToolNames {
			if !evaluationSimulationID.MatchString(name) || seenTools[name] {
				return nil, errors.New("invalid simulation Tool list")
			}
			seenTools[name] = true
		}
		p.profiles[profile.ID] = profile
	}
	return p, nil
}

func (p *evaluationSimulationAdmission) AuthorizeEvaluationMode(ctx context.Context, a evaluationproduct.Actor, run evaluationproduct.RunData, suite evaluationproduct.SuiteData) error {
	if run.Mode != "simulation" {
		return nil
	}
	if p == nil || p.catalog == nil || p.policies == nil {
		return evaluationproduct.ErrUnavailable
	}
	profile, ok := p.profiles[run.SimulationProfile]
	if !ok {
		return evaluationproduct.ErrUnavailable
	}
	if a.Scope != profile.Scope || a.PrincipalType != "user" || a.PrincipalID == "" || suite.AgentID != profile.AgentID || suite.AgentVersionID != profile.VersionID || suite.InstallationID != profile.InstallationID || suite.InstallationRevision != profile.InstallationRevision {
		return evaluationproduct.ErrForbidden
	}
	scope := sharedkernel.Scope{TenantID: a.Scope.TenantID, DepartmentID: a.Scope.DepartmentID, ApplicationID: a.Scope.ApplicationID, PrincipalType: a.PrincipalType, PrincipalID: a.PrincipalID, AgentID: suite.AgentID, AgentVersionID: suite.AgentVersionID, InstallationID: suite.InstallationID, AgentInstanceID: suite.InstallationID}
	target, e := p.catalog.ResolveEvaluationAgentTarget(ctx, scope, suite.AgentID, suite.AgentVersionID)
	if e != nil || target.Revision != profile.InstallationRevision {
		return evaluationproduct.ErrForbidden
	}
	fixture, e := p.catalog.EvaluationFixtureDeclaration(ctx, suite.AgentVersionID)
	if e != nil {
		return evaluationproduct.ErrUnavailable
	}
	if !fixture {
		return evaluationproduct.ErrForbidden
	}
	policy, e := p.policies.Resolve(ctx, scope, suite.AgentVersionID)
	if e != nil || policy.Hash != profile.PolicyHash {
		return evaluationproduct.ErrForbidden
	}
	if len(policy.Tool.AllowedTools) != len(profile.ToolNames) {
		return evaluationproduct.ErrForbidden
	}
	for _, name := range policy.Tool.AllowedTools {
		allowed := false
		for _, n := range profile.ToolNames {
			if n == name {
				allowed = true
			}
		}
		if !allowed {
			return evaluationproduct.ErrForbidden
		}
		bound := false
		for _, b := range p.bindings {
			if b.ToolName != name || b.TenantID != scope.TenantID || b.ApplicationID != scope.ApplicationID || b.Purpose != "evaluation_fixture" || !b.ReadOnly || b.SecretRef != "" {
				continue
			}
			for _, agent := range b.AgentIDs {
				if agent == scope.AgentID {
					bound = true
				}
			}
		}
		if !bound || p.bindingsHash != profile.BindingsFileHash {
			return evaluationproduct.ErrForbidden
		}
	}
	return nil
}
