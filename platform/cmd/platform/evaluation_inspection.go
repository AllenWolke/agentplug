package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type evaluationInspection struct {
	catalog   *catalog.Module
	execution *execution.Module
	runs      *execution.SQLStore
	identity  identity.Store
	audit     *audit.SQLStore
	usage     *usagecost.SQLStore
}

func (p evaluationInspection) AuthorizeSources(ctx context.Context, a evaluationproduct.Actor, refs []agenteval.SourceReference) error {
	return p.authorizeSources(ctx, a, refs, 0)
}
func (p evaluationInspection) authorizeSources(ctx context.Context, a evaluationproduct.Actor, refs []agenteval.SourceReference, depth int) error {
	if depth > 8 {
		return evaluationproduct.ErrForbidden
	}
	if p.runs == nil || p.identity == nil || a.PrincipalType != "user" || len(refs) > 10000 {
		return evaluationproduct.ErrUnavailable
	}
	for _, ref := range refs {
		run, err := p.runs.GetContext(ctx, ref.RunID)
		if err != nil {
			return evaluationproduct.ErrForbidden
		}
		if run.Scope.TenantID != a.Scope.TenantID || run.Scope.DepartmentID != a.Scope.DepartmentID || run.Scope.ApplicationID != a.Scope.ApplicationID || authorizeBusinessResource(ctx, p.identity, run.Scope, a.PrincipalID, "history.read") != nil {
			return evaluationproduct.ErrForbidden
		}
		outcome, err := p.runs.GetOutcome(run.ID)
		if err != nil || len(outcome.OutputJSON) > 1<<20 {
			return evaluationproduct.ErrUnavailable
		}
		digest := sha256.Sum256(outcome.OutputJSON)
		if hex.EncodeToString(digest[:]) != ref.OutputHash {
			return evaluationproduct.ErrConflict
		}
		var value any
		d := json.NewDecoder(bytes.NewReader(outcome.OutputJSON))
		d.UseNumber()
		if d.Decode(&value) != nil {
			return evaluationproduct.ErrInvalid
		}
		redacted, _ := json.Marshal(agenteval.Sanitize(value))
		digest = sha256.Sum256(redacted)
		if hex.EncodeToString(digest[:]) != ref.RedactedOutputHash {
			return evaluationproduct.ErrInvalid
		}
		if authorizeBusinessResource(ctx, p.identity, run.Scope, a.PrincipalID, "history.read") != nil {
			return evaluationproduct.ErrForbidden
		}
		if run.Scope.AgentID == "agent-eval-judge" {
			var envelope struct {
				Input map[string]json.RawMessage `json:"input"`
			}
			if json.Unmarshal(run.RequestJSON, &envelope) != nil {
				return evaluationproduct.ErrInvalid
			}
			delete(envelope.Input, "policy_snapshot")
			b, _ := json.Marshal(envelope.Input)
			var frozen agenteval.JudgeInput
			if json.Unmarshal(b, &frozen) != nil {
				return evaluationproduct.ErrInvalid
			}
			parent, e := frozen.SourceReference()
			if e != nil {
				return evaluationproduct.ErrInvalid
			}
			if e = p.authorizeSources(ctx, a, []agenteval.SourceReference{parent}, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}

func inspectionScope(a evaluationproduct.Actor) sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: a.Scope.TenantID, DepartmentID: a.Scope.DepartmentID, ApplicationID: a.Scope.ApplicationID, PrincipalID: a.PrincipalID, PrincipalType: a.PrincipalType}
}

func (p evaluationInspection) Agents(ctx context.Context, a evaluationproduct.Actor, page, size int) (agenteval.Discovery, error) {
	if p.catalog == nil || p.identity == nil {
		return agenteval.Discovery{}, evaluationproduct.ErrUnavailable
	}
	err := (identityEvaluationProductControl{store: p.identity}).AuthorizeEvaluation(ctx, a, evaluationproduct.ActionExecute, a.Scope)
	if err != nil && !errors.Is(err, evaluationproduct.ErrForbidden) {
		return agenteval.Discovery{}, err
	}
	canEvaluate := err == nil
	scope := inspectionScope(a)
	items, err := p.catalog.DiscoverEvaluationAgents(ctx, catalog.ControlActor{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalID: scope.PrincipalID, PrincipalType: scope.PrincipalType}, canEvaluate)
	if errors.Is(err, catalog.ErrCatalogForbidden) {
		return agenteval.Discovery{}, evaluationproduct.ErrForbidden
	}
	if err != nil {
		return agenteval.Discovery{}, err
	}
	result := agenteval.Discovery{Items: []agenteval.Agent{}, Total: len(items), Page: page, PageSize: size}
	online := map[string]bool{}
	for i := range items {
		item := &items[i]
		if item.Health == "online" {
			online[item.AgentID] = true
			result.OnlineInstances++
		}
		if item.CanEvaluate {
			result.Evaluable++
		}
		target := scope
		target.AgentID, target.AgentVersionID, target.InstallationID, target.AgentInstanceID = item.AgentID, item.VersionID, item.InstallationID, item.InstallationID
		decision, e := identity.CheckPrincipalAccess(ctx, p.identity, target, identity.PrincipalUser, a.PrincipalID, "history.read")
		if e != nil {
			return agenteval.Discovery{}, e
		}
		if decision.Allowed && p.runs != nil {
			n, e := p.runs.EvaluationActiveCount(ctx, target)
			if e != nil {
				return agenteval.Discovery{}, e
			}
			item.ActiveRuns = &n
		}
	}
	result.OnlineAgents = len(online)
	start := (page - 1) * size
	if start < len(items) {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		result.Items = items[start:end]
	}
	err = (identityEvaluationProductControl{store: p.identity}).AuthorizeEvaluation(ctx, a, evaluationproduct.ActionExecute, a.Scope)
	if err != nil && !errors.Is(err, evaluationproduct.ErrForbidden) {
		return agenteval.Discovery{}, err
	}
	if err != nil {
		for i := range result.Items {
			result.Items[i].CanEvaluate = false
		}
		result.Evaluable = 0
	}
	return result, nil
}

func (p evaluationInspection) Trajectory(ctx context.Context, a evaluationproduct.Actor, id, session string, revision uint64) (agenteval.Trajectory, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	root, err := p.singleTrajectory(ctx, a, id, session, revision)
	if err != nil {
		return agenteval.Trajectory{}, err
	}
	type pending struct {
		id, parent string
		depth      int
	}
	queue := []pending{}
	for _, child := range root.Children {
		queue = append(queue, pending{child, root.RunID, 1})
	}
	seen := map[string]bool{root.RunID: true}
	all := []agenteval.Trajectory{root}
	descendants := []agenteval.Trajectory{}
	complete := true
	eventCount := len(root.Events)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if seen[item.id] || item.depth > 8 || len(all) >= 200 {
			complete = false
			continue
		}
		seen[item.id] = true
		child, e := p.singleTrajectory(ctx, a, item.id, session, revision)
		if e != nil {
			if errors.Is(e, evaluationproduct.ErrForbidden) || errors.Is(e, evaluationproduct.ErrNotFound) {
				complete = false
				continue
			}
			return agenteval.Trajectory{}, e
		}
		if child.ParentRunID != item.parent {
			complete = false
			continue
		}
		if eventCount+len(child.Events) > 10000 {
			complete = false
			break
		}
		eventCount += len(child.Events)
		descendants = append(descendants, child)
		all = append(all, child)
		for _, grandchild := range child.Children {
			queue = append(queue, pending{grandchild, child.RunID, item.depth + 1})
		}
		if len(queue) > 200 {
			queue = queue[:200]
			complete = false
		}
	}
	for _, t := range all {
		for _, missing := range t.Missing {
			if missing == "child_history_permission" || missing == "children" {
				complete = false
			}
		}
		// Re-authorize every disclosed descendant after all reads; revocation wins.
		run, e := p.runs.GetContext(ctx, t.RunID)
		if e != nil {
			return agenteval.Trajectory{}, inspectionReadError(e)
		}
		actor := execution.BrowserRunActor{Scope: inspectionScope(a), AuthenticationSession: session, AuthenticationRevision: revision}
		if e = (identityExecutionBrowserControl{store: p.identity, runs: p.runs}).Authorize(ctx, run.Scope, actor, "history.read"); e != nil {
			return agenteval.Trajectory{}, inspectionReadError(e)
		}
	}
	return agenteval.AggregateTree(root, descendants, complete), nil
}

func (p evaluationInspection) singleTrajectory(ctx context.Context, a evaluationproduct.Actor, id, session string, revision uint64) (agenteval.Trajectory, error) {
	if p.execution == nil || p.runs == nil || p.identity == nil {
		return agenteval.Trajectory{}, evaluationproduct.ErrUnavailable
	}
	actor := execution.BrowserRunActor{Scope: inspectionScope(a), AuthenticationSession: session, AuthenticationRevision: revision}
	t, err := p.execution.ReadEvaluationTrajectory(ctx, actor, id)
	if err != nil {
		return agenteval.Trajectory{}, inspectionReadError(err)
	}
	run, err := p.runs.GetContext(ctx, id)
	if err != nil {
		return agenteval.Trajectory{}, inspectionReadError(err)
	}
	var envelope struct {
		Input map[string]json.RawMessage `json:"input"`
	}
	if json.Unmarshal(run.RequestJSON, &envelope) == nil {
		var version string
		_ = json.Unmarshal(envelope.Input["version"], &version)
		if version == "agent-eval-judge-input/v1" {
			delete(envelope.Input, "policy_snapshot")
			b, _ := json.Marshal(envelope.Input)
			var frozen agenteval.JudgeInput
			if json.Unmarshal(b, &frozen) != nil {
				return agenteval.Trajectory{}, evaluationproduct.ErrInvalid
			}
			ref, e := frozen.SourceReference()
			if e != nil {
				return agenteval.Trajectory{}, evaluationproduct.ErrInvalid
			}
			if e = p.AuthorizeSources(ctx, a, []agenteval.SourceReference{ref}); e != nil {
				return agenteval.Trajectory{}, e
			}
		}
	}
	meta := audit.MetadataScope{Type: "application", TenantID: a.Scope.TenantID, DepartmentID: a.Scope.DepartmentID, ApplicationID: a.Scope.ApplicationID}
	// A current owner history grant exposes only exact-Run typed summaries;
	// it never enables application-wide audit or usage browsing.
	owned := run.Scope.PrincipalType == "user" && run.Scope.PrincipalID == a.PrincipalID
	if p.audit != nil && (owned || (identityAuditMetadataControl{store: p.identity}).Authorize(ctx, actor.Scope, meta) == nil) {
		toolEvents := []agenteval.Event{}
		cursor := ""
		for n := 0; n < 100; n++ {
			page, e := p.audit.ListRuntimeSteps(ctx, audit.RuntimeStepsQuery{Scope: meta, RunID: id, PageSize: 100, Cursor: cursor})
			if e != nil {
				return agenteval.Trajectory{}, e
			}
			for _, step := range page.Items {
				kind := "tool"
				if step.ExecutionType != nil {
					kind = *step.ExecutionType
				}
				if kind == "api" || kind == "code" {
					kind = "tool"
				}
				status := step.Status
				if step.ObservationStatus != nil {
					status = *step.ObservationStatus
				}
				errorType := ""
				if step.ErrorType != nil {
					errorType = *step.ErrorType
				}
				started := ""
				if step.StartedAt != nil {
					started = step.StartedAt.UTC().Format(time.RFC3339Nano)
				}
				finished := ""
				if step.FinishedAt != nil {
					finished = step.FinishedAt.UTC().Format(time.RFC3339Nano)
				}
				toolEvents = append(toolEvents, agenteval.Event{RunID: id, Kind: kind, StartedAt: started, FinishedAt: finished, StepID: step.StepID, ToolName: step.ToolName, Status: status, ErrorType: errorType, DurationMS: step.DurationMS, OutputBytes: step.OutputSizeBytes})
			}
			if page.NextCursor == "" {
				if t.Coverage == nil {
					t.Coverage = map[string]bool{}
				}
				t.Coverage["tool"] = t.FinishedAt != ""
				break
			}
			cursor = page.NextCursor
			if n == 99 {
				t.Missing = append(t.Missing, "runtime_steps_truncated")
				t.Complete = false
			}
		}
		if !owned && (identityAuditMetadataControl{store: p.identity}).Authorize(ctx, actor.Scope, meta) != nil {
			return agenteval.Trajectory{}, evaluationproduct.ErrForbidden
		}
		sort.SliceStable(toolEvents, func(i, j int) bool {
			a, ae := time.Parse(time.RFC3339Nano, toolEvents[i].StartedAt)
			b, be := time.Parse(time.RFC3339Nano, toolEvents[j].StartedAt)
			if ae != nil || be != nil {
				return ae == nil && be != nil
			}
			return a.Before(b)
		})
		t.Events = append(t.Events, toolEvents...)
	} else {
		t.Missing = append(t.Missing, "runtime_steps_permission_or_provider")
		t.Complete = false
	}
	uScope := usagecost.Scope{TenantID: a.Scope.TenantID, DepartmentID: a.Scope.DepartmentID, ApplicationID: a.Scope.ApplicationID, AgentID: run.Scope.AgentID, AgentVersionID: run.AgentVersionID, RunID: id}
	uActor := usagecost.Actor{TenantID: a.Scope.TenantID, DepartmentID: a.Scope.DepartmentID, ApplicationID: a.Scope.ApplicationID, PrincipalID: a.PrincipalID, PrincipalType: a.PrincipalType}
	if p.usage != nil && (owned || (identityUsageControl{store: p.identity}).AuthorizeUsageCost(ctx, uActor, usagecost.ActionReadUsage, uScope) == nil) {
		from, to := run.CreatedAt.Add(-time.Second), time.Now().Add(time.Second)
		summary, e := p.usage.EvaluationUsage(ctx, uScope, from, to)
		if e != nil {
			return agenteval.Trajectory{}, e
		}
		// No event is not proof of zero usage; unknown historical bills remain missing.
		if summary.EventCount > 0 && summary.Unsettled == 0 {
			t.Measurements.InputTokens = &summary.InputTokens
			t.Measurements.OutputTokens = &summary.OutputTokens
			// 仅同币种、精确结算的历史价目可作为计价费用；不是提供商账单。
			if summary.Currency != "" && summary.Unpriced == 0 {
				// 仅同币种、精确结算的历史价目可作为计价费用；不是提供商账单。
				if summary.Currency != "" && summary.Unpriced == 0 {
					t.Measurements.CostMicros = &summary.CostMicros
					t.Measurements.Currency = summary.Currency
				} else {
					t.Missing = append(t.Missing, "usage_currency_or_price_proof")
				}
				t.Measurements.Currency = summary.Currency
			} else {
				t.Missing = append(t.Missing, "usage_currency_or_price_proof")
			}
			t.Measurements.ModelCalls = &summary.EventCount
			t.Coverage["usage"] = true
		} else if summary.Unsettled > 0 {
			t.Missing = append(t.Missing, "usage_unsettled_or_unknown")
		} else {
			t.Missing = append(t.Missing, "confirmed_usage")
		}
		if !owned && (identityUsageControl{store: p.identity}).AuthorizeUsageCost(ctx, uActor, usagecost.ActionReadUsage, uScope) != nil {
			return agenteval.Trajectory{}, evaluationproduct.ErrForbidden
		}
	} else {
		t.Missing = append(t.Missing, "usage_permission_or_provider")
	}
	// Final object authorization wins over all previous successful reads.
	if err = (identityExecutionBrowserControl{store: p.identity, runs: p.runs}).Authorize(ctx, run.Scope, actor, "history.read"); err != nil {
		return agenteval.Trajectory{}, inspectionReadError(err)
	}
	return t, nil
}
func inspectionReadError(err error) error {
	switch {
	case errors.Is(err, platformruntime.ErrRunNotFound):
		return evaluationproduct.ErrNotFound
	case errors.Is(err, execution.ErrRunPermissionDenied), errors.Is(err, execution.ErrBrowserSessionInvalid):
		return evaluationproduct.ErrForbidden
	default:
		return err
	}
}
