package agenteval

import (
	"encoding/json"
	"math"
	"sort"
	"time"
)

// AggregateTree accepts only already authorized, direct Run projections. It
// never sums parent latency or TTFT and never treats missing child cost as 0.
func AggregateTree(root Trajectory, descendants []Trajectory, complete bool) Trajectory {
	limits, validProfile := TrajectoryReadLimitsFor(root.EvidenceReadProfile)
	if !validProfile {
		limits, _ = TrajectoryReadLimitsFor("")
		complete = false
		root.Missing = append(root.Missing, "evidence_read_profile_invalid")
	}
	all := []Trajectory{root}
	seen := map[string]bool{root.RunID: true}
	for _, t := range descendants {
		if t.EvidenceReadProfile != root.EvidenceReadProfile {
			complete = false
			root.Missing = append(root.Missing, "evidence_read_profile_mismatch")
			continue
		}
		if t.ToolArgumentProjection != root.ToolArgumentProjection {
			complete = false
			root.Missing = append(root.Missing, "tool_argument_projection_mismatch")
			continue
		}
		if t.RunID == "" || seen[t.RunID] {
			continue
		}
		if !seen[t.ParentRunID] {
			complete = false
			continue
		}
		seen[t.RunID] = true
		all = append(all, t)
		root.Descendants = append(root.Descendants, RunSummary{RunID: t.RunID, ParentRunID: t.ParentRunID, Agent: t.Agent, Status: t.Status, TraceID: t.TraceID, StartedAt: t.StartedAt, FinishedAt: t.FinishedAt, Missing: t.Missing, Coverage: t.Coverage, Measurements: t.Measurements})
		root.Events = append(root.Events, t.Events...)
	}
	if root.Coverage == nil {
		root.Coverage = map[string]bool{}
	}
	root.Coverage["run_tree"] = complete
	for _, kind := range []string{"events", "tool", "usage", "model_timing", "native_stage_cache"} {
		valid := complete
		for _, t := range all {
			if !t.Coverage[kind] {
				valid = false
			}
		}
		root.Coverage[kind] = valid
	}
	if !complete {
		root.Missing = append(root.Missing, "run_tree_incomplete")
	}
	for _, t := range all[1:] {
		if len(t.Missing) > 0 {
			root.Missing = append(root.Missing, "descendant_evidence_missing")
			break
		}
	}
	kept, bytesRead := 0, 2
	for _, event := range root.Events {
		if kept >= limits.Events {
			break
		}
		if limits.EventBytes > 0 {
			encoded, err := json.Marshal(event)
			if err != nil || bytesRead+len(encoded)+1 > limits.EventBytes {
				break
			}
			bytesRead += len(encoded) + 1
		}
		kept++
	}
	if kept < len(root.Events) {
		root.Events = root.Events[:kept]
		root.Coverage["events"], root.Coverage["tool"] = false, false
		root.Coverage["model_timing"], root.Coverage["native_stage_cache"] = false, false
		root.Missing = append(root.Missing, "tree_events_truncated")
	}
	sort.SliceStable(root.Events, func(i, j int) bool {
		a, ae := time.Parse(time.RFC3339Nano, root.Events[i].StartedAt)
		b, be := time.Parse(time.RFC3339Nano, root.Events[j].StartedAt)
		if ae != nil || be != nil {
			return ae == nil && be != nil
		}
		return a.Before(b)
	})
	sum := func(get func(Measurements) *int64) *int64 {
		if !complete {
			return nil
		}
		var n int64
		for _, t := range all {
			p := get(t.Measurements)
			if p == nil || *p < 0 || math.MaxInt64-n < *p {
				return nil
			}
			n += *p
		}
		return &n
	}
	root.Measurements.InputTokens = sum(func(m Measurements) *int64 { return m.InputTokens })
	root.Measurements.OutputTokens = sum(func(m Measurements) *int64 { return m.OutputTokens })
	root.Measurements.CostMicros = sum(func(m Measurements) *int64 { return m.CostMicros })
	root.Measurements.ToolCostMicros = sum(func(m Measurements) *int64 { return m.ToolCostMicros })
	root.Measurements.ModelCalls = sum(func(m Measurements) *int64 { return m.ModelCalls })
	root.Measurements.Loops = sum(func(m Measurements) *int64 { return m.Loops })
	root.Measurements.CacheHits = sum(func(m Measurements) *int64 { return m.CacheHits })
	root.Measurements.CacheLookups = sum(func(m Measurements) *int64 { return m.CacheLookups })
	for _, t := range all {
		if t.Measurements.Currency == "" || t.Measurements.Currency != root.Measurements.Currency {
			root.Measurements.Currency = ""
			break
		}
	}
	root.Complete = root.Complete && complete && len(root.Missing) == 0
	return root
}
