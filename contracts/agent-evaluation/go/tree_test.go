package agenteval

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTreeAggregatesOnceAndCannotInventChildUsage(t *testing.T) {
	rootCost, childCost, rootLatency, childLatency := int64(7), int64(5), 100., 40.
	root := Trajectory{RunID: "root", Coverage: map[string]bool{"tool": true, "events": true, "usage": true}, Measurements: Measurements{CostMicros: &rootCost, LatencyMS: &rootLatency}}
	child := Trajectory{RunID: "child", ParentRunID: "root", Coverage: map[string]bool{"tool": true, "events": true, "usage": true}, Measurements: Measurements{CostMicros: &childCost, LatencyMS: &childLatency}}
	result := AggregateTree(root, []Trajectory{child, child}, true)
	if len(result.Descendants) != 1 || result.Measurements.CostMicros == nil || *result.Measurements.CostMicros != 12 || *result.Measurements.LatencyMS != 100 {
		t.Fatal("duplicate counting or non-critical-path latency")
	}
	child.Measurements.CostMicros = nil
	result = AggregateTree(root, []Trajectory{child}, true)
	if result.Measurements.CostMicros != nil {
		t.Fatal("unknown child cost replaced with zero")
	}
	result = AggregateTree(root, nil, false)
	if result.Measurements.CostMicros != nil || result.Coverage["tool"] || result.Coverage["run_tree"] {
		t.Fatal("partial authorized tree claimed complete")
	}
	child.ParentRunID = "unrelated"
	result = AggregateTree(root, []Trajectory{child}, true)
	if len(result.Descendants) != 0 || result.Coverage["run_tree"] {
		t.Fatal("unrelated Run admitted")
	}
}

func TestTreePerformanceCoveragePreservesMissingChildAndTruncation(t *testing.T) {
	lookups, hits := int64(4), int64(1)
	root := Trajectory{RunID: "root", Coverage: map[string]bool{"model_timing": true, "native_stage_cache": true},
		Measurements: Measurements{CacheLookups: &lookups, CacheHits: &hits}}
	child := Trajectory{RunID: "child", ParentRunID: "root"}
	result := AggregateTree(root, []Trajectory{child}, true)
	if result.Coverage["model_timing"] || result.Coverage["native_stage_cache"] || result.Measurements.CacheHits != nil {
		t.Fatal("missing child measurements became complete performance evidence")
	}
	root.Events = make([]Event, 10001)
	root.Coverage = map[string]bool{"model_timing": true, "native_stage_cache": true}
	result = AggregateTree(root, nil, true)
	if result.Coverage["model_timing"] || result.Coverage["native_stage_cache"] {
		t.Fatal("truncated tree retained timing/cache completeness")
	}
}

func TestRedactionStableForFrozenEvidenceAndNamespacedEvents(t *testing.T) {
	value := map[string]any{"large": strings.Repeat("中文", 4000)}
	for i := 0; i < 300; i++ {
		value[fmt.Sprintf("field-%03d", i)] = i
	}
	first := Sanitize(value)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(Sanitize(first))
	if string(a) != string(b) {
		t.Fatal("redaction changed a frozen proof on a second pass")
	}
	if EventReference("root", Event{RunID: "root", Seq: 1}) == EventReference("root", Event{RunID: "child", Seq: 1}) {
		t.Fatal("child sequence replaced root evidence")
	}
}

func TestTreeReadCapacityIsVersionedAndOverflowRemainsIncomplete(t *testing.T) {
	root := Trajectory{RunID: "root", Complete: true, Events: make([]Event, 10001),
		Coverage: map[string]bool{"events": true, "tool": true, "usage": true}}
	legacy := AggregateTree(root, nil, true)
	if len(legacy.Events) != 10000 || legacy.Complete || legacy.Coverage["events"] {
		t.Fatal("legacy event limit changed")
	}
	root.EvidenceReadProfile = EvidenceReadProfileLargeV1
	root.Coverage = map[string]bool{"events": true, "tool": true, "usage": true}
	large := AggregateTree(root, nil, true)
	if len(large.Events) != 10001 || !large.Complete || !large.Coverage["events"] {
		t.Fatal("explicit large profile did not retain bounded source events")
	}
	child := Trajectory{RunID: "child", ParentRunID: "root"}
	mixed := AggregateTree(root, []Trajectory{child}, true)
	if mixed.Complete || mixed.Coverage["run_tree"] || len(mixed.Descendants) != 0 {
		t.Fatal("mixed read protocols silently combined")
	}
	root.Events = make([]Event, 2200)
	for i := range root.Events {
		root.Events[i].Arguments = map[string]any{"body": strings.Repeat("x", 8192)}
	}
	root.Coverage = map[string]bool{"events": true, "tool": true}
	large = AggregateTree(root, nil, true)
	bytes, err := TrajectoryEventBytes(large.Events)
	if err != nil || bytes <= 16<<20 || bytes > 64<<20 || len(large.Events) != 2200 || !large.Complete || !large.Coverage["tool"] {
		t.Fatal("explicit large profile lost a legal full batch trace", bytes, err)
	}
	root.Events = make([]Event, 8800)
	body := strings.Repeat("x", 8192)
	for i := range root.Events {
		root.Events[i].Arguments = map[string]any{"body": body}
	}
	root.Coverage = map[string]bool{"events": true, "tool": true}
	large = AggregateTree(root, nil, true)
	bytes, err = TrajectoryEventBytes(large.Events)
	if err != nil || bytes > 64<<20 || len(large.Events) >= 8800 || large.Complete || large.Coverage["tool"] {
		t.Fatal("large byte overflow was accepted or exposed without bound", bytes, err)
	}
	root.EvidenceReadProfile = "unlimited"
	invalid := AggregateTree(root, nil, true)
	if invalid.Complete || invalid.Coverage["run_tree"] {
		t.Fatal("unknown profile accepted")
	}
}
