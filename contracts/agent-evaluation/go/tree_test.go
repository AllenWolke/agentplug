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
