package main

import (
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestIndexPublicationRejectsCorruptOrSensitiveOutcomes(t *testing.T) {
	for _, mode := range []string{"allowed", "extra-secret", "foreign-knowledge", "wrong-revision", "wrong-run", "wrong-event", "negative-count", "missing-generation", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			result := knowledge.IndexTaskPublication{SchemaVersion: "knowledge-index-result/v1", KnowledgeID: "docs", GenerationID: "generation", SourceRevision: 1, IndexRevision: 1, EmbeddedChunks: 2, CheckpointRevision: 1}
			if mode == "foreign-knowledge" {
				result.KnowledgeID = "other"
			}
			if mode == "negative-count" {
				result.EmbeddedChunks = -1
			}
			if mode == "missing-generation" {
				result.GenerationID = ""
			}
			raw, _ := json.Marshal(result)
			if mode == "extra-secret" {
				raw = append(raw[:len(raw)-1], []byte(",\"lease_token\":\"private\"}")...)
			}
			if mode == "trailing-json" {
				raw = append(raw, []byte("{}")...)
			}
			outcome := platformruntime.Outcome{RunID: "run", Revision: 3, EventType: "task_completed", OutputJSON: raw}
			if mode == "wrong-revision" {
				outcome.Revision++
			}
			if mode == "wrong-run" {
				outcome.RunID = "other"
			}
			if mode == "wrong-event" {
				outcome.EventType = "task_failed"
			}
			_, err := indexPublication(outcome, platformruntime.Run{ID: "run", Revision: 3}, knowledge.ProjectionScope{KnowledgeID: "docs"})
			if (err == nil) != (mode == "allowed") {
				t.Fatal("unsafe publication validation", err)
			}
		})
	}
}
