// Package inspect inventories a legacy Agent without importing or executing it.
// inspect 包只读盘点存量 Agent，不导入、不执行目标代码。
package inspect

import "time"

type Status string

const (
	Confirmed     Status = "confirmed"
	Declared      Status = "declared"
	Unknown       Status = "unknown"
	Failed        Status = "failed"
	NotApplicable Status = "not_applicable"
)

// Finding mirrors one structural fact discovered in the legacy Agent. The JSON
// tags are pinned to contracts/agent-template/v1/inventory.schema.json so the
// emitted report validates against the declared contract.
// Finding 表示存量 Agent 中识别到的一项结构化事实；JSON 标签与
// contracts/agent-template/v1/inventory.schema.json 对齐，使报告符合声明契约。
type Finding struct {
	ID         string   `json:"code"`
	Status     Status   `json:"status"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence float64  `json:"confidence"`
}

type Report struct {
	InventoryVersion string    `json:"inventory_version"`
	Root             string    `json:"root"`
	AgentID          string    `json:"agent_id,omitempty"`
	Language         string    `json:"language"`
	Framework        string    `json:"framework,omitempty"`
	Files            []string  `json:"files"`
	Skipped          []string  `json:"skipped,omitempty"`
	Findings         []Finding `json:"findings"`
	SuggestedAdapter string    `json:"suggested_adapter,omitempty"`
	ReadErrors       []string  `json:"read_errors,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
}
