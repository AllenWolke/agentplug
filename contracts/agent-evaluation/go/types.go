// Package agenteval defines language-neutral, privacy-preserving evaluation evidence.
package agenteval

import "encoding/json"

const ReportVersion = "agent-evaluation-report/v1"
const TrajectoryVersion = "agent-evaluation-trajectory/v1"

type Agent struct {
	AgentID         string `json:"agent_id"`
	Name            string `json:"name"`
	Language        string `json:"language"`
	InstallationID  string `json:"installation_id"`
	VersionID       string `json:"version_id"`
	SemanticVersion string `json:"semantic_version"`
	Revision        uint64 `json:"revision"`
	Health          string `json:"health"`
	Reason          string `json:"reason,omitempty"`
	CheckedAt       string `json:"checked_at"`
	CanEvaluate     bool   `json:"can_evaluate"`
	ActiveRuns      *int   `json:"active_runs"`
}
type Discovery struct {
	Items           []Agent `json:"items"`
	Total           int     `json:"total"`
	OnlineAgents    int     `json:"online_agents"`
	OnlineInstances int     `json:"online_instances"`
	Evaluable       int     `json:"evaluable"`
	Page            int     `json:"page"`
	PageSize        int     `json:"page_size"`
}
type Event struct {
	Seq         uint64         `json:"seq"`
	RunID       string         `json:"run_id,omitempty"`
	StartedAt   string         `json:"started_at,omitempty"`
	FinishedAt  string         `json:"finished_at,omitempty"`
	Kind        string         `json:"kind"`
	StepID      string         `json:"step_id,omitempty"`
	ToolName    string         `json:"tool_name,omitempty"`
	CallID      string         `json:"call_id,omitempty"`
	Status      string         `json:"status,omitempty"`
	ErrorType   string         `json:"error_type,omitempty"`
	Arguments   map[string]any `json:"arguments,omitempty"`
	ResourceIDs []string       `json:"resource_ids,omitempty"`
	DurationMS  *int64         `json:"duration_ms,omitempty"`
	OutputBytes *int64         `json:"output_bytes,omitempty"`
}
type Measurements struct {
	LatencyMS      *float64 `json:"latency_ms"`
	TTFTMS         *float64 `json:"ttft_ms"`
	InputTokens    *int64   `json:"input_tokens"`
	OutputTokens   *int64   `json:"output_tokens"`
	CostMicros     *int64   `json:"cost_micros"`
	ToolCostMicros *int64   `json:"tool_cost_micros"`
	Currency       string   `json:"currency,omitempty"`
	ModelCalls     *int64   `json:"model_calls"`
	Loops          *int64   `json:"loops"`
	CacheHits      *int64   `json:"cache_hits"`
	CacheLookups   *int64   `json:"cache_lookups"`
}
type Trajectory struct {
	Version           string          `json:"version"`
	Source            string          `json:"source"`
	RunID             string          `json:"run_id"`
	ParentRunID       string          `json:"parent_run_id,omitempty"`
	Agent             Agent           `json:"agent"`
	Status            string          `json:"status"`
	StartedAt         string          `json:"started_at"`
	FinishedAt        string          `json:"finished_at,omitempty"`
	TraceID           string          `json:"trace_id"`
	InputHash         string          `json:"input_hash,omitempty"`
	BusinessInputHash string          `json:"business_input_hash,omitempty"`
	OutputHash        string          `json:"output_hash,omitempty"`
	Output            json.RawMessage `json:"output,omitempty"`
	Events            []Event         `json:"events"`
	Children          []string        `json:"children,omitempty"`
	Descendants       []RunSummary    `json:"descendants,omitempty"`
	Missing           []string        `json:"missing"`
	Complete          bool            `json:"complete"`
	Coverage          map[string]bool `json:"coverage,omitempty"`
	Measurements      Measurements    `json:"measurements"`
	// Checks contain evidence-backed outcomes from explicit graders/reviewers.
	// Missing checks are unknown, never implicit success.
	Checks map[string]bool `json:"checks,omitempty"`
}

// Descendant summaries contain no child input, output or coordination tokens.
type RunSummary struct {
	RunID        string          `json:"run_id"`
	ParentRunID  string          `json:"parent_run_id"`
	Agent        Agent           `json:"agent"`
	Status       string          `json:"status"`
	TraceID      string          `json:"trace_id"`
	StartedAt    string          `json:"started_at"`
	FinishedAt   string          `json:"finished_at,omitempty"`
	Missing      []string        `json:"missing"`
	Coverage     map[string]bool `json:"coverage,omitempty"`
	Measurements Measurements    `json:"measurements"`
}
type Assertion struct {
	Path  string `json:"path"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}
type ToolRules struct {
	Allowed      []string                  `json:"allowed,omitempty"`
	Required     []string                  `json:"required,omitempty"`
	Forbidden    []string                  `json:"forbidden,omitempty"`
	Parameters   map[string]map[string]any `json:"parameters,omitempty"`
	Dependencies [][2]string               `json:"dependencies,omitempty"`
	MaximumCalls map[string]int            `json:"maximum_calls,omitempty"`
	MinimumSteps int                       `json:"minimum_steps,omitempty"`
}

// GoldReference is evaluator-owned, frozen source evidence. It is never sent
// to the business Agent, and it does not certify production/human provenance.
type GoldReference struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Source   string `json:"source"`
	Content  string `json:"content"`
}

type Expected struct {
	GoldReferences []GoldReference `json:"gold_references,omitempty"`
	DomainFacts    []string        `json:"domain_facts,omitempty"`
	Assertions     []Assertion     `json:"assertions,omitempty"`
	Tools          *ToolRules      `json:"tools,omitempty"`
	RelevantIDs    []string        `json:"relevant_ids,omitempty"`
	CitationIDs    []string        `json:"citation_ids,omitempty"`
	RequiredTrace  []string        `json:"required_trace,omitempty"`
	// Applicability and reviewed checks are explicit evaluation labels.
	NotApplicable  []string        `json:"not_applicable,omitempty"`
	ReviewedChecks map[string]bool `json:"reviewed_checks,omitempty"`
}
type Trial struct {
	CaseID     string      `json:"case_id"`
	Attempt    int         `json:"attempt"`
	Trajectory Trajectory  `json:"trajectory"`
	Expected   Expected    `json:"expected"`
	Judgements []Judgement `json:"judgements,omitempty"`
}
type Metric struct {
	ID           string      `json:"id"`
	Dimension    string      `json:"dimension"`
	Name         string      `json:"name"`
	Definition   string      `json:"definition"`
	Unit         string      `json:"unit"`
	Direction    string      `json:"direction"`
	Status       string      `json:"status"`
	Value        *float64    `json:"value"`
	Numerator    float64     `json:"numerator"`
	Denominator  float64     `json:"denominator"`
	Samples      int         `json:"samples"`
	Missing      int         `json:"missing"`
	Confidence95 *[2]float64 `json:"confidence_95,omitempty"`
	Evidence     []string    `json:"evidence"`
}
type Recommendation struct {
	Priority       string   `json:"priority"`
	MetricID       string   `json:"metric_id"`
	Problem        string   `json:"problem"`
	Evidence       []string `json:"evidence"`
	Cause          string   `json:"cause"`
	CauseConfirmed bool     `json:"cause_confirmed"`
	Change         string   `json:"change"`
	Retest         string   `json:"retest"`
}
type Report struct {
	Version         string            `json:"version"`
	ProducedAt      string            `json:"produced_at"`
	Source          string            `json:"source"`
	Trials          int               `json:"trials"`
	Metrics         []Metric          `json:"metrics"`
	SafetyGate      string            `json:"safety_gate"`
	QualityGate     string            `json:"quality_gate"`
	Warnings        []string          `json:"warnings"`
	Recommendations []Recommendation  `json:"recommendations"`
	RunIDs          []string          `json:"run_ids"`
	Cohort          *Cohort           `json:"cohort,omitempty"`
	Reviews         []ReviewSummary   `json:"reviews,omitempty"`
	Targets         []Agent           `json:"targets,omitempty"`
	ThresholdGate   string            `json:"threshold_gate,omitempty"`
	Thresholds      []ThresholdResult `json:"thresholds,omitempty"`
}

// Review metadata is public report content. Private evidence and free-form
// model/reviewer text remain in authorized platform records.
type ReviewSummary struct {
	Source              string       `json:"source"`
	SourceRunID         string       `json:"source_run_id"`
	RubricID            string       `json:"rubric_id"`
	RubricHash          string       `json:"rubric_hash"`
	JudgeRunID          string       `json:"judge_run_id,omitempty"`
	JudgeVersionID      string       `json:"judge_version_id,omitempty"`
	ScoringModel        string       `json:"scoring_model,omitempty"`
	ScoringModelVersion string       `json:"scoring_model_version,omitempty"`
	ReviewerID          string       `json:"reviewer_id,omitempty"`
	ReviewEvidenceID    string       `json:"review_evidence_id,omitempty"`
	Measurements        Measurements `json:"measurements"`
	Overrides           []string     `json:"human_overrides,omitempty"`
}

// Version is deliberately excluded: the same cohort can compare Agent releases.
// Gold, workload and measurement protocol must remain identical.
type Cohort struct {
	AgentID             string `json:"agent_id"`
	DatasetHash         string `json:"dataset_hash"`
	Mode                string `json:"mode"`
	Repeat              int    `json:"repeat"`
	Concurrency         int    `json:"concurrency"`
	Currency            string `json:"currency,omitempty"`
	ScorerVersion       string `json:"scorer_version"`
	SimulationProfile   string `json:"simulation_profile,omitempty"`
	LimitTokens         int64  `json:"limit_tokens"`
	LimitMicros         int64  `json:"limit_micros"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
	MeasurementProtocol string `json:"measurement_protocol,omitempty"`
	ThresholdHash       string `json:"threshold_hash,omitempty"`
	ReviewProtocolHash  string `json:"review_protocol_hash,omitempty"`
}
