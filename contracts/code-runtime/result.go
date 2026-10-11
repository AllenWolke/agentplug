package coderuntime

import "time"

// Result is shared by the isolated controller and platform adapter. Unknown
// resource measurements remain null rather than being represented as zero.
type Result struct {
	Version          string         `json:"version"`
	Status           string         `json:"status"`
	ErrorType        string         `json:"error_type"`
	Stdout           string         `json:"stdout"`
	Stderr           string         `json:"stderr"`
	ExitCode         int            `json:"exit_code"`
	OutputTruncated  bool           `json:"output_truncated"`
	StartedAt        time.Time      `json:"started_at"`
	FinishedAt       time.Time      `json:"finished_at"`
	DurationMS       int64          `json:"duration_ms"`
	Limits           Limits         `json:"limits"`
	ResourceUsage    map[string]any `json:"resource_usage"`
	ContainerRemoved bool           `json:"container_removed"`
}
