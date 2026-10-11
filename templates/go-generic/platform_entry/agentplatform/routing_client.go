package agentplatform

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func childReceiptHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}

// ReadAgentAdmissionState proves whether the original prepared slot has a Run.
// It is metadata-only and grants no permission; admission still checks live IAM.
func (c *CapabilityClient) ReadAgentAdmissionState(ctx context.Context, operationKey string, ordinal int, childKey, inputFingerprint, outputSchema string) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || !childReceiptHash(childKey) || !childReceiptHash(inputFingerprint) || !strings.HasPrefix(outputSchema, "schema://") || len(outputSchema) > 256 || strings.ContainsAny(outputSchema, "*\x00\r\n\t ") {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/admission-state", map[string]any{"operation_key": operationKey, "ordinal": ordinal})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	parentID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		State struct {
			Version          string `json:"version"`
			ParentRunID      string `json:"parent_run_id"`
			OperationKey     string `json:"operation_key"`
			Ordinal          *int   `json:"ordinal"`
			ChildKey         string `json:"child_key"`
			ChildRunID       string `json:"child_run_id"`
			Status           string `json:"status"`
			Revision         uint64 `json:"revision"`
			InputFingerprint string `json:"input_fingerprint"`
			OutputSchema     string `json:"output_schema"`
		} `json:"admission_state"`
	}
	if groupDecode(result, &receipt) != nil {
		return nil, harnessError("AGENT_ADMISSION_STATE_REJECTED")
	}
	p := receipt.State
	if p.Version != "agent-child-admission-state/v1" || parentID == "" || p.ParentRunID != parentID || p.OperationKey != operationKey || p.Ordinal == nil || *p.Ordinal != ordinal || p.ChildKey != childKey || p.InputFingerprint != inputFingerprint || p.OutputSchema != outputSchema || p.Revision > 1<<63-1 {
		return nil, harnessError("AGENT_ADMISSION_STATE_REJECTED")
	}
	if p.Status == "preparing" {
		if p.Revision != 2 || p.ChildRunID != "" {
			return nil, harnessError("AGENT_ADMISSION_STATE_REJECTED")
		}
	} else {
		valid := p.Status == "accepted" || p.Status == "running" || p.Status == "completed" || p.Status == "failed" || p.Status == "cancelled" || p.Status == "uncertain"
		if !valid || p.Revision < 3 || p.ChildRunID != "child-"+childKey[:48] {
			return nil, harnessError("AGENT_ADMISSION_STATE_REJECTED")
		}
	}
	return result, nil
}

// CancelAgentChild persists stop intent for a recorded child. Cancelling and
// recovering are pending states; neither means the remote execution stopped.
func (c *CapabilityClient) CancelAgentChild(ctx context.Context, operationKey string, ordinal int, childKey string, expectedExecutionRevision uint64) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || !childReceiptHash(childKey) || expectedExecutionRevision == 0 || expectedExecutionRevision > 1<<63-1 {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/cancel", map[string]any{"operation_key": operationKey, "ordinal": ordinal, "expected_execution_revision": expectedExecutionRevision})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		Cancellation struct {
			Version           string `json:"version"`
			ParentRunID       string `json:"parent_run_id"`
			ChildRunID        string `json:"child_run_id"`
			ChildKey          string `json:"child_key"`
			OperationKey      string `json:"operation_key"`
			Ordinal           *int   `json:"ordinal"`
			Status            string `json:"status"`
			ExecutionRevision uint64 `json:"execution_revision"`
		} `json:"cancellation"`
	}
	raw, err := json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		return nil, harnessError("AGENT_CANCELLATION_REJECTED")
	}
	p := receipt.Cancellation
	validStatus := p.Status == "cancelling" || p.Status == "recovering" || p.Status == "cancelled" || p.Status == "completed" || p.Status == "failed"
	if p.Version != "agent-child-cancellation/v1" || runID == "" || p.ParentRunID != runID || p.OperationKey != operationKey || p.Ordinal == nil || *p.Ordinal != ordinal || p.ChildKey != childKey || p.ChildRunID != "child-"+childKey[:48] || p.ExecutionRevision == 0 || p.ExecutionRevision > 1<<63-1 || !validStatus {
		return nil, harnessError("AGENT_CANCELLATION_REJECTED")
	}
	return result, nil
}

// AdmitAgentChild accepts the frozen preparation once. An unknown response
// must be reconciled with ReadAgentChild; this method never retries dispatch.
func (c *CapabilityClient) AdmitAgentChild(ctx context.Context, operationKey string, ordinal int, childKey, inputFingerprint string) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || !childReceiptHash(childKey) || !childReceiptHash(inputFingerprint) {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/admit", map[string]any{"operation_key": operationKey, "ordinal": ordinal, "expected_revision": 2})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		Admission struct {
			Version          string `json:"version"`
			ParentRunID      string `json:"parent_run_id"`
			ChildRunID       string `json:"child_run_id"`
			ChildKey         string `json:"child_key"`
			OperationKey     string `json:"operation_key"`
			Ordinal          *int   `json:"ordinal"`
			Status           string `json:"status"`
			Revision         uint64 `json:"revision"`
			InputFingerprint string `json:"input_fingerprint"`
		} `json:"admission"`
	}
	raw, err := json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		return nil, harnessError("AGENT_ADMISSION_REJECTED")
	}
	p := receipt.Admission
	validStatus := p.Status == "accepted" || p.Status == "running" || p.Status == "completed" || p.Status == "failed" || p.Status == "cancelled" || p.Status == "uncertain"
	if p.Version != "agent-child-admission/v1" || runID == "" || p.ParentRunID != runID || p.OperationKey != operationKey || p.Ordinal == nil || *p.Ordinal != ordinal || p.ChildKey != childKey || p.ChildRunID != "child-"+childKey[:48] || p.InputFingerprint != inputFingerprint || p.Revision < 3 || !validStatus {
		return nil, harnessError("AGENT_ADMISSION_REJECTED")
	}
	return result, nil
}

// ReadAgentChild reads only a recorded immediate child. Output is untrusted
// business data, never instructions or permission to retry a child operation.
func (c *CapabilityClient) ReadAgentChild(ctx context.Context, operationKey string, ordinal int, childKey, outputSchema string) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || !childReceiptHash(childKey) || !strings.HasPrefix(outputSchema, "schema://") || len(outputSchema) > 256 || strings.ContainsAny(outputSchema, "*\x00\r\n\t ") {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/child", map[string]any{"operation_key": operationKey, "ordinal": ordinal})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	return validateAgentChildResult(result, runID, operationKey, ordinal, childKey, outputSchema)
}

func validateAgentChildResult(result map[string]any, runID, operationKey string, ordinal int, childKey, outputSchema string) (map[string]any, error) {
	var receipt struct {
		Child struct {
			Version           string          `json:"version"`
			ParentRunID       string          `json:"parent_run_id"`
			ChildRunID        string          `json:"child_run_id"`
			ChildKey          string          `json:"child_key"`
			OperationKey      string          `json:"operation_key"`
			Ordinal           *int            `json:"ordinal"`
			Status            string          `json:"status"`
			ExecutionRevision uint64          `json:"execution_revision"`
			OutputSchema      string          `json:"output_schema"`
			Output            json.RawMessage `json:"output"`
			OutputBytes       *int64          `json:"output_bytes"`
			OutputOmitted     *bool           `json:"output_omitted"`
			OutputDigest      string          `json:"output_digest"`
			InstructionTrust  string          `json:"instruction_trust"`
		} `json:"child"`
	}
	raw, err := json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		return nil, harnessError("AGENT_CHILD_REJECTED")
	}
	p := receipt.Child
	validStatus := false
	for _, status := range []string{"accepted", "running", "waiting", "completed", "failed", "cancelled", "cancelling", "recovering", "uncertain"} {
		if p.Status == status {
			validStatus = true
		}
	}
	if p.Version != "agent-child-result/v1" || runID == "" || p.ParentRunID != runID || p.OperationKey != operationKey || p.Ordinal == nil || *p.Ordinal != ordinal || p.ChildKey != childKey || p.ChildRunID != "child-"+childKey[:48] || p.ExecutionRevision == 0 || !validStatus || p.OutputSchema != outputSchema || p.InstructionTrust != "untrusted_data" || p.OutputBytes == nil || *p.OutputBytes < 0 || p.OutputOmitted == nil || len(p.Output) == 0 {
		return nil, harnessError("AGENT_CHILD_REJECTED")
	}
	if string(p.Output) != "null" {
		var output map[string]json.RawMessage
		if p.Status != "completed" || *p.OutputOmitted || *p.OutputBytes == 0 || *p.OutputBytes > 16384 || len(p.Output) > 98304 || json.Unmarshal(p.Output, &output) != nil || output == nil || !childReceiptHash(p.OutputDigest) {
			return nil, harnessError("AGENT_CHILD_REJECTED")
		}
	} else if p.OutputDigest != "" || (*p.OutputOmitted && (p.Status != "completed" || *p.OutputBytes <= 16384)) || (!*p.OutputOmitted && (p.Status == "completed" || *p.OutputBytes != 0)) {
		return nil, harnessError("AGENT_CHILD_REJECTED")
	}
	return result, nil
}

type AgentChildBinding struct {
	ChildKey     string
	OutputSchema string
}

// GatherAgentChildren reads a whole admitted plan once. Bindings must be saved
// in route ordinal order; this does not poll, create, resume or re-dispatch.
func (c *CapabilityClient) GatherAgentChildren(ctx context.Context, operationKey string, bindings []AgentChildBinding) (map[string]any, error) {
	bindings = append([]AgentChildBinding(nil), bindings...)
	if !harnessSkillIdentifier(operationKey) || len(bindings) < 1 || len(bindings) > 16 {
		return nil, harnessError("REQUEST_INVALID")
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		if !childReceiptHash(binding.ChildKey) || seen[binding.ChildKey] || !strings.HasPrefix(binding.OutputSchema, "schema://") || len(binding.OutputSchema) > 256 || strings.ContainsAny(binding.OutputSchema, "*\x00\r\n\t ") {
			return nil, harnessError("REQUEST_INVALID")
		}
		seen[binding.ChildKey] = true
	}
	result, err := c.Post(ctx, "/internal/agent/gather", map[string]any{"operation_key": operationKey})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		Group struct {
			Version          string           `json:"version"`
			ParentRunID      string           `json:"parent_run_id"`
			OperationKey     string           `json:"operation_key"`
			Status           string           `json:"status"`
			Terminal         *bool            `json:"terminal"`
			OutputsComplete  *bool            `json:"outputs_complete"`
			Completed        *int             `json:"completed"`
			Failed           *int             `json:"failed"`
			Cancelled        *int             `json:"cancelled"`
			Pending          *int             `json:"pending"`
			OutputsOmitted   *int             `json:"outputs_omitted"`
			Children         []map[string]any `json:"children"`
			InstructionTrust string           `json:"instruction_trust"`
		} `json:"group"`
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 524288 {
		return nil, harnessError("AGENT_GROUP_REJECTED")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&receipt) != nil {
		return nil, harnessError("AGENT_GROUP_REJECTED")
	}
	g := receipt.Group
	if g.Version != "agent-group-result/v1" || runID == "" || g.ParentRunID != runID || g.OperationKey != operationKey || g.InstructionTrust != "untrusted_data" || g.Terminal == nil || g.OutputsComplete == nil || g.Completed == nil || g.Failed == nil || g.Cancelled == nil || g.Pending == nil || g.OutputsOmitted == nil || len(g.Children) != len(bindings) {
		return nil, harnessError("AGENT_GROUP_REJECTED")
	}
	completed, failed, cancelled, pending, omitted := 0, 0, 0, 0, 0
	uncertain := false
	for ordinal, child := range g.Children {
		if _, err := validateAgentChildResult(map[string]any{"child": child}, runID, operationKey, ordinal, bindings[ordinal].ChildKey, bindings[ordinal].OutputSchema); err != nil {
			return nil, harnessError("AGENT_GROUP_REJECTED")
		}
		switch child["status"] {
		case "completed":
			completed++
		case "failed":
			failed++
		case "cancelled":
			cancelled++
		default:
			pending++
		}
		uncertain = uncertain || child["status"] == "uncertain"
		if child["output_omitted"] == true {
			omitted++
		}
	}
	terminal := pending == 0
	status := "completed"
	switch {
	case uncertain:
		status = "uncertain"
	case !terminal:
		status = "in_progress"
	case failed > 0:
		status = "failed"
	case cancelled > 0:
		status = "cancelled"
	}
	if g.Status != status || *g.Terminal != terminal || *g.OutputsComplete != (terminal && completed == len(bindings) && omitted == 0) || *g.Completed != completed || *g.Failed != failed || *g.Cancelled != cancelled || *g.Pending != pending || *g.OutputsOmitted != omitted {
		return nil, harnessError("AGENT_GROUP_REJECTED")
	}
	return result, nil
}

// PrepareAgentChild freezes input for an existing route ordinal. The receipt
// describes preparation only; it is neither execution nor a dispatch permit.
func (c *CapabilityClient) PrepareAgentChild(ctx context.Context, operationKey string, ordinal int, inputSchema string, input map[string]any) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || input == nil || !strings.HasPrefix(inputSchema, "schema://") || len(inputSchema) > 256 || strings.ContainsAny(inputSchema, "*\x00\r\n\t ") {
		return nil, harnessError("REQUEST_INVALID")
	}
	if _, reserved := input["policy_snapshot"]; reserved {
		return nil, harnessError("REQUEST_INVALID")
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 65536 {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/prepare", map[string]any{"operation_key": operationKey, "ordinal": ordinal, "expected_revision": 1, "input_schema": inputSchema, "input": json.RawMessage(raw)})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		Preparation struct {
			Version          string `json:"version"`
			ParentRunID      string `json:"parent_run_id"`
			OperationKey     string `json:"operation_key"`
			Ordinal          *int   `json:"ordinal"`
			ChildKey         string `json:"child_key"`
			Status           string `json:"status"`
			Revision         uint64 `json:"revision"`
			InputSchema      string `json:"input_schema"`
			InputFingerprint string `json:"input_fingerprint"`
		} `json:"preparation"`
	}
	raw, err = json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		return nil, harnessError("AGENT_PREPARATION_REJECTED")
	}
	p := receipt.Preparation
	validHash := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32 && value == hex.EncodeToString(decoded)
	}
	if p.Version != "agent-child-preparation/v1" || runID == "" || p.ParentRunID != runID || p.OperationKey != operationKey || p.Ordinal == nil || *p.Ordinal != ordinal || p.Status != "preparing" || p.Revision != 2 || p.InputSchema != inputSchema || !validHash(p.ChildKey) || !validHash(p.InputFingerprint) {
		return nil, harnessError("AGENT_PREPARATION_REJECTED")
	}
	return result, nil
}

// RouteAgents only plans and reserves eligible child targets. It does not
// dispatch, grant permission, or allow caller-selected endpoints or versions.
func (c *CapabilityClient) RouteAgents(ctx context.Context, operationKey, taskType string, count int) (map[string]any, error) {
	if !harnessSkillIdentifier(operationKey) || !harnessSkillIdentifier(taskType) || count < 1 || count > 16 {
		return nil, harnessError("REQUEST_INVALID")
	}
	result, err := c.Post(ctx, "/internal/agent/route", map[string]any{"operation_key": operationKey, "task_type": taskType, "count": count})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	runID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	var receipt struct {
		Route struct {
			Version      string `json:"version"`
			OperationKey string `json:"operation_key"`
			TaskType     string `json:"task_type"`
			ParentRunID  string `json:"parent_run_id"`
			ChildDepth   int    `json:"child_depth"`
			Targets      []struct {
				InstallationID string `json:"installation_id"`
				AgentID        string `json:"agent_id"`
				VersionID      string `json:"version_id"`
				InputSchema    string `json:"input_schema"`
				OutputSchema   string `json:"output_schema"`
			} `json:"targets"`
		} `json:"route"`
	}
	raw, err := json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Route.Version != "agent-route/v1" || receipt.Route.OperationKey != operationKey || receipt.Route.TaskType != taskType || runID == "" || receipt.Route.ParentRunID != runID || receipt.Route.ChildDepth < 1 || receipt.Route.ChildDepth > 4 || len(receipt.Route.Targets) != count {
		return nil, harnessError("AGENT_ROUTE_REJECTED")
	}
	seen := map[string]bool{}
	for _, target := range receipt.Route.Targets {
		if !harnessSkillIdentifier(target.InstallationID) || !harnessSkillIdentifier(target.AgentID) || !harnessSkillIdentifier(target.VersionID) || seen[target.InstallationID] {
			return nil, harnessError("AGENT_ROUTE_REJECTED")
		}
		seen[target.InstallationID] = true
		for _, schema := range []string{target.InputSchema, target.OutputSchema} {
			if !strings.HasPrefix(schema, "schema://") || len(schema) > 256 || strings.ContainsAny(schema, "*\x00\r\n\t ") {
				return nil, harnessError("AGENT_ROUTE_REJECTED")
			}
		}
	}
	return result, nil
}
