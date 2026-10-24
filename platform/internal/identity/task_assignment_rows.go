package identity

import "encoding/json"

// Match loadTaskAssignments exactly: identity/scope/status/revision come from
// native columns. Only validity and attribution are supplied by the JSON body.
func parseTaskAssignmentRows(raw []byte) ([]TaskAssignment, error) {
	var rows []struct {
		ID              string          `json:"id"`
		SubjectID       string          `json:"subject_id"`
		TaskID          string          `json:"task_id"`
		Action          string          `json:"action"`
		TenantID        string          `json:"tenant_id"`
		DepartmentID    string          `json:"department_id"`
		ApplicationID   string          `json:"application_id"`
		AgentInstanceID string          `json:"agent_instance_id"`
		Status          string          `json:"status"`
		Revision        uint64          `json:"revision"`
		Payload         json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	result := make([]TaskAssignment, 0, len(rows))
	for _, row := range rows {
		var metadata TaskAssignment
		if err := json.Unmarshal(row.Payload, &metadata); err != nil {
			return nil, err
		}
		result = append(result, TaskAssignment{ID: row.ID, SubjectID: row.SubjectID,
			TaskID: row.TaskID, Action: row.Action, Status: row.Status, Revision: row.Revision,
			Scope: ManagementScope{Type: "agent_installation", TenantID: row.TenantID,
				DepartmentID: row.DepartmentID, ApplicationID: row.ApplicationID, ResourceID: row.AgentInstanceID},
			Validity: metadata.Validity, SourceID: metadata.SourceID,
			DelegationID: metadata.DelegationID, TaskObject: metadata.TaskObject})
	}
	return result, nil
}
