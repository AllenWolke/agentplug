package agentplatform

import "context"

// LoadSkill first returns summary and section names. Request one explicit
// section to disclose its instructions under the same run-pinned version.
// This does not register, publish, approve, or grant any Skill capability.
func (c *CapabilityClient) LoadSkill(ctx context.Context, skillID, section string) (map[string]any, error) {
	if skillID == "" || len(skillID) > 128 || len(section) > 128 {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "valid skill and optional section required"}
	}
	return c.Post(ctx, "/internal/skill/load", map[string]any{"skill_id": skillID, "section": section})
}
