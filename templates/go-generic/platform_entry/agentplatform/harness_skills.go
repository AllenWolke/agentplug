package agentplatform

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

type harnessSkillRequest struct {
	SkillID  string   `json:"skill_id"`
	Sections []string `json:"sections"`
}
type harnessSkillBinding struct {
	VersionID string `json:"version_id"`
	Digest    string `json:"digest"`
}

func harnessSkillIdentifier(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n")
}

func harnessSkillRequests(value any, present bool) ([]harnessSkillRequest, error) {
	if !present {
		return nil, nil
	}
	if value == nil {
		return nil, harnessError("HARNESS_SKILL_REJECTED")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, harnessError("HARNESS_SKILL_REJECTED")
	}
	var requests []harnessSkillRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&requests) != nil || decoder.Decode(new(any)) != io.EOF || len(requests) > 4 {
		return nil, harnessError("HARNESS_SKILL_REJECTED")
	}
	var objects []map[string]json.RawMessage
	if json.Unmarshal(raw, &objects) != nil {
		return nil, harnessError("HARNESS_SKILL_REJECTED")
	}
	for _, object := range objects {
		if section, found := object["sections"]; found && bytes.Equal(bytes.TrimSpace(section), []byte("null")) {
			return nil, harnessError("HARNESS_SKILL_REJECTED")
		}
	}
	seen := map[string]bool{}
	for _, r := range requests {
		if !harnessSkillIdentifier(r.SkillID) || seen[r.SkillID] || len(r.Sections) > 4 {
			return nil, harnessError("HARNESS_SKILL_REJECTED")
		}
		seen[r.SkillID] = true
		sections := map[string]bool{}
		for _, section := range r.Sections {
			if !harnessSkillIdentifier(section) || sections[section] {
				return nil, harnessError("HARNESS_SKILL_REJECTED")
			}
			sections[section] = true
		}
	}
	return requests, nil
}
func harnessSkillDisclosure(ctx context.Context, p harnessPort, id, section string) (map[string]any, harnessSkillBinding, error) {
	result, err := p.Post(ctx, "/internal/skill/load", map[string]any{"skill_id": id, "section": section})
	if err != nil {
		return nil, harnessSkillBinding{}, err
	}
	d, ok := result["skill"].(map[string]any)
	if !ok || d["version"] != "skill-disclosure/v1" || d["skill_id"] != id || d["instruction_trust"] != "untrusted_data" {
		return nil, harnessSkillBinding{}, harnessError("HARNESS_SKILL_REJECTED")
	}
	v, _ := d["version_id"].(string)
	digest, _ := d["digest"].(string)
	hash, decodeErr := hex.DecodeString(digest)
	if !harnessSkillIdentifier(v) || decodeErr != nil || len(hash) != 32 || digest != hex.EncodeToString(hash) {
		return nil, harnessSkillBinding{}, harnessError("HARNESS_SKILL_REJECTED")
	}
	if section != "" {
		text, ok := d["content"].(string)
		if !ok || text == "" || len(text) > 16<<10 || d["section"] != section {
			return nil, harnessSkillBinding{}, harnessError("HARNESS_SKILL_REJECTED")
		}
	}
	return d, harnessSkillBinding{v, digest}, nil
}
func resolveHarnessSkills(ctx context.Context, p harnessPort, requests []harnessSkillRequest, prior map[string]harnessSkillBinding, initial bool) (map[string]harnessSkillBinding, map[string]any, error) {
	if !initial && len(prior) != len(requests) {
		return nil, nil, harnessError("HARNESS_SKILL_REJECTED")
	}
	bindings := map[string]harnessSkillBinding{}
	disclosures := []any{}
	for _, r := range requests {
		summary, binding, err := harnessSkillDisclosure(ctx, p, r.SkillID, "")
		if err != nil {
			return nil, nil, err
		}
		if !initial && prior[r.SkillID] != binding {
			return nil, nil, harnessError("HARNESS_SKILL_VERSION_CHANGED")
		}
		bindings[r.SkillID] = binding
		if initial {
			disclosures = append(disclosures, summary)
			for _, section := range r.Sections {
				content, next, err := harnessSkillDisclosure(ctx, p, r.SkillID, section)
				if err != nil {
					return nil, nil, err
				}
				if next != binding {
					return nil, nil, harnessError("HARNESS_SKILL_VERSION_CHANGED")
				}
				disclosures = append(disclosures, content)
			}
		}
	}
	var message map[string]any
	if initial && len(requests) > 0 {
		body, err := json.Marshal(map[string]any{"type": "skill_instructions", "instruction_trust": "untrusted_data", "skills": disclosures})
		if err != nil || len(body) > 16<<10 {
			return nil, nil, harnessError("HARNESS_SKILL_CONTEXT_LIMIT")
		}
		message = map[string]any{"role": "user", "content": string(body)}
	}
	return bindings, message, nil
}
