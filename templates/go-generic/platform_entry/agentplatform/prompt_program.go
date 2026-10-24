package agentplatform

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

type PromptProgram struct {
	Version        string            `json:"version"`
	Instructions   string            `json:"instructions,omitempty"`
	DefaultStage   string            `json:"default_stage,omitempty"`
	ExecutionModes []string          `json:"execution_modes"`
	Stages         map[string]string `json:"stages"`
}

func ParsePromptProgram(template string) (PromptProgram, error) {
	legacy := PromptProgram{Version: "legacy-prompt", ExecutionModes: []string{}, Stages: map[string]string{}}
	if strings.TrimSpace(template) == "" {
		return legacy, publicError("PROMPT_PROGRAM_REJECTED")
	}
	var header struct {
		Version string `json:"version"`
	}
	if json.Unmarshal([]byte(template), &header) != nil || header.Version != "agentplug-prompt-program/v1" {
		return legacy, nil
	}
	var value PromptProgram
	decoder := json.NewDecoder(strings.NewReader(template))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || strings.TrimSpace(value.Instructions) == "" || value.ExecutionModes == nil || len(value.ExecutionModes) > 8 || len(value.Stages) < 1 || len(value.Stages) > 8 {
		return legacy, publicError("PROMPT_PROGRAM_REJECTED")
	}
	seen := map[string]bool{}
	modeName := regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	stageName := regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	for _, mode := range value.ExecutionModes {
		if !modeName.MatchString(mode) || seen[mode] {
			return legacy, publicError("PROMPT_PROGRAM_REJECTED")
		}
		seen[mode] = true
	}
	for stage, body := range value.Stages {
		if !stageName.MatchString(stage) || strings.TrimSpace(body) == "" {
			return legacy, publicError("PROMPT_PROGRAM_REJECTED")
		}
	}
	if _, exists := value.Stages[value.DefaultStage]; !exists {
		return legacy, publicError("PROMPT_PROGRAM_REJECTED")
	}
	return value, nil
}

// StageMessages selects trusted stage metadata as user data. The caller keeps
// the entire immutable published template in its original system message.
func (p PromptProgram) StageMessages(stage string, payload map[string]any) ([]map[string]any, error) {
	if p.Version != "agentplug-prompt-program/v1" || p.Stages[stage] == "" || payload == nil {
		return nil, publicError("PROMPT_STAGE_REJECTED")
	}
	if _, exists := payload["stage"]; exists {
		return nil, publicError("PROMPT_STAGE_REJECTED")
	}
	raw, err := publicJSON(map[string]any{"stage": stage, "input": payload})
	if err != nil {
		return nil, err
	}
	return []map[string]any{{"role": "user", "content": string(bytes.TrimSpace(raw))}}, nil
}
