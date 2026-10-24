package prompt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/modelgateway"
)

var ErrProgram = errors.New("invalid published prompt program or stage")
var stageName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var modeName = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
var inputCount = regexp.MustCompile(`\{\{input\.([A-Za-z_][A-Za-z0-9_]{0,63})\.count\}\}`)

type Program struct {
	Version        string            `json:"version"`
	Instructions   string            `json:"instructions"`
	DefaultStage   string            `json:"default_stage"`
	ExecutionModes []string          `json:"execution_modes"`
	Stages         map[string]string `json:"stages"`
}

// Legacy templates remain literal. Programs opt in through immutable modes;
// neither a caller's stage body nor a caller-authored system prompt is accepted.
func ParseProgram(template string) (*Program, error) {
	var header struct {
		Version string `json:"version"`
	}
	if json.Unmarshal([]byte(template), &header) != nil || header.Version != "agentplug-prompt-program/v1" {
		return nil, nil
	}
	var p Program
	d := json.NewDecoder(strings.NewReader(template))
	d.DisallowUnknownFields()
	var trailing any
	if d.Decode(&p) != nil || d.Decode(&trailing) != io.EOF || strings.TrimSpace(p.Instructions) == "" || p.ExecutionModes == nil || len(p.ExecutionModes) > 8 || len(p.Stages) < 1 || len(p.Stages) > 8 {
		return nil, ErrProgram
	}
	seen := map[string]bool{}
	for _, mode := range p.ExecutionModes {
		if !modeName.MatchString(mode) || seen[mode] {
			return nil, ErrProgram
		}
		seen[mode] = true
	}
	for stage, body := range p.Stages {
		if !stageName.MatchString(stage) || strings.TrimSpace(body) == "" {
			return nil, ErrProgram
		}
	}
	if _, ok := p.Stages[p.DefaultStage]; !ok {
		return nil, ErrProgram
	}
	return &p, nil
}

func (p *Program) HasMode(mode string) bool {
	if p == nil {
		return false
	}
	for _, current := range p.ExecutionModes {
		if current == mode {
			return true
		}
	}
	return false
}

// StageMessages keeps the full published template for fingerprints and SDK
// validation. Only the platform's provider boundary may render a selected stage.
func StageMessages(template, mode, stage string, input any) ([]modelgateway.Message, bool, error) {
	p, err := ParseProgram(template)
	if err != nil {
		return nil, false, err
	}
	if !p.HasMode(mode) {
		return nil, false, nil
	}
	if _, ok := p.Stages[stage]; !ok {
		return nil, true, ErrProgram
	}
	raw, err := json.Marshal(map[string]any{"stage": stage, "input": input})
	if err != nil {
		return nil, true, ErrProgram
	}
	return []modelgateway.Message{{Role: "system", Content: template}, {Role: "user", Content: string(raw)}}, true, nil
}

// InvocationMessages renders only an approved stage and only when the release
// explicitly opts in. Original messages and policy hashes remain the durable
// command identity. Tool calls, evidence and user content remain unchanged.
func InvocationMessages(template string, messages []modelgateway.Message) ([]modelgateway.Message, error) {
	p, err := ParseProgram(template)
	if err != nil {
		return nil, err
	}
	if !p.HasMode("prompt-stage-render/v1") {
		return messages, nil
	}
	if len(messages) == 0 {
		return nil, ErrProgram
	}
	start := 0
	if messages[0].Role == "system" {
		if messages[0].Content != template || len(messages[0].ToolCalls) != 0 {
			return nil, ErrProgram
		}
		start = 1
	}
	stage := p.DefaultStage
	var stageInput map[string]json.RawMessage
	for i := start; i < len(messages); i++ {
		if messages[i].Role == "system" {
			return nil, ErrProgram
		}
		if messages[i].Role != "user" {
			continue
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal([]byte(messages[i].Content), &envelope) != nil {
			continue
		}
		selected, has := envelope["stage"]
		if !has {
			continue
		}
		var name string
		var input map[string]json.RawMessage
		if len(envelope) != 2 || json.Unmarshal(selected, &name) != nil || json.Unmarshal(envelope["input"], &input) != nil || input == nil {
			return nil, ErrProgram
		}
		if _, ok := p.Stages[name]; !ok {
			return nil, ErrProgram
		}
		stage = name
		stageInput = input
	}
	stageBody, err := renderInputCounts(p.Stages[stage], stageInput)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	body.WriteString(p.Instructions)
	body.WriteString("\nPublished stage: ")
	body.WriteString(stage)
	body.WriteString("\n")
	body.WriteString(stageBody)
	out := []modelgateway.Message{{Role: "system", Content: body.String()}}
	return append(out, messages[start:]...), nil
}

// Only a published template may request an array cardinality. Array contents
// never enter system instructions; the durable envelope remains unchanged.
// The same rendering is used by input preflight and the actual provider send.
func renderInputCounts(body string, input map[string]json.RawMessage) (string, error) {
	var invalid bool
	result := inputCount.ReplaceAllStringFunc(body, func(token string) string {
		field := inputCount.FindStringSubmatch(token)[1]
		var values []json.RawMessage
		if json.Unmarshal(input[field], &values) != nil || values == nil || len(values) > 1024 {
			invalid = true
			return token
		}
		return strconv.Itoa(len(values))
	})
	if invalid {
		return "", ErrProgram
	}
	return result, nil
}
