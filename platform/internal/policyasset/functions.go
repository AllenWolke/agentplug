package policyasset

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"

	"github.com/google/jsonschema-go/jsonschema"
)

// FunctionDefinition is immutable published policy. Name is the vendor wire
// name; ToolName is the independently authorized platform tool identity.
type FunctionDefinition struct {
	Name        string          `json:"name"`
	ToolName    string          `json:"tool_name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

var functionName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`)
var ErrFunctionDenied = errors.New("function is not permitted by published policy")

func (p ToolPolicy) ValidateFunctions() error {
	if len(p.Functions) > 32 {
		return ErrFunctionDenied
	}
	seen := map[string]bool{}
	for _, f := range p.Functions {
		if !functionName.MatchString(f.Name) || seen[f.Name] || !slices.Contains(p.AllowedTools, f.ToolName) || f.ToolName == "" || len(f.Description) > 4096 {
			return ErrFunctionDenied
		}
		seen[f.Name] = true
		if _, err := f.schema(); err != nil {
			return ErrFunctionDenied
		}
	}
	return nil
}

func (f FunctionDefinition) schema() (*jsonschema.Resolved, error) {
	if len(f.Parameters) == 0 || len(f.Parameters) > 16384 {
		return nil, ErrFunctionDenied
	}
	var object map[string]any
	if json.Unmarshal(f.Parameters, &object) != nil || object["type"] != "object" {
		return nil, ErrFunctionDenied
	}
	var schema jsonschema.Schema
	if json.Unmarshal(f.Parameters, &schema) != nil {
		return nil, ErrFunctionDenied
	}
	// A nil Loader rejects remote references; policy schemas cannot cause egress.
	return schema.Resolve(&jsonschema.ResolveOptions{})
}

func (p ToolPolicy) ValidateFunctionArguments(name string, arguments json.RawMessage) (string, error) {
	if p.ValidateFunctions() != nil || len(arguments) == 0 || len(arguments) > 65536 {
		return "", ErrFunctionDenied
	}
	for _, f := range p.Functions {
		if f.Name != name {
			continue
		}
		var value map[string]any
		if json.Unmarshal(arguments, &value) != nil || value == nil {
			return "", ErrFunctionDenied
		}
		schema, err := f.schema()
		if err != nil || schema.Validate(value) != nil {
			return "", ErrFunctionDenied
		}
		return f.ToolName, nil
	}
	return "", ErrFunctionDenied
}
