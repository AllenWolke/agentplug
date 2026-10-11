// Package mapping interprets the small, declarative adapter mapping language.
// mapping 包只解释有限 DSL，不执行脚本或动态代码。
package mapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type Expression struct {
	Source    string `json:"source,omitempty"`
	Const     any    `json:"const,omitempty"`
	Convert   string `json:"convert,omitempty"`
	Required  bool   `json:"required,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
	Default   any    `json:"default,omitempty"`
	// HasDefault preserves an explicit JSON null across the durable target
	// boundary. / HasDefault 让异步 target 持久化保留显式 JSON null。
	HasDefault bool `json:"has_default,omitempty"`
}
type Plan struct {
	MappingID string                `json:"mapping_id"`
	Version   string                `json:"version"`
	Kind      string                `json:"kind"`
	Revision  uint64                `json:"revision,omitempty"`
	Request   map[string]Expression `json:"request"`
	Response  map[string]Expression `json:"response"`
	Hash      string                `json:"hash"`
}

// expressionFields is the fixed grammar of one compact expression. It mirrors
// the Harness plan schema so the adapter accepts exactly what the control plane
// published and nothing more. / expressionFields 是紧凑表达式的固定语法，与
// Harness 计划结构保持一致。
var expressionFields = map[string]bool{
	"source": true, "const": true, "required": true,
	"max_length": true, "default": true, "convert": true,
}

// convertFunctions is the pure-function allow-list; there is no implicit
// coercion anywhere else. / convertFunctions 是纯函数白名单，其余位置无隐式转换。
var convertFunctions = map[string]bool{"to_string": true, "to_int": true, "to_float": true, "to_bool": true}

// maxApplySteps bounds one Apply section so a wide plan cannot exceed the
// execution budget fixed by the control plane. / maxApplySteps 约束单段 Apply，
// 宽计划无法突破控制面固定的执行预算。
const maxApplySteps = 1024

// DecodeWirePlan accepts only the immutable plan emitted by Harness. It is an
// interpreter boundary, not a DSL compiler; source normalization and compile
// remain control-plane/Harness responsibilities. / DecodeWirePlan 只接受
// Harness 生成的不可变计划，不是 DSL 编译器；规范化和编译由控制面/Harness
// 完成。
func DecodeWirePlan(raw any, expectedHash string) (*Plan, error) {
	if raw == nil {
		return nil, errors.New("mapping plan is missing")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, errors.New("mapping plan is invalid")
	}
	return DecodeWirePlanBody(encoded, expectedHash)
}

// DecodeWirePlanBody is DecodeWirePlan over already-encoded bytes, so a signed
// plan is verified and interpreted over the very same bytes the signer covered.
// DecodeWirePlanBody 是 DecodeWirePlan 的字节版本，使签名计划在「签名者覆盖的
// 同一份字节」上完成校验与解释。
func DecodeWirePlanBody(encoded []byte, expectedHash string) (*Plan, error) {
	if len(encoded) == 0 {
		return nil, errors.New("mapping plan is missing")
	}
	var wire struct {
		MappingID string                     `json:"mapping_id"`
		Version   string                     `json:"version"`
		Kind      string                     `json:"kind"`
		Revision  uint64                     `json:"revision"`
		Request   map[string]json.RawMessage `json:"request"`
		Response  map[string]json.RawMessage `json:"response"`
		Hash      string                     `json:"hash"`
	}
	dec := json.NewDecoder(strings.NewReader(string(encoded)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || wire.MappingID == "" || wire.Version == "" || wire.Kind != "legacy-http" || wire.Hash == "" || len(wire.Request) == 0 || len(wire.Response) == 0 {
		return nil, errors.New("invalid immutable mapping plan")
	}
	if expectedHash != "" && wire.Hash != expectedHash {
		return nil, errors.New("mapping plan hash mismatch")
	}
	plan := &Plan{MappingID: wire.MappingID, Version: wire.Version, Kind: wire.Kind, Revision: wire.Revision, Hash: wire.Hash, Request: map[string]Expression{}, Response: map[string]Expression{}}
	for key, value := range wire.Request {
		expression, parseErr := expr(value)
		if parseErr != nil {
			return nil, fmt.Errorf("request.%s: %w", key, parseErr)
		}
		plan.Request[key] = expression
	}
	for key, value := range wire.Response {
		expression, parseErr := expr(value)
		if parseErr != nil {
			return nil, fmt.Errorf("response.%s: %w", key, parseErr)
		}
		plan.Response[key] = expression
	}
	return plan, nil
}

func expr(raw []byte) (Expression, error) {
	var source string
	if json.Unmarshal(raw, &source) == nil {
		parts := strings.Split(source, ".")
		if len(parts) < 2 || (parts[0] != "input" && parts[0] != "context" && parts[0] != "body") {
			return Expression{}, errors.New("source must start with input., context. or body.")
		}
		for _, part := range parts[1:] {
			if part == "" || strings.ContainsAny(part, "[](){}\\\\") {
				return Expression{}, errors.New("unsafe source path")
			}
		}
		return Expression{Source: source}, nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) == 0 {
		return Expression{}, errors.New("expression must be source or const")
	}
	for key := range object {
		if !expressionFields[key] {
			return Expression{}, fmt.Errorf("unknown expression field %s", key)
		}
	}
	if value, ok := object["const"]; ok {
		var c any
		if json.Unmarshal(value, &c) != nil {
			return Expression{}, errors.New("invalid const")
		}
		return expressionOptions(Expression{Const: c}, object)
	}
	if value, ok := object["source"]; ok {
		var source string
		if json.Unmarshal(value, &source) != nil {
			return Expression{}, errors.New("source must be a string")
		}
		return expressionOptions(Expression{Source: source}, object)
	}
	return Expression{}, errors.New("unknown expression field")
}

func expressionOptions(expression Expression, object map[string]json.RawMessage) (Expression, error) {
	if expression.Source != "" {
		parts := strings.Split(expression.Source, ".")
		if len(parts) < 2 || (parts[0] != "input" && parts[0] != "context" && parts[0] != "body") {
			return Expression{}, errors.New("source must start with input., context. or body.")
		}
		for _, part := range parts[1:] {
			if part == "" || strings.ContainsAny(part, "[](){}\\\\") {
				return Expression{}, errors.New("unsafe source path")
			}
		}
	}
	if value, ok := object["required"]; ok && json.Unmarshal(value, &expression.Required) != nil {
		return Expression{}, errors.New("required must be boolean")
	}
	if value, ok := object["max_length"]; ok && (json.Unmarshal(value, &expression.MaxLength) != nil || expression.MaxLength < 1 || expression.MaxLength > 1<<20) {
		return Expression{}, errors.New("max_length must be between 1 and 1048576")
	}
	if value, ok := object["convert"]; ok {
		var name string
		if json.Unmarshal(value, &name) != nil || !convertFunctions[name] {
			return Expression{}, errors.New("unsupported convert function")
		}
		expression.Convert = name
	}
	if value, ok := object["default"]; ok {
		if json.Unmarshal(value, &expression.Default) != nil {
			return Expression{}, errors.New("default must be valid JSON")
		}
		expression.HasDefault = true
	}
	return expression, nil
}

// Apply evaluates a compiled section against the request/upstream maps. Missing
// values are omitted, defaults fill gaps, and a violated constraint fails closed
// with a stable error instead of forwarding a half-built payload.
// Apply 求值已编译段落：缺失值省略、默认值补齐，违反约束则以稳定错误失败关闭，
// 不转发半成品负载。
func Apply(spec map[string]Expression, input, context, body map[string]any) (map[string]any, error) {
	steps := 0
	out := make(map[string]any, len(spec))
	for _, key := range sortedExpressionKeys(spec) {
		expression := spec[key]
		value := applyExpression(expression, input, context, body)
		steps++
		if steps > maxApplySteps {
			return nil, fmt.Errorf("mapping exceeded %d execution steps", maxApplySteps)
		}
		if expression.Convert != "" {
			converted, err := convertValue(expression.Convert, value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			value = converted
		}
		if isMissing(value) && expression.HasDefault {
			value = expression.Default
		}
		if isMissing(value) {
			if expression.Required {
				return nil, fmt.Errorf("%s: required value is missing", key)
			}
			continue
		}
		if expression.MaxLength > 0 {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%s: max_length requires a string value", key)
			}
			if len(text) > expression.MaxLength {
				return nil, fmt.Errorf("%s: value exceeds max_length %d", key, expression.MaxLength)
			}
		}
		out[key] = value
	}
	return out, nil
}

func applyExpression(expression Expression, input, context, body map[string]any) any {
	if expression.Source == "" {
		return expression.Const
	}
	parts := strings.Split(expression.Source, ".")
	var root map[string]any
	switch parts[0] {
	case "input":
		root = input
	case "context":
		root = context
	case "body":
		root = body
	default:
		return nil
	}
	return lookupPath(root, parts[1:])
}

// lookupPath walks dotted keys without ever panicking on a non-object segment.
// lookupPath 用点分键逐层取值，遇到非对象段不会 panic。
func lookupPath(root map[string]any, path []string) any {
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

// isMissing reports whether a value counts as absent; only explicit null or an
// absent path is missing. / isMissing 判断取值是否缺失，只有 null 或路径不存在算缺失。
func isMissing(value any) bool {
	return value == nil
}

// convertValue applies the pure-function allow-list, returning a stable error for
// an impossible conversion. / convertValue 应用纯函数白名单，无法转换时返回稳定错误。
func convertValue(name string, value any) (any, error) {
	if isMissing(value) {
		return nil, nil
	}
	switch name {
	case "to_string":
		switch typed := value.(type) {
		case string:
			return typed, nil
		case json.Number:
			return typed.String(), nil
		case bool:
			return strconv.FormatBool(typed), nil
		default:
			return fmt.Sprint(typed), nil
		}
	case "to_int":
		number, err := toFloat(value)
		if err != nil || math.Trunc(number) != number {
			return nil, errors.New("convert to_int: value is not an integer")
		}
		return int64(number), nil
	case "to_float":
		number, err := toFloat(value)
		if err != nil {
			return nil, errors.New("convert to_float: value is not a number")
		}
		return number, nil
	case "to_bool":
		switch typed := value.(type) {
		case bool:
			return typed, nil
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
			if err != nil {
				return nil, errors.New("convert to_bool: value is not a boolean")
			}
			return parsed, nil
		default:
			number, err := toFloat(value)
			if err != nil {
				return nil, errors.New("convert to_bool: value is not a boolean")
			}
			return number != 0, nil
		}
	default:
		return nil, fmt.Errorf("unsupported convert function %q", name)
	}
}

func toFloat(value any) (float64, error) {
	switch typed := value.(type) {
	case json.Number:
		return typed.Float64()
	case float64:
		return typed, nil
	case int:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(typed), 64)
	default:
		return 0, errors.New("not a number")
	}
}

func sortedExpressionKeys(spec map[string]Expression) []string {
	keys := make([]string, 0, len(spec))
	for key := range spec {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
