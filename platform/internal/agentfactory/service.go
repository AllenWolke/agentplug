package agentfactory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	semverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	protectedKeys = map[string]bool{
		"tenant_id": true, "department_id": true, "application_id": true, "agent_instance_id": true,
		"agent_id": true, "agent_version_id": true, "principal_type": true, "principal_id": true,
		"session_id": true, "run_id": true, "authorization_epoch": true, "trace_id": true,
		"parent_run_id": true, "delegation_depth": true, "scope": true, "policy": true,
		"policy_snapshot_hash": true, "identity": true, "permissions": true, "roles": true,
		"capabilities": true,
	}
)

type Service struct{ Store Store }

func (s Service) RegisterTemplate(ctx context.Context, scope Scope, actor Actor, in CreateTemplateRequest) (Template, error) {
	if err := scope.Validate(); err != nil || !safeID(in.TemplateID) || strings.TrimSpace(in.Name) != in.Name || in.Name == "" || len(in.Name) > 128 || len(in.Framework) > 64 {
		return Template{}, ErrInvalidRequest
	}
	language := strings.ToLower(strings.TrimSpace(in.Language))
	if language != "python" && language != "go" && language != "java" {
		return Template{}, ErrInvalidRequest
	}
	now := time.Now().UTC()
	id, err := newID()
	if err != nil {
		return Template{}, err
	}
	row := Template{ID: id, Scope: scope, TemplateID: in.TemplateID, Name: in.Name, Language: language, Framework: strings.TrimSpace(in.Framework), Status: StatusDraft, CreatedBy: actor.PrincipalID, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreateTemplate(ctx, row); err != nil {
		return Template{}, err
	}
	return row, nil
}

// RegisterVersion decodes only bounded upload metadata and stores the artifact digest, never its body.
// RegisterVersion 只解码有界上传内容并保存制品摘要，绝不保存制品正文。
func (s Service) RegisterVersion(ctx context.Context, scope Scope, actor Actor, definitionID string, in CreateTemplateVersionRequest) (TemplateVersion, error) {
	if err := scope.Validate(); err != nil || !safeID(definitionID) || !semverPattern.MatchString(in.Version) || len(in.Version) > 64 || !safeArtifactURI(in.ArtifactURI) {
		return TemplateVersion{}, ErrInvalidRequest
	}
	if len(in.ArtifactBase64) == 0 || len(in.ArtifactBase64) > base64.StdEncoding.EncodedLen(maxArtifactBytes) {
		return TemplateVersion{}, ErrInvalidRequest
	}
	artifact, err := base64.StdEncoding.DecodeString(in.ArtifactBase64)
	if err != nil || len(artifact) == 0 || len(artifact) > maxArtifactBytes {
		return TemplateVersion{}, ErrInvalidRequest
	}
	definition, err := s.Store.GetTemplate(ctx, scope, definitionID)
	if err != nil {
		return TemplateVersion{}, err
	}
	sum := sha256.Sum256(artifact)
	contentHash := hex.EncodeToString(sum[:])
	lockSum := sha256.Sum256([]byte(in.Version + ":" + contentHash))
	id, err := newID()
	if err != nil {
		return TemplateVersion{}, err
	}
	row := TemplateVersion{ID: id, Scope: scope, DefinitionID: definition.ID, SemanticVersion: in.Version, ArtifactURI: strings.TrimSpace(in.ArtifactURI), ContentHash: contentHash, LockHash: hex.EncodeToString(lockSum[:]), ArtifactSize: len(artifact), CreatedBy: actor.PrincipalID, CreatedAt: time.Now().UTC()}
	if err := s.Store.CreateTemplateVersion(ctx, row); err != nil {
		return TemplateVersion{}, err
	}
	return row, nil
}

func (s Service) CreateMapping(ctx context.Context, scope Scope, actor Actor, in CreateMappingRequest) (Mapping, error) {
	if err := scope.Validate(); err != nil {
		return Mapping{}, ErrInvalidRequest
	}
	doc, normalized, err := compileDocument(in.Spec)
	if err != nil {
		return Mapping{}, ErrInvalidRequest
	}
	if in.MappingID == "" {
		in.MappingID = doc.MappingID
	}
	if in.Kind == "" {
		in.Kind = doc.Kind
	}
	if !safeID(in.MappingID) || !allowedMappingKind(in.Kind) || doc.MappingID != in.MappingID || doc.Kind != in.Kind {
		return Mapping{}, ErrInvalidRequest
	}
	if in.ID == "" {
		in.ID, err = newID()
		if err != nil {
			return Mapping{}, err
		}
	}
	if !safeID(in.ID) {
		return Mapping{}, ErrInvalidRequest
	}
	now := time.Now().UTC()
	row := Mapping{ID: in.ID, Scope: scope, MappingID: doc.MappingID, Kind: doc.Kind, Status: StatusDraft, Spec: normalized, ContentHash: doc.Hash, Revision: 1, CreatedBy: actor.PrincipalID, CreatedAt: now, UpdatedAt: now}
	if err = s.Store.CreateMapping(ctx, row); err != nil {
		return Mapping{}, err
	}
	return row, nil
}

func (s Service) DryRun(ctx context.Context, scope Scope, actor Actor, id string, req DryRunRequest) (DryRunResult, error) {
	if err := scope.Validate(); err != nil || !safeID(id) {
		return DryRunResult{}, ErrInvalidRequest
	}
	fixture, err := canonicalJSON(req)
	if err != nil || len(fixture) > maxFixtureBytes {
		return DryRunResult{}, ErrInvalidRequest
	}
	row, err := s.Store.GetMapping(ctx, scope, id)
	if err != nil {
		return DryRunResult{}, err
	}
	doc, _, compileErr := compileDocument(row.Spec)
	var output DryRunResult
	status := "passed"
	checkCount := 0
	var resultBytes []byte
	if compileErr == nil {
		output, compileErr = doc.Evaluate(req, row.Revision)
	}
	if compileErr != nil {
		status = "failed"
		output = DryRunResult{}
	} else {
		checkCount = output.Steps
		resultBytes, err = canonicalJSON(struct {
			Request  map[string]any `json:"request"`
			Response map[string]any `json:"response"`
		}{output.Request, output.Response})
		if err != nil {
			return DryRunResult{}, err
		}
	}
	fixtureDigest := sha256.Sum256(fixture)
	resultDigest := sha256.Sum256(resultBytes)
	evidenceID, idErr := newID()
	if idErr != nil {
		return DryRunResult{}, idErr
	}
	evidence := ConformanceEvidence{ID: evidenceID, Scope: scope, MappingID: row.ID, MappingRevision: row.Revision, MappingHash: row.ContentHash, FixtureHash: hex.EncodeToString(fixtureDigest[:]), ResultHash: hex.EncodeToString(resultDigest[:]), Status: status, CheckCount: checkCount, CreatedBy: actor.PrincipalID, CreatedAt: time.Now().UTC()}
	if saveErr := s.Store.SaveEvidence(ctx, evidence); saveErr != nil {
		return DryRunResult{}, saveErr
	}
	if compileErr != nil {
		return DryRunResult{}, compileErr
	}
	output.Evidence = evidence
	// The browser's legacy response field named input is the mapped request, not a copy of arbitrary caller data.
	// 浏览器旧响应中的 input 实际指映射后的请求，避免复制任意调用方原始数据。
	output.Input = output.Request
	return output, nil
}

func (s Service) PublishMapping(ctx context.Context, scope Scope, id string, expected uint64) (Mapping, error) {
	if err := scope.Validate(); err != nil || !safeID(id) || expected == 0 {
		return Mapping{}, ErrInvalidRequest
	}
	return s.Store.PublishMapping(ctx, scope, id, expected)
}

func (s Service) ListEvidence(ctx context.Context, scope Scope, id string, limit int) ([]ConformanceEvidence, error) {
	if err := scope.Validate(); err != nil || !safeID(id) {
		return nil, ErrInvalidRequest
	}
	return s.Store.ListEvidence(ctx, scope, id, clampLimit(limit))
}

// mappingDocument is the bounded and executable subset accepted by this module.
// mappingDocument 是本模块接受的有界可执行映射子集。
type mappingDocument struct {
	MappingID    string                     `json:"mapping_id"`
	Version      string                     `json:"version"`
	Kind         string                     `json:"kind"`
	Request      map[string]json.RawMessage `json:"request"`
	Response     map[string]json.RawMessage `json:"response"`
	Hash         string                     `json:"-"`
	requestExpr  map[string]*expression
	responseExpr map[string]*expression
}

type mappingEnvelope struct {
	MappingID string                     `json:"mapping_id"`
	Version   string                     `json:"version"`
	Kind      string                     `json:"kind"`
	Request   map[string]json.RawMessage `json:"request"`
	Response  map[string]json.RawMessage `json:"response"`
}

func compileDocument(raw []byte) (*mappingDocument, []byte, error) {
	if len(raw) == 0 || len(raw) > maxMappingBytes || rejectDuplicateKeys(raw) != nil {
		return nil, nil, ErrInvalidRequest
	}
	var object map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&object); err != nil || len(object) == 0 {
		return nil, nil, ErrInvalidRequest
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, ErrInvalidRequest
	}
	if apiVersionRaw := object["api_version"]; len(apiVersionRaw) > 0 {
		var canonical struct {
			APIVersion string `json:"api_version"`
			Metadata   struct {
				MappingID string `json:"mapping_id"`
				Version   string `json:"version"`
			} `json:"metadata"`
			Spec struct {
				UpstreamRef string `json:"upstream_ref"`
				Operations  map[string]struct {
					Request struct {
						Method  string                     `json:"method"`
						Path    string                     `json:"path"`
						Headers map[string]json.RawMessage `json:"headers"`
						Query   map[string]json.RawMessage `json:"query"`
						Body    struct {
							ContentType string                     `json:"content_type"`
							Object      map[string]json.RawMessage `json:"object"`
						} `json:"body"`
					} `json:"request"`
					Response struct {
						SuccessStatus []int             `json:"success_status"`
						Output        json.RawMessage   `json:"output"`
						Errors        []json.RawMessage `json:"errors"`
					} `json:"response"`
				} `json:"operations"`
			} `json:"spec"`
		}
		canonicalDecoder := json.NewDecoder(bytes.NewReader(raw))
		canonicalDecoder.DisallowUnknownFields()
		if canonicalDecoder.Decode(&canonical) != nil || canonical.APIVersion != "agent-mapping/v1" || canonical.Metadata.MappingID == "" || canonical.Metadata.Version == "" {
			return nil, nil, ErrInvalidRequest
		}
		invoke, ok := canonical.Spec.Operations["invoke"]
		if !ok || len(canonical.Spec.Operations) > 16 || !regexp.MustCompile(`^endpoint://[A-Za-z0-9._-]{1,128}$`).MatchString(canonical.Spec.UpstreamRef) || len(invoke.Request.Body.Object) == 0 || len(invoke.Response.Output) == 0 {
			return nil, nil, ErrInvalidRequest
		}
		method := strings.ToUpper(invoke.Request.Method)
		if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" || !strings.HasPrefix(invoke.Request.Path, "/") || strings.Contains(invoke.Request.Path, "..") {
			return nil, nil, ErrInvalidRequest
		}
		if len(invoke.Response.SuccessStatus) == 0 {
			return nil, nil, ErrInvalidRequest
		}
		for _, status := range invoke.Response.SuccessStatus {
			if status < 100 || status > 599 {
				return nil, nil, ErrInvalidRequest
			}
		}
		if _, err := compileSection(invoke.Request.Headers, "headers"); err != nil {
			return nil, nil, err
		}
		if _, err := compileSection(invoke.Request.Query, "query"); err != nil {
			return nil, nil, err
		}
		for _, failure := range invoke.Response.Errors {
			if !json.Valid(failure) {
				return nil, nil, ErrInvalidRequest
			}
		}
		canonicalRaw, err := canonicalJSON(canonical)
		if err != nil {
			return nil, nil, ErrInvalidRequest
		}
		canonicalRaw, err = canonicalizeJSONBytes(canonicalRaw)
		if err != nil {
			return nil, nil, ErrInvalidRequest
		}
		bodyRequest := invoke.Request.Body.Object
		response := map[string]json.RawMessage{"output": invoke.Response.Output}
		envelope := mappingEnvelope{MappingID: canonical.Metadata.MappingID, Version: canonical.Metadata.Version, Kind: "legacy-http", Request: bodyRequest, Response: response}
		compiled, _, err := compileFlatEnvelope(envelope, canonicalRaw)
		if err != nil {
			return nil, nil, err
		}
		return compiled, canonicalRaw, nil
	}
	var envelope mappingEnvelope
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(&envelope) != nil || !safeID(envelope.MappingID) || !semverPattern.MatchString(envelope.Version) || !allowedMappingKind(envelope.Kind) || len(envelope.Request) == 0 || len(envelope.Response) == 0 || len(envelope.Request)+len(envelope.Response) > 128 {
		return nil, nil, ErrInvalidRequest
	}
	canonical, err := canonicalJSON(envelope)
	if err != nil {
		return nil, nil, ErrInvalidRequest
	}
	canonical, err = canonicalizeJSONBytes(canonical)
	if err != nil {
		return nil, nil, ErrInvalidRequest
	}
	return compileFlatEnvelope(envelope, canonical)
}

func compileFlatEnvelope(envelope mappingEnvelope, normalized []byte) (*mappingDocument, []byte, error) {
	if !safeID(envelope.MappingID) || !semverPattern.MatchString(envelope.Version) || !allowedMappingKind(envelope.Kind) || len(envelope.Request) == 0 || len(envelope.Response) == 0 || len(envelope.Request)+len(envelope.Response) > 128 {
		return nil, nil, ErrInvalidRequest
	}
	requestExpr, err := compileSection(envelope.Request, "request")
	if err != nil {
		return nil, nil, err
	}
	responseExpr, err := compileSection(envelope.Response, "response")
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(normalized)
	doc := &mappingDocument{MappingID: envelope.MappingID, Version: envelope.Version, Kind: envelope.Kind, Request: envelope.Request, Response: envelope.Response, requestExpr: requestExpr, responseExpr: responseExpr, Hash: hex.EncodeToString(digest[:])}
	return doc, normalized, nil
}

type expression struct {
	Source      []string
	Constant    any
	HasConstant bool
	Required    bool
	MaxLength   int
	HasDefault  bool
	Default     any
	Convert     string
	Steps       int
	Untrusted   bool
}

func compileSection(section map[string]json.RawMessage, name string) (map[string]*expression, error) {
	compiled := make(map[string]*expression, len(section))
	for key, raw := range section {
		if !keyPattern.MatchString(key) {
			return nil, ErrInvalidRequest
		}
		expr, err := parseExpression(raw, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: %s.%s", ErrInvalidRequest, name, key)
		}
		if protectedKeys[key] && expr.Untrusted {
			return nil, ErrInvalidRequest
		}
		compiled[key] = expr
	}
	return compiled, nil
}

func parseExpression(raw []byte, depth int) (*expression, error) {
	if depth > 16 || len(raw) == 0 || len(raw) > maxMappingBytes {
		return nil, ErrInvalidRequest
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil, ErrInvalidRequest
	}
	result := &expression{Steps: 1}
	switch typed := value.(type) {
	case string:
		result.Source, result.Untrusted = parseSource(typed)
		if result.Source == nil {
			return nil, ErrInvalidRequest
		}
	case map[string]any:
		allowed := map[string]bool{"source": true, "const": true, "from_input": true, "from_context": true, "from_body": true, "required": true, "max_length": true, "default": true, "convert": true}
		for key := range typed {
			if !allowed[key] {
				return nil, ErrInvalidRequest
			}
		}
		sources := 0
		for _, field := range []struct{ name string }{{"source"}, {"from_input"}, {"from_context"}, {"from_body"}} {
			if rawValue, ok := typed[field.name]; ok {
				text, isString := rawValue.(string)
				if !isString {
					return nil, ErrInvalidRequest
				}
				if field.name != "source" {
					root := strings.TrimPrefix(field.name, "from_")
					if text == root {
						text = "payload"
					}
					text = root + "." + text
				}
				path, untrusted := parseSource(text)
				if path == nil {
					return nil, ErrInvalidRequest
				}
				result.Source, result.Untrusted = path, untrusted
				sources++
			}
		}
		if constant, ok := typed["const"]; ok {
			result.Constant, result.HasConstant = constant, true
			sources++
		}
		if sources != 1 {
			return nil, ErrInvalidRequest
		}
		if required, ok := typed["required"]; ok {
			flag, ok := required.(bool)
			if !ok {
				return nil, ErrInvalidRequest
			}
			result.Required = flag
		}
		if maxLength, ok := typed["max_length"]; ok {
			number, ok := maxLength.(json.Number)
			if !ok {
				return nil, ErrInvalidRequest
			}
			parsed, err := strconv.Atoi(number.String())
			if err != nil || parsed < 1 || parsed > 1<<20 {
				return nil, ErrInvalidRequest
			}
			result.MaxLength = parsed
		}
		if value, ok := typed["default"]; ok {
			result.Default, result.HasDefault = value, true
		}
		if convert, ok := typed["convert"]; ok {
			name, ok := convert.(string)
			if !ok || !map[string]bool{"to_string": true, "to_int": true, "to_float": true, "to_bool": true}[name] {
				return nil, ErrInvalidRequest
			}
			result.Convert = name
		}
	default:
		return nil, ErrInvalidRequest
	}
	return result, nil
}

func parseSource(value string) ([]string, bool) {
	if len(value) > 4096 || strings.ContainsAny(value, "[](){}\\") {
		return nil, false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || (parts[0] != "input" && parts[0] != "context" && parts[0] != "body") {
		return nil, false
	}
	for _, part := range parts[1:] {
		if part == "" || len(part) > 128 || strings.ContainsAny(part, "\x00\r\n\t") {
			return nil, false
		}
	}
	return parts, parts[0] == "input" || parts[0] == "body"
}

func (d *mappingDocument) Evaluate(req DryRunRequest, revision uint64) (DryRunResult, error) {
	result := DryRunResult{MappingID: d.MappingID, Version: d.Version, Revision: revision, Request: map[string]any{}, Response: map[string]any{}, Input: req.Input}
	steps := 0
	for _, section := range []struct {
		name          string
		exprs         map[string]*expression
		dest          map[string]any
		context, body map[string]any
	}{{"request", d.requestExpr, result.Request, req.Context, nil}, {"response", d.responseExpr, result.Response, req.Context, req.Body}} {
		keys := make([]string, 0, len(section.exprs))
		for key := range section.exprs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value, count, err := evalExpression(section.exprs[key], req.Input, section.context, section.body)
			steps += count
			if steps > 1024 {
				return DryRunResult{}, ErrInvalidRequest
			}
			if err != nil {
				return DryRunResult{}, fmt.Errorf("%s.%s: %w", section.name, key, err)
			}
			if value != nil {
				section.dest[key] = value
			}
		}
	}
	result.Steps = steps
	return result, nil
}

func evalExpression(expr *expression, input, context, body map[string]any) (any, int, error) {
	steps := expr.Steps
	var value any
	if expr.HasConstant {
		value = expr.Constant
	} else if len(expr.Source) > 0 {
		var root map[string]any
		switch expr.Source[0] {
		case "input":
			root = input
		case "context":
			root = context
		case "body":
			root = body
		}
		value = lookup(root, expr.Source[1:])
	}
	if value == nil && expr.HasDefault {
		value = expr.Default
	}
	if value == nil && expr.Required {
		return nil, steps, errors.New("required value is missing")
	}
	if value != nil && expr.MaxLength > 0 {
		text, ok := value.(string)
		if !ok || len(text) > expr.MaxLength {
			return nil, steps, errors.New("value violates max_length")
		}
	}
	if value != nil && expr.Convert != "" {
		converted, err := convert(expr.Convert, value)
		if err != nil {
			return nil, steps, err
		}
		value = converted
	}
	return value, steps, nil
}

func lookup(root map[string]any, path []string) any {
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

func convert(name string, value any) (any, error) {
	switch name {
	case "to_string":
		return fmt.Sprint(value), nil
	case "to_int":
		var f float64
		var err error
		switch v := value.(type) {
		case json.Number:
			f, err = v.Float64()
		case string:
			f, err = strconv.ParseFloat(strings.TrimSpace(v), 64)
		case float64:
			f = v
		default:
			err = ErrInvalidRequest
		}
		if err != nil || math.Trunc(f) != f {
			return nil, ErrInvalidRequest
		}
		return int64(f), nil
	case "to_float":
		switch v := value.(type) {
		case json.Number:
			return v.Float64()
		case string:
			return strconv.ParseFloat(strings.TrimSpace(v), 64)
		case float64:
			return v, nil
		default:
			return nil, ErrInvalidRequest
		}
	case "to_bool":
		switch v := value.(type) {
		case bool:
			return v, nil
		case string:
			return strconv.ParseBool(strings.TrimSpace(v))
		case json.Number:
			f, e := v.Float64()
			return f != 0, e
		default:
			return nil, ErrInvalidRequest
		}
	default:
		return nil, ErrInvalidRequest
	}
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := scanJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}
func scanJSONValue(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidRequest
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyToken, e := dec.Token()
			if e != nil {
				return e
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return ErrInvalidRequest
			}
			seen[key] = true
			if e = scanJSONValue(dec, depth+1); e != nil {
				return e
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err = scanJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return ErrInvalidRequest
}

func canonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }
func canonicalizeJSONBytes(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ErrInvalidRequest
	}
	return json.Marshal(value)
}
func safeID(value string) bool { return keyPattern.MatchString(value) }
func allowedMappingKind(value string) bool {
	return value == "legacy-http" || value == "grpc" || value == "process" || value == "sidecar"
}
func safeArtifactURI(value string) bool {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "oci" {
		return u.Host != "" && strings.Trim(u.Path, "/") != ""
	}
	return (u.Scheme == "https" || u.Scheme == "artifact") && u.Host != "" && strings.Trim(u.Path, "/") != ""
}
func clampLimit(value int) int {
	if value < 1 {
		return 50
	}
	if value > 200 {
		return 200
	}
	return value
}

func hashJSON(value any) string {
	encoded, _ := canonicalJSON(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
