package evaluationproduct

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

const metricRunnerPath = "/v1/metrics:execute"
const metricRunnerMaxBytes = 2 << 20

// RemoteMetricEvaluator sends retrieval, citation, grounding, and signed
// domain-plugin metrics to the isolated Metric Runner. Only the three small
// scalar metrics remain in-process; arbitrary case JSON is never sent to a
// plugin, only the fields selected by the published formula.
// RemoteMetricEvaluator 将检索、引用、接地和已签名领域插件指标送到隔离 Metric Runner。
// 仅三种简单标量指标在进程内执行；任意用例 JSON 不会发给插件，只发送已发布公式选择的字段。
type RemoteMetricEvaluator struct {
	URL     string
	Token   string
	Timeout time.Duration
	Client  *http.Client
}

type remoteMetricFormula struct {
	GroundingTarget      string             `json:"grounding_target,omitempty"`
	InputRelevantField   string             `json:"input_relevant_field,omitempty"`
	OutputRankedField    string             `json:"output_ranked_field,omitempty"`
	K                    int                `json:"k,omitempty"`
	InputExpectedField   string             `json:"input_expected_field,omitempty"`
	OutputActualField    string             `json:"output_actual_field,omitempty"`
	OutputCitationsField string             `json:"output_citations_field,omitempty"`
	InputCitationsField  string             `json:"input_citations_field,omitempty"`
	OutputClaimsField    string             `json:"output_claims_field,omitempty"`
	InputTotalField      string             `json:"input_total_field,omitempty"`
	OutputCorrectField   string             `json:"output_correct_field,omitempty"`
	Gate                 *metricGateFormula `json:"gate,omitempty"`
}

type metricGateFormula struct {
	MinEntailment    float64 `json:"min_entailment"`
	RequireAllClaims bool    `json:"require_all_claims"`
	ExpectedRevision string  `json:"expected_revision,omitempty"`
	FailOnUnknown    bool    `json:"fail_on_unknown"`
}

type metricRunnerAdmission struct {
	SignatureVerified bool   `json:"signature_verified"`
	Network           string `json:"network"`
	SecretAccess      bool   `json:"secret_access"`
	MaxOutputBytes    int    `json:"max_output_bytes"`
	MaxSeconds        int    `json:"max_seconds"`
	MaxPIDs           int    `json:"max_pids"`
}

type metricRunnerRequest struct {
	Metric        string                `json:"metric"`
	Version       string                `json:"version"`
	FormulaHash   string                `json:"formula_hash"`
	Plugin        string                `json:"plugin,omitempty"`
	PluginVersion string                `json:"plugin_version,omitempty"`
	PluginDigest  string                `json:"plugin_digest,omitempty"`
	Relevant      []string              `json:"relevant,omitempty"`
	Ranked        []string              `json:"ranked,omitempty"`
	K             int                   `json:"k,omitempty"`
	Total         int                   `json:"total,omitempty"`
	Correct       int                   `json:"correct,omitempty"`
	Citations     []metricCitation      `json:"citations,omitempty"`
	Claims        []metricClaim         `json:"claims,omitempty"`
	Gate          metricGateFormula     `json:"gate,omitempty"`
	MinSamples    int                   `json:"min_samples"`
	Admission     metricRunnerAdmission `json:"admission"`
}

type metricCitation struct {
	ID       string `json:"id"`
	Revision string `json:"revision,omitempty"`
	Source   string `json:"source,omitempty"`
	Content  string `json:"content,omitempty"`
}

type metricClaim struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	CitationIDs []string `json:"citation_ids"`
}

type metricRunnerResponse struct {
	MetricID    string         `json:"metric_id"`
	Version     string         `json:"version"`
	Kind        string         `json:"kind,omitempty"`
	FormulaHash string         `json:"formula_hash"`
	Status      string         `json:"status"`
	Code        string         `json:"code,omitempty"`
	Message     string         `json:"message,omitempty"`
	Numerator   float64        `json:"numerator"`
	Denominator float64        `json:"denominator"`
	Value       *float64       `json:"value,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

func (e RemoteMetricEvaluator) EvaluateMetric(ctx context.Context, metric MetricSnapshot, input, output json.RawMessage) (MetricOutcome, error) {
	if metric.Kind == "agent_assertions" {
		return EvaluateAgentAssertions(ctx, metric, input, output)
	}
	if metric.Kind == "exact_match" || metric.Kind == "contains" || metric.Kind == "numeric_tolerance" {
		return BuiltinMetricEvaluator{}.EvaluateMetric(ctx, metric, input, output)
	}
	request, err := buildMetricRunnerRequest(metric, input, output)
	if err != nil {
		return MetricOutcome{}, err
	}
	response, err := e.execute(ctx, request)
	if err != nil {
		return MetricOutcome{}, err
	}
	if response.MetricID != request.Metric || response.Version != metric.Version || response.FormulaHash != metric.FormulaHash {
		return MetricOutcome{}, errors.New("metric runner response identity mismatch")
	}
	if len(response.Code) > 64 || len(response.Message) > 512 {
		return MetricOutcome{}, errors.New("metric runner response diagnostic exceeds limits")
	}
	if !finiteMetricNumber(response.Numerator) || !finiteMetricNumber(response.Denominator) {
		return MetricOutcome{}, errors.New("metric runner response contains a non-finite count")
	}
	status := "unknown"
	var value *float64
	switch response.Status {
	case "OK":
		if response.Value == nil || !finiteMetricNumber(*response.Value) || response.Denominator <= 0 {
			return MetricOutcome{}, errors.New("metric runner returned an invalid passing outcome")
		}
		status = "passed"
		copy := *response.Value
		value = &copy
	case "UNKNOWN":
		if response.Value != nil {
			return MetricOutcome{}, errors.New("metric runner UNKNOWN outcome carries a value")
		}
	case "BLOCKED":
		if response.Value != nil {
			return MetricOutcome{}, errors.New("metric runner BLOCKED outcome carries a value")
		}
		if response.Code == "SANDBOX_ADMISSION_DENIED" && response.Reason == "" {
			status = "blocked"
			break
		}
		if request.Metric != "grounding_gate" || response.Code != "" || !validGroundingBlockReason(response.Reason) || response.Numerator != 0 || response.Denominator != 0 {
			return MetricOutcome{}, errors.New("metric runner BLOCKED outcome has an unsupported code")
		}
		status = "blocked"
	default:
		return MetricOutcome{}, errors.New("metric runner returned an unsupported outcome")
	}
	if request.Metric == "grounding_gate" && response.Status == "OK" {
		one := 1.0
		value = &one
	}
	// Product evidence binds MetricOutcome to the immutable resource ID
	// (metric-id + version), not the runner's implementation metric name.
	// Product 证据必须绑定不可变 Metric Resource ID（metric-id + version），而不是 Runner 内部算法名。
	return MetricOutcome{MetricID: metric.ID, Status: status, Value: value, Direction: "higher_is_better"}, nil
}

func validGroundingBlockReason(reason string) bool {
	switch reason {
	case "no claims to ground",
		"claims reference missing or unknown evidence",
		"claims cite evidence from a conflicting revision",
		"entailment verdict is unknown",
		"one or more claims are not entailed by their evidence",
		"no claim is entailed by its evidence":
		return true
	default:
		return false
	}
}

func (e RemoteMetricEvaluator) execute(ctx context.Context, request metricRunnerRequest) (result metricRunnerResponse, returnedErr error) {
	ctx, span := telemetry.Start(ctx, "platform.evaluation.metric_runner", trace.SpanKindClient)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "METRIC_RUNNER_FAILED")
		}
	}()
	var empty metricRunnerResponse
	baseURL := strings.TrimRight(strings.TrimSpace(e.URL), "/")
	if baseURL == "" || strings.TrimSpace(e.Token) == "" {
		return empty, errors.New("isolated metric runner is not configured")
	}
	timeout := e.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 20 * time.Second
	}
	seconds := int(timeout / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	request.Admission = metricRunnerAdmission{SignatureVerified: true, Network: "none", MaxOutputBytes: 256 << 10, MaxSeconds: seconds, MaxPIDs: 128}
	body, err := json.Marshal(request)
	if err != nil || len(body) > metricRunnerMaxBytes {
		return empty, errors.New("metric runner request is invalid or too large")
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(callCtx, http.MethodPost, baseURL+metricRunnerPath, bytes.NewReader(body))
	if err != nil {
		return empty, errors.New("metric runner request could not be created")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(e.Token))
	telemetry.Inject(callCtx, httpRequest.Header)
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return empty, errors.New("metric runner is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, errors.New("metric runner refused or failed the request")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, metricRunnerMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > metricRunnerMaxBytes {
		return empty, errors.New("metric runner response is invalid or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&empty); err != nil {
		return metricRunnerResponse{}, errors.New("metric runner response is malformed")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return metricRunnerResponse{}, errors.New("metric runner response has trailing data")
	}
	return empty, nil
}

func buildMetricRunnerRequest(metric MetricSnapshot, input, output json.RawMessage) (metricRunnerRequest, error) {
	formula := remoteMetricFormula{}
	decoder := json.NewDecoder(bytes.NewReader(metric.Formula))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&formula); err != nil || !formula.validFor(metric.Kind) {
		return metricRunnerRequest{}, errors.New("published metric formula is invalid")
	}
	request := metricRunnerRequest{Metric: metric.MetricID, Version: metric.Version, FormulaHash: metric.FormulaHash, MinSamples: 1}
	switch metric.Kind {
	case "recall_at_k", "precision_at_k", "mrr", "ndcg":
		request.Metric = map[string]string{"recall_at_k": "recall", "precision_at_k": "precision", "mrr": "mrr", "ndcg": "ndcg"}[metric.Kind]
		if request.Relevant, _ = readStringList(input, formula.InputRelevantField); request.Relevant == nil {
			return metricRunnerRequest{}, errors.New("metric input relevance field is invalid")
		}
		var err error
		request.Ranked, err = readStringList(output, formula.OutputRankedField)
		if err != nil {
			return metricRunnerRequest{}, err
		}
		request.K = formula.K
	case "citation_accuracy":
		request.Metric = "citation_precision"
		expected, err := readStringList(input, formula.InputExpectedField)
		if err != nil {
			return metricRunnerRequest{}, err
		}
		actual, err := readStringList(output, formula.OutputActualField)
		if err != nil {
			return metricRunnerRequest{}, err
		}
		want := make(map[string]struct{}, len(expected))
		for _, id := range expected {
			want[id] = struct{}{}
		}
		request.Total = len(actual)
		for _, id := range actual {
			if _, ok := want[id]; ok {
				request.Correct++
			}
		}
	case "grounding":
		request.Metric = "grounding_gate"
		citations, err := jsonFieldPath(output, formula.OutputCitationsField)
		if formula.InputCitationsField != "" {
			// Canonical reference text is frozen with the dataset, outside the
			// Agent's input projection. Agent-provided citation text is ignored.
			citations, err = jsonFieldPath(input, formula.InputCitationsField)
		}
		if err != nil || json.Unmarshal(citations, &request.Citations) != nil {
			return metricRunnerRequest{}, errors.New("grounding citations are invalid")
		}
		claims, err := jsonFieldPath(output, formula.OutputClaimsField)
		if err != nil || json.Unmarshal(claims, &request.Claims) != nil {
			return metricRunnerRequest{}, errors.New("grounding claims are invalid")
		}
		request.Gate = *formula.Gate
	case "custom_deterministic":
		request.Plugin, request.PluginVersion, request.PluginDigest = metric.PluginID, metric.PluginVersion, metric.PluginDigest
		total, err := readInteger(input, formula.InputTotalField)
		if err != nil {
			return metricRunnerRequest{}, err
		}
		correct, err := readInteger(output, formula.OutputCorrectField)
		if err != nil {
			return metricRunnerRequest{}, err
		}
		request.Total, request.Correct = total, correct
	default:
		return metricRunnerRequest{}, ErrUnsupportedMetric
	}
	return request, nil
}

func (f remoteMetricFormula) validFor(kind string) bool {
	if f.InputCitationsField != "" && (kind != "grounding" || !strings.HasPrefix(f.InputCitationsField, "expected.") || !validJSONFieldPath(f.InputCitationsField) || f.OutputCitationsField != "") {
		return false
	}
	if f.GroundingTarget != "" && (kind != "grounding" || f.GroundingTarget != "citation" && f.GroundingTarget != "domain") {
		return false
	}
	switch kind {
	case "recall_at_k", "precision_at_k", "mrr", "ndcg":
		return validJSONFieldPath(f.InputRelevantField) && validJSONFieldPath(f.OutputRankedField) && f.K > 0 && f.K <= 1000 &&
			f.InputExpectedField == "" && f.OutputActualField == "" && f.OutputCitationsField == "" && f.OutputClaimsField == "" && f.InputTotalField == "" && f.OutputCorrectField == "" && f.Gate == nil
	case "citation_accuracy":
		return validJSONFieldPath(f.InputExpectedField) && validJSONFieldPath(f.OutputActualField) && f.InputRelevantField == "" && f.OutputRankedField == "" && f.OutputCitationsField == "" && f.OutputClaimsField == "" && f.InputTotalField == "" && f.OutputCorrectField == "" && f.Gate == nil
	case "grounding":
		return (validJSONFieldPath(f.OutputCitationsField) || f.InputCitationsField != "") && validJSONFieldPath(f.OutputClaimsField) && f.Gate != nil && finiteMetricNumber(f.Gate.MinEntailment) && f.Gate.MinEntailment >= 0 && f.Gate.MinEntailment <= 1 && f.Gate.RequireAllClaims && f.Gate.FailOnUnknown && f.InputRelevantField == "" && f.OutputRankedField == "" && f.InputExpectedField == "" && f.OutputActualField == "" && f.InputTotalField == "" && f.OutputCorrectField == ""
	case "custom_deterministic":
		return validJSONFieldPath(f.InputTotalField) && validJSONFieldPath(f.OutputCorrectField) && f.InputRelevantField == "" && f.OutputRankedField == "" && f.InputExpectedField == "" && f.OutputActualField == "" && f.OutputCitationsField == "" && f.OutputClaimsField == "" && f.Gate == nil
	default:
		return false
	}
}

func validJSONFieldPath(path string) bool {
	if len(path) == 0 || len(path) > 256 {
		return false
	}
	parts := strings.Split(path, ".")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if !idPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func readStringList(raw json.RawMessage, path string) ([]string, error) {
	field, err := jsonFieldPath(raw, path)
	if err != nil {
		return nil, err
	}
	var values []string
	if err := json.Unmarshal(field, &values); err != nil || len(values) > 10000 {
		return nil, errors.New("metric string-list field is invalid")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" || len(value) > 1024 {
			return nil, errors.New("metric string-list contains an invalid item")
		}
		if _, ok := seen[value]; ok {
			return nil, errors.New("metric string-list contains duplicate identifiers")
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

func readInteger(raw json.RawMessage, path string) (int, error) {
	field, err := jsonFieldPath(raw, path)
	if err != nil {
		return 0, err
	}
	var value json.Number
	decoder := json.NewDecoder(bytes.NewReader(field))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return 0, errors.New("metric count field is invalid")
	}
	n, err := value.Int64()
	if err != nil || n < 0 || n > 10000000 {
		return 0, errors.New("metric count field is outside limits")
	}
	return int(n), nil
}

func finiteMetricNumber(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
