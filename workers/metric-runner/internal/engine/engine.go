// Package engine holds the metric-runner dispatch core shared by the one-shot
// stdin runner and the long-running dispatch service. Both entrypoints must
// apply identical admission, sandbox and result-contract semantics, so the
// logic lives here once instead of being duplicated per binary.
// Package engine 存放一次性 stdin Runner 与常驻派发服务共用的指标 Runner 派发核心。两个入口
// 必须施加完全相同的准入、沙箱与结果契约语义，因此逻辑只在此处实现一次，而非按二进制重复。
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/lexagent/metric-runner/builtin"
	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/aggregate"
	"github.com/lexagent/metric-runner/internal/limits"
	"github.com/lexagent/metric-runner/internal/protocol"
	"github.com/lexagent/metric-runner/internal/sandbox"
)

// Operator configuration. Every value has a fail-closed default: without a
// pinned key no plugin runs, and without an explicit relaxation a plugin never
// starts from uid 0.
// 运维配置。每个取值都有失败闭合的默认值：没有固定公钥则任何插件都不运行；没有显式放宽，
// 插件绝不从 uid 0 启动。
const (
	pluginRootEnv    = "LEXAGENT_METRIC_PLUGIN_ROOT"
	pluginKeyEnv     = "LEXAGENT_METRIC_PLUGIN_PUBKEY"
	networkModeEnv   = "LEXAGENT_METRIC_NETWORK_MODE"
	requireRootEnv   = "LEXAGENT_METRIC_REQUIRE_NONROOT"
	defaultPluginDir = "/plugins"
)

// MaxRequestBytes bounds one request document. The limit is enforced by both
// entrypoints so a caller cannot smuggle an oversized body past the one-shot
// runner by speaking HTTP instead of stdin.
// MaxRequestBytes 限定单个请求文档的大小。两个入口都强制该上限，使调用方无法改用 HTTP 而非
// stdin 来绕过一次性 Runner 的体积限制。
const MaxRequestBytes = 2 << 20

type request struct {
	Metric        string               `json:"metric"`
	Version       string               `json:"version"`
	FormulaHash   string               `json:"formula_hash"`
	Plugin        string               `json:"plugin"`
	PluginVersion string               `json:"plugin_version,omitempty"`
	PluginDigest  string               `json:"plugin_digest,omitempty"`
	Relevant      []string             `json:"relevant"`
	Ranked        []string             `json:"ranked"`
	K             int                  `json:"k"`
	Total         int                  `json:"total"`
	Correct       int                  `json:"correct"`
	Samples       []float64            `json:"samples"`
	SampleCount   int                  `json:"sample_count"`
	Cost          float64              `json:"cost"`
	MinSamples    int                  `json:"min_samples"`
	Citations     []contracts.Citation `json:"citations"`
	Claims        []contracts.Claim    `json:"claims"`
	Gate          contracts.GateConfig `json:"gate"`
	Admission     sandbox.Admission    `json:"admission"`
}

// Handle decodes one strict request document and returns the JSON response
// body. An oversized, empty or malformed document yields the same
// INVALID_INPUT error the one-shot runner has always produced.
// Handle 解码单个严格请求文档并返回 JSON 响应体。超长、为空或畸形的文档产出一次性 Runner
// 一直以来给出的同一 INVALID_INPUT 错误。
func Handle(ctx context.Context, raw []byte) []byte {
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return encode(map[string]any{"status": "ERROR", "code": "INVALID_INPUT"})
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req request
	if err := dec.Decode(&req); err != nil {
		return encode(map[string]any{"status": "ERROR", "code": "INVALID_INPUT"})
	}
	return encode(dispatch(ctx, req))
}

// dispatch applies the admission record first, so a request that fails the
// sandbox policy is refused before any plugin is even resolved.
// dispatch 先施加准入记录，使未通过沙箱策略的请求在任何插件被解析之前即被拒绝。
func dispatch(ctx context.Context, req request) any {
	if err := sandbox.Validate(req.Admission); err != nil {
		return pluginFailureResponse(req, "SANDBOX_ADMISSION_DENIED", err.Error())
	}
	if strings.TrimSpace(req.Plugin) != "" {
		return runPlugin(ctx, req)
	}
	return evaluate(req)
}

// runPlugin resolves the registered third-party metric plugin and runs it under
// the sandbox. Policy refusals are reported as BLOCKED so the gate stops the
// run; transport, timeout, crash and malformed-output failures are reported as
// ERROR so a plugin can never turn its own malfunction into a passing score.
// runPlugin 解析已注册的第三方指标插件并在沙箱下运行。策略拒绝上报为 BLOCKED，使闸门拦截
// 本次运行；传输、超时、崩溃与畸形输出失败上报为 ERROR，使插件无法把自身故障变成通过分数。
func runPlugin(ctx context.Context, req request) any {
	registryDir := pluginRegistryDir()
	runner := sandbox.PluginRunner{
		RegistryDir:    registryDir,
		PublicKey:      pluginPublicKey(registryDir),
		NetworkMode:    envString(networkModeEnv, limits.NetworkNone),
		RequireNonRoot: envBool(requireRootEnv, true),
	}
	outcome, err := runner.Execute(ctx, req.Admission, strings.TrimSpace(req.Plugin), protocol.PluginRequest{
		Metric:        req.Metric,
		Version:       req.Version,
		FormulaHash:   req.FormulaHash,
		PluginVersion: req.PluginVersion,
		PluginDigest:  req.PluginDigest,
		Relevant:      req.Relevant,
		Ranked:        req.Ranked,
		K:             req.K,
		Total:         req.Total,
		Correct:       req.Correct,
		Samples:       req.Samples,
	})
	if err != nil {
		return pluginFailure(req, err)
	}
	return outcome
}

// pluginFailure classifies a plugin-path failure into the two stable codes the
// gate understands.
// pluginFailure 把插件路径的失败归类为闸门可理解的两种稳定码。

func pluginFailure(req request, err error) map[string]any {
	status, code := "ERROR", "METRIC_PLUGIN_ERROR"
	switch {
	case errors.Is(err, sandbox.ErrPolicyDenied),
		errors.Is(err, limits.ErrRootForbidden),
		errors.Is(err, limits.ErrNetworkRequired),
		errors.Is(err, limits.ErrUnavailable),
		errors.Is(err, limits.ErrInvalid):
		status, code = "BLOCKED", "SANDBOX_ADMISSION_DENIED"
	}
	return map[string]any{
		"metric_id": req.Metric, "version": req.Version, "formula_hash": req.FormulaHash,
		"status": status, "code": code, "message": err.Error(),
	}
}

func pluginFailureResponse(req request, code, message string) map[string]any {
	return map[string]any{
		"metric_id": req.Metric, "version": req.Version, "formula_hash": req.FormulaHash,
		"status": "BLOCKED", "code": code, "message": message,
	}
}

func pluginRegistryDir() string {
	if dir := strings.TrimSpace(os.Getenv(pluginRootEnv)); dir != "" {
		return dir
	}
	return defaultPluginDir
}

// pluginPublicKey loads the pinned verification key. The environment wins so an
// operator can pin a key out of band (for example from a Secret); otherwise the
// key published next to the registry is used, which keeps a baked registry and
// its signature verifiable without any extra wiring. A malformed or missing key
// yields nil, which makes every plugin launch fail closed rather than run
// unverified.
// pluginPublicKey 载入固定校验公钥。环境变量优先，使运维可带外固定密钥（例如来自 Secret）；
// 否则使用注册表旁发布的公钥，使随镜像烘焙的注册表及其签名无需额外接线即可校验。密钥畸形或
// 缺失返回 nil，使每次插件启动都失败闭合，而不是在未校验状态下运行。
func pluginPublicKey(root string) []byte {
	if key, err := protocol.LoadPublicKey(os.Getenv(pluginKeyEnv)); err == nil {
		return key
	}
	raw, err := os.ReadFile(filepath.Join(root, "public.key"))
	if err != nil {
		return nil
	}
	key, err := protocol.LoadPublicKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil
	}
	return key
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

// evaluate dispatches one frozen metric request to the built-in implementation.
// Every built-in metric returns a fail-closed contracts.Result, and a grounding
// metric is routed through the single public gate so a domain metric can never
// promote "a citation exists" to grounded.
// evaluate 把单个冻结的指标请求分派到内置实现。每个内置指标都返回失败闭合的
// contracts.Result，接地类指标一律经唯一公共闸门，领域 Metric 无法把"存在引用"提升为接地。
func evaluate(req request) any {
	switch req.Metric {
	case "recall_mrr_ndcg":
		recall, mrr, ndcg := aggregate.Retrieval(req.Relevant, req.Ranked, req.K)
		return map[string]any{"recall_at_k": recall, "mrr": mrr, "ndcg": ndcg, "status": contracts.StatusOK}
	case builtin.MetricRecall:
		return respond(req, builtin.KindRatio, builtin.RecallAtK(req.Relevant, req.Ranked, req.K), 1)
	case builtin.MetricPrecision:
		return respond(req, builtin.KindRatio, builtin.PrecisionAtK(req.Relevant, req.Ranked, req.K), 1)
	case builtin.MetricMRR:
		return respond(req, builtin.KindRatio, builtin.MRRAtK(req.Relevant, req.Ranked, req.K), 1)
	case builtin.MetricNDCG:
		return respond(req, builtin.KindRatio, builtin.NDCGAtK(req.Relevant, req.Ranked, req.K), 1)
	case builtin.MetricCitationCoverage:
		return respond(req, builtin.KindRatio, builtin.CitationCoverage(req.Total, req.Correct), req.Total)
	case builtin.MetricCitationPrecision:
		return respond(req, builtin.KindRatio, builtin.CitationPrecision(req.Total, req.Correct), req.Total)
	case builtin.MetricFactAccuracy:
		return respond(req, builtin.KindRatio, builtin.FactAccuracy(req.Total, req.Correct), req.Total)
	case builtin.MetricRefusalAccuracy:
		return respond(req, builtin.KindRatio, builtin.RefusalAccuracy(req.Total, req.Correct), req.Total)
	case builtin.MetricConformance:
		return respond(req, builtin.KindConformance, builtin.Conformance(req.Total, req.Correct), req.Total)
	case builtin.MetricCost:
		return respond(req, builtin.KindCost, builtin.Cost(req.Cost, req.SampleCount), req.SampleCount)
	case builtin.MetricMeanLatency:
		return respond(req, builtin.KindLatency, builtin.MeanLatency(req.Samples), len(req.Samples))
	case builtin.MetricLatencyHistogram:
		res, details := builtin.LatencyHistogram(req.Samples)
		return respondDetails(req, builtin.KindLatency, res, details, len(req.Samples))
	case "grounding_gate":
		return groundingGate(req)
	default:
		return map[string]any{"status": "ERROR", "code": "UNKNOWN_METRIC"}
	}
}

// respond enforces the declared minimum-sample floor and wraps the value in a
// versioned, auditable outcome so a caller can trace the value back to the exact
// metric version and formula that produced it.
// respond 应用声明的样本下限并把数值包装进带版本的可审计封套，使调用方可将数值追溯回
// 产生它的确切指标版本与公式。
func respond(req request, kind string, res contracts.Result, sampleCount int) contracts.Outcome {
	res = contracts.EnforceMinSamples(res, sampleCount, req.MinSamples)
	return contracts.NewOutcome(req.Metric, req.Version, kind, req.FormulaHash, res, nil)
}

// respondDetails is respond for metrics that carry structured, mergeable
// details such as a latency histogram. Details are dropped whenever the result
// is not OK, so a non-passing status never ships a distribution that a consumer
// might read as usable.
// respondDetails 用于携带结构化可合并细节（如延迟直方图）的指标。只要结果不是 OK，details
// 就被丢弃，使非通过状态永远不会附带一份可能被下游当作可用的分布。
func respondDetails(req request, kind string, res contracts.Result, details map[string]any, sampleCount int) contracts.Outcome {
	res = contracts.EnforceMinSamples(res, sampleCount, req.MinSamples)
	if res.Status != contracts.StatusOK {
		details = nil
	}
	return contracts.NewOutcome(req.Metric, req.Version, kind, req.FormulaHash, res, details)
}

// groundingGate runs the built-in entailment metric over every claim and then the
// single public gate. It never returns a value: the outcome is a pass/fail
// decision with the offending claim ids.
// groundingGate 用内置蕴含指标对每个声明求判定，再交给唯一公共闸门。它绝不返回值：
// 结论是通过/拦截的判决，并给出违规声明 id。
func groundingGate(req request) any {
	verdicts, err := builtin.EvaluateClaims(builtin.LexicalEntailmentMetric{}, req.Citations, req.Claims)
	if err != nil {
		return map[string]any{"status": "ERROR", "code": "ENTAILMENT_FAILED", "message": err.Error()}
	}
	decision := contracts.EvaluateGroundingGate(req.Gate, req.Citations, req.Claims, verdicts)
	result := contracts.Blocked(decision.Reason)
	if decision.Passed() {
		result = contracts.Ratio(1, 1)
	}
	return contracts.NewOutcome(req.Metric, req.Version, "grounding_gate", req.FormulaHash, result, map[string]any{
		"claims": decision.Claims, "grounded": decision.Grounded, "unsupported": decision.Unsupported,
		"unknown_verdict": decision.UnknownVerdict, "missing_citation": decision.MissingCitation,
		"version_conflict": decision.VersionConflict,
	})
}

// encode marshals one response. A marshalling failure still emits a valid JSON
// error object so a caller never receives an empty body.
// encode 序列化单个响应。序列化失败仍输出合法 JSON 错误对象，使调用方绝不收到空响应体。
func encode(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return []byte(`{"status":"ERROR"}`)
	}
	return append(raw, '\n')
}
