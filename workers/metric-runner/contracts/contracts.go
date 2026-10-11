// Package contracts defines the transport-neutral metric contracts shared by the
// metric runner: the fail-closed result envelope, the Claim/Citation structures,
// reference-integrity checking, the EntailmentMetric SPI and the single public
// grounding gate. No metric may produce a groundedness verdict outside that gate.
// Package contracts 定义指标 Runner 共享的、与传输无关的指标契约：失败闭合的结果信封、
// Claim/Citation 结构、引用完整性检查、EntailmentMetric SPI 与唯一公共接地闸门。
// 任何指标都不得在该闸门之外自行给出接地判定。
package contracts

import (
	"math"
	"strings"
)

// Status values. A metric that cannot compute a value reports UNKNOWN instead of
// a number; the grounding gate reports BLOCKED when it refuses to release a run.
// Neither status is a passing value, so "no data" can never be read as a perfect
// score downstream.
// 状态取值。无法计算的指标上报 UNKNOWN 而非数值；接地闸门拒绝放行时上报 BLOCKED。
// 两者都不是通过值，因此下游绝不会把"无数据"误读为满分。
const (
	StatusOK      = "OK"
	StatusUnknown = "UNKNOWN"
	StatusBlocked = "BLOCKED"
)

// Result is the deterministic output of one built-in metric. Value is nil
// whenever Status is not OK, so a consumer can never read a stale number out of
// an UNKNOWN/BLOCKED result.
// Result 是单个内置指标的确定性输出。Status 非 OK 时 Value 为 nil，
// 使下游无法从 UNKNOWN/BLOCKED 结果中读到过期数值。
type Result struct {
	Numerator   float64  `json:"numerator"`
	Denominator float64  `json:"denominator"`
	Value       *float64 `json:"value,omitempty"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
}

// Unknown builds a non-passing result carrying a human-readable reason.
// Unknown 构建带可读原因的、非通过结果。
func Unknown(reason string) Result {
	return Result{Status: StatusUnknown, Reason: reason}
}

// Blocked builds a refused result carrying a human-readable reason.
// Blocked 构建带可读原因的、被拒绝结果。
func Blocked(reason string) Result {
	return Result{Status: StatusBlocked, Reason: reason}
}

// Ratio builds an OK result from counts. It fails closed to UNKNOWN on a
// non-finite numerator/denominator or a non-positive denominator, so a zero
// denominator is never a perfect score.
// Ratio 由计数构建 OK 结果：分子/分母非有限或分母非正时失败闭合为 UNKNOWN，
// 因此零分母永远不会是满分。
func Ratio(numerator, denominator float64) Result {
	if !isFinite(numerator) || !isFinite(denominator) {
		return Unknown("non-finite numerator or denominator")
	}
	if denominator <= 0 {
		return Unknown("non-positive denominator")
	}
	value := numerator / denominator
	if !isFinite(value) {
		return Unknown("non-finite value")
	}
	return Result{Numerator: numerator, Denominator: denominator, Value: &value, Status: StatusOK}
}

// EnforceMinSamples fails closed when there are no samples or fewer than the
// declared minimum, independently of the computed value, so a metric can never
// report a number that claims to rest on samples it does not have.
// EnforceMinSamples 在零样本或低于声明下限时失败闭合，与已算出的数值无关，
// 使指标无法上报一个"依赖并不存在的样本"的数值。
func EnforceMinSamples(result Result, sampleCount, minSamples int) Result {
	if sampleCount <= 0 {
		return Unknown("no samples")
	}
	if minSamples > 0 && sampleCount < minSamples {
		return Unknown("insufficient samples")
	}
	return result
}

func isFinite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// Citation is one retrieved evidence passage a claim may point at. Revision ties
// the passage to the index revision it was retrieved from, so a claim citing a
// passage from a different revision is detected as a version conflict.
// Citation 是声明可以引用的某一检索证据片段。Revision 把片段绑定到其检索来源的索引
// 版本，使引用不同版本片段的声明被识别为版本冲突。
type Citation struct {
	ID       string `json:"id"`
	Revision string `json:"revision,omitempty"`
	Source   string `json:"source,omitempty"`
	Content  string `json:"content,omitempty"`
}

// Claim is one atomic assertion an answer makes. CitationIDs names the evidence
// the answer points at; the groundedness verdict is supplied out of band by an
// EntailmentMetric. A non-empty CitationIDs list alone is never enough to mark a
// claim grounded -- that is exactly the shortcut this contract forbids.
// Claim 是回答做出的一个原子断言。CitationIDs 指出回答引用的证据；接地判定由
// EntailmentMetric 独立给出。仅 CitationIDs 非空绝不等于接地——这正是本契约禁止的捷径。
type Claim struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	CitationIDs []string `json:"citation_ids"`
}

// EntailmentVerdict is one claim's groundedness verdict produced by an
// EntailmentMetric. Unknown means the metric could not decide (no evidence, no
// verdict, non-finite score); the gate treats unknown as unsafe, never grounded.
// EntailmentVerdict 是 EntailmentMetric 对单个声明给出的接地判定。Unknown 表示无法
// 判定（无证据、无判定、非有限分数）；闸门把 unknown 视为不安全，绝不视为接地。
type EntailmentVerdict struct {
	Score    float64 `json:"score"`
	Grounded bool    `json:"grounded"`
	Unknown  bool    `json:"unknown"`
	Reason   string  `json:"reason,omitempty"`
}

// EntailmentMetric is the provider-neutral SPI that decides whether a claim is
// actually entailed by the evidence it cites. Domain metrics must implement this
// rather than promoting "a citation exists" to grounded.
// EntailmentMetric 是判定声明是否真被其引用证据蕴含的、与模型供应商无关的 SPI。
// 领域 Metric 必须实现它，而不是把"存在引用"提升为接地。
type EntailmentMetric interface {
	Name() string
	Entail(citation Citation, claim Claim) (EntailmentVerdict, error)
}

// CheckReferenceIntegrity returns the claim ids that cite nothing or that cite an
// evidence id which was never retrieved. A claim failing this check is not
// grounded, so the gate must block it rather than silently pass it.
// CheckReferenceIntegrity 返回未引用任何证据、或引用了从未检索到的证据 id 的声明 id。
// 未通过该检查的声明不接地，闸门必须拦截而不是静默放行。
func CheckReferenceIntegrity(citations []Citation, claims []Claim) []string {
	known := make(map[string]bool, len(citations))
	for _, citation := range citations {
		if id := strings.TrimSpace(citation.ID); id != "" {
			known[id] = true
		}
	}
	var missing []string
	for _, claim := range claims {
		if len(claim.CitationIDs) == 0 {
			missing = append(missing, claim.ID)
			continue
		}
		found := false
		for _, id := range claim.CitationIDs {
			if known[strings.TrimSpace(id)] {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, claim.ID)
		}
	}
	return missing
}

// conflictingRevisionClaims returns the claim ids whose cited evidence belongs to
// a revision other than the expected one; an empty expected revision disables the
// check so a suite frozen before this contract remains valid.
// conflictingRevisionClaims 返回引用的证据版本与预期不符的声明 id；预期版本为空时
// 关闭该检查，使本契约之前冻结的 Suite 仍然有效。
func conflictingRevisionClaims(expected string, citations []Citation, claims []Claim) []string {
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	byID := make(map[string]string, len(citations))
	for _, citation := range citations {
		byID[strings.TrimSpace(citation.ID)] = strings.TrimSpace(citation.Revision)
	}
	var conflicts []string
	for _, claim := range claims {
		for _, id := range claim.CitationIDs {
			if revision, ok := byID[strings.TrimSpace(id)]; ok && revision != strings.TrimSpace(expected) {
				conflicts = append(conflicts, claim.ID)
				break
			}
		}
	}
	return conflicts
}

// GateConfig is the frozen gate policy a suite pins. A zero MinEntailment means
// any grounded verdict passes; RequireAllClaims, ExpectedRevision and
// FailOnUnknown tighten the gate further.
// GateConfig 是 Suite 固定的闸门策略。MinEntailment 为零表示任何接地判定都通过；
// RequireAllClaims、ExpectedRevision 与 FailOnUnknown 会进一步收紧闸门。
type GateConfig struct {
	MinEntailment    float64 `json:"min_entailment"`
	RequireAllClaims bool    `json:"require_all_claims"`
	ExpectedRevision string  `json:"expected_revision,omitempty"`
	FailOnUnknown    bool    `json:"fail_on_unknown"`
}

// GroundingGateResult is the deterministic outcome of the public grounding gate.
// It records exactly why a run was blocked so an operator never has to guess.
// GroundingGateResult 是公共接地闸门的确定性结果，精确记录被拦截的原因，
// 使运维无需猜测。
type GroundingGateResult struct {
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	Claims          int      `json:"claims"`
	Grounded        int      `json:"grounded"`
	Unsupported     []string `json:"unsupported,omitempty"`
	UnknownVerdict  []string `json:"unknown_verdict,omitempty"`
	MissingCitation []string `json:"missing_citation,omitempty"`
	VersionConflict []string `json:"version_conflict,omitempty"`
}

// Passed reports whether the gate released the run.
// Passed 报告闸门是否放行本次运行。
func (r GroundingGateResult) Passed() bool { return r.Status == StatusOK }

// EvaluateGroundingGate is the single public gate every grounded metric must go
// through; a domain metric may not bypass it. It fails closed on any of: no
// claims, a missing or unknown citation reference, a cited-evidence version
// conflict, an unknown entailment verdict when FailOnUnknown is set, or an
// entailment score below MinEntailment. It never treats the mere presence of a
// citation as grounded, so "citation correct but conclusion wrong", a wrong
// subject, a negation reversal, an omitted condition and a version conflict all
// block.
// EvaluateGroundingGate 是每个接地指标都必须经过的唯一公共闸门；领域 Metric 不得绕过。
// 它在以下任一情况失败闭合：无声明、引用缺失或未知、引用证据版本冲突、设置
// FailOnUnknown 时出现未知判定、或蕴含分数低于 MinEntailment。它绝不把"存在引用"
// 当作接地，因此"引用正确但结论错误"、主体错误、否定反转、条件遗漏与版本冲突都会被拦截。
func EvaluateGroundingGate(cfg GateConfig, citations []Citation, claims []Claim, verdicts map[string]EntailmentVerdict) GroundingGateResult {
	result := GroundingGateResult{Status: StatusOK, Claims: len(claims)}
	if len(claims) == 0 {
		result.Status = StatusBlocked
		result.Reason = "no claims to ground"
		return result
	}
	if missing := CheckReferenceIntegrity(citations, claims); len(missing) > 0 {
		result.Status = StatusBlocked
		result.Reason = "claims reference missing or unknown evidence"
		result.MissingCitation = missing
		return result
	}
	if conflicts := conflictingRevisionClaims(cfg.ExpectedRevision, citations, claims); len(conflicts) > 0 {
		result.Status = StatusBlocked
		result.Reason = "claims cite evidence from a conflicting revision"
		result.VersionConflict = conflicts
		return result
	}
	for _, claim := range claims {
		verdict, ok := verdicts[claim.ID]
		if !ok || verdict.Unknown || !isFinite(verdict.Score) {
			result.UnknownVerdict = append(result.UnknownVerdict, claim.ID)
			continue
		}
		if verdict.Grounded && verdict.Score >= cfg.MinEntailment {
			result.Grounded++
			continue
		}
		result.Unsupported = append(result.Unsupported, claim.ID)
	}
	if cfg.FailOnUnknown && len(result.UnknownVerdict) > 0 {
		result.Status = StatusBlocked
		result.Reason = "entailment verdict is unknown"
		return result
	}
	if len(result.Unsupported) > 0 && cfg.RequireAllClaims {
		result.Status = StatusBlocked
		result.Reason = "one or more claims are not entailed by their evidence"
		return result
	}
	if result.Grounded == 0 {
		result.Status = StatusBlocked
		result.Reason = "no claim is entailed by its evidence"
		return result
	}
	return result
}

// Outcome is the auditable, versioned envelope a runner emits for one metric. It
// pins the metric id, version and formula hash alongside the numeric result and
// details, so a value can be traced back to the exact definition that produced
// it and two metric versions never collapse into one another.
// Outcome 是 Runner 为单个指标输出的、可审计且带版本的封套。它把指标 id、版本与公式
// 哈希连同数值结果和 details 一起固定，使数值可追溯到产生它的确切定义，
// 且不同指标版本不会相互混同。
type Outcome struct {
	MetricID    string `json:"metric_id"`
	Version     string `json:"version"`
	Kind        string `json:"kind,omitempty"`
	FormulaHash string `json:"formula_hash"`
	Result
	Details map[string]any `json:"details,omitempty"`
}

// NewOutcome wraps a computed result in a versioned, auditable envelope.
// NewOutcome 把已算出的结果包装进带版本的可审计封套。
func NewOutcome(metricID, version, kind, formulaHash string, result Result, details map[string]any) Outcome {
	return Outcome{
		MetricID:    metricID,
		Version:     version,
		Kind:        kind,
		FormulaHash: formulaHash,
		Result:      result,
		Details:     details,
	}
}

// Validate reports whether the outcome is a well-formed, versioned envelope.
// A missing identity or a passing status without a finite value is invalid;
// UNKNOWN/BLOCKED must not carry a numeric value.
// Validate 报告该结果是否为形态完整的带版本封套。缺身份、或通过状态却没有有限数值均为非法；
// UNKNOWN/BLOCKED 不得携带数值。
func (o Outcome) Validate(wantMetric, wantVersion, wantHash string) bool {
	if strings.TrimSpace(o.MetricID) == "" || o.MetricID != strings.TrimSpace(wantMetric) {
		return false
	}
	if strings.TrimSpace(o.Version) == "" {
		return false
	}
	if want := strings.TrimSpace(wantVersion); want != "" && o.Version != want {
		return false
	}
	if strings.TrimSpace(o.FormulaHash) == "" {
		return false
	}
	if want := strings.TrimSpace(wantHash); want != "" && o.FormulaHash != want {
		return false
	}
	switch o.Status {
	case StatusOK:
		// A passing aggregate must rest on a positive population. Accepting a
		// negative denominator would make a malformed ratio look trustworthy.
		// 通过的聚合结果必须基于正样本总体；接受负分母会让畸形比例看似可信。
		return o.Value != nil && isFinite(*o.Value) && isFinite(o.Numerator) && isFinite(o.Denominator) && o.Denominator > 0
	case StatusUnknown, StatusBlocked:
		return o.Value == nil
	default:
		return false
	}
}
