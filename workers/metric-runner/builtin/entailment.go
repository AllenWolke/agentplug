package builtin

import (
	"strings"
	"unicode"

	"github.com/lexagent/metric-runner/contracts"
)

// negationTokens are cues that invert a sentence's meaning. When a claim and the
// evidence it cites disagree on polarity, the claim is not entailed even though
// every other token matches -- the classic "negation reversal" counterexample.
// negationTokens 是反转句子含义的线索词。当声明与其引用证据的极性不一致时，即使其余
// 词元完全匹配，声明也不算蕴含——这正是典型的"否定反转"反例。
var negationTokens = map[string]bool{
	"no": true, "not": true, "never": true, "none": true, "without": true,
	"cannot": true, "cant": true, "dont": true, "doesnt": true, "isnt": true,
	"arent": true, "wasnt": true, "werent": true, "wont": true, "wouldnt": true,
	"shouldnt": true, "couldnt": true,
	"不": true, "无": true, "非": true, "未": true, "没": true, "否": true, "勿": true, "禁": true,
}

// conditionalTokens are cues that a statement holds only under a condition. A
// claim that drops a condition the evidence states over-generalizes and must not
// be treated as entailed.
// conditionalTokens 表示陈述仅在某个条件下成立。若声明丢弃了证据中陈述的条件，即为
// 过度泛化，不得视为蕴含。
var conditionalTokens = map[string]bool{
	"if": true, "when": true, "unless": true, "provided": true, "except": true,
	"conditional": true, "condition": true, "requires": true, "required": true,
	"only": true, "assuming": true, "given": true,
	"如果": true, "若": true, "除非": true, "前提": true, "条件": true, "仅": true, "需": true,
}

// stopwordTokens are high-frequency function words with little topical signal;
// dropping them keeps the overlap ratio focused on content words so a shared
// "the/of" cannot inflate groundedness.
// stopwordTokens 是几乎不携带主题信号的高频虚词；剔除它们使覆盖度聚焦于内容词，
// 避免共享的"的/了/是"抬高接地度。
var stopwordTokens = map[string]bool{
	"a": true, "an": true, "the": true, "of": true, "to": true, "and": true,
	"or": true, "in": true, "on": true, "at": true, "by": true, "for": true,
	"is": true, "are": true, "was": true, "were": true, "be": true, "been": true,
	"it": true, "its": true, "this": true, "that": true, "these": true, "those": true,
	"as": true, "with": true, "from": true, "into": true,
	"的": true, "了": true, "是": true, "在": true, "和": true, "与": true, "有": true,
	"个": true, "为": true, "对": true, "把": true,
}

// defaultMinOverlap requires every content token of a claim to be supported by
// the cited evidence. The default is deliberately 1.0: a claim that introduces
// any unsupported content word -- a wrong conclusion ("90 days" vs "30 days"), a
// wrong subject ("warranty" vs "refund"), an invented fact -- must not be promoted
// to grounded just because the rest of the sentence matches the citation.
// defaultMinOverlap 要求声明的每个内容词都被被引证据支持。默认刻意取 1.0：只要声明
// 引入任何无证据支持的内容词——结论错误（"90 天" vs "30 天"）、主体错误
// （"保修" vs "退款"）、杜撰事实——都不得因句中其余部分与引用匹配而被提升为接地。
const defaultMinOverlap = 1.0

// LexicalEntailmentMetric is the built-in, provider-neutral EntailmentMetric. It
// is a deterministic lexical baseline: groundedness comes from content-word
// coverage plus polarity and condition checks, never from the mere existence of a
// citation id. A production deployment may swap in an NLI model behind the same
// SPI without touching the public gate.
// LexicalEntailmentMetric 是内置、与供应商无关的 EntailmentMetric。它是确定性词面基线：
// 仅凭内容词覆盖度与极性、条件检查判定接地，绝不凭"存在引用 id"判定。生产环境可在同一
// SPI 之后替换为 NLI 模型，而无需改动公共闸门。
type LexicalEntailmentMetric struct {
	// MinOverlap is the minimum share of the claim's content tokens that must
	// appear in the cited evidence before the claim counts as entailed; a value
	// <= 0 falls back to defaultMinOverlap.
	// MinOverlap 是声明内容词必须出现在被引证据中的最低占比，低于它即不算蕴含；
	// 取值 <= 0 时回退到 defaultMinOverlap。
	MinOverlap float64
}

// Name implements contracts.EntailmentMetric.
// Name 实现 contracts.EntailmentMetric。
func (LexicalEntailmentMetric) Name() string { return "lexical_entailment" }

// Entail implements contracts.EntailmentMetric. It returns Unknown (never
// grounded) when the evidence or the claim carries no usable content, and a
// not-grounded verdict for the negation-reversal, wrong-subject/conclusion and
// omitted-condition counterexamples.
// Entail 实现 contracts.EntailmentMetric。当证据或声明没有可用内容时返回 Unknown（绝不
// 接地）；对否定反转、主体/结论错误和条件遗漏反例返回不接地判定。
func (m LexicalEntailmentMetric) Entail(citation contracts.Citation, claim contracts.Claim) (contracts.EntailmentVerdict, error) {
	evidenceText := strings.TrimSpace(citation.Content)
	if evidenceText == "" {
		return contracts.EntailmentVerdict{Unknown: true, Reason: "evidence passage has no content"}, nil
	}
	claimText := strings.TrimSpace(claim.Text)
	if claimText == "" {
		return contracts.EntailmentVerdict{Unknown: true, Reason: "claim has no text"}, nil
	}
	evidenceTokens := tokenize(evidenceText)
	if len(evidenceTokens) == 0 {
		return contracts.EntailmentVerdict{Unknown: true, Reason: "evidence passage has no content tokens"}, nil
	}
	claimTokens := tokenize(claimText)
	// A verbatim complete sentence has its own polarity and conditions. Do not
	// compare it with the count of negations in unrelated handbook sentences.
	// Keep the full sentence (including qualifiers); substring matching would
	// incorrectly allow "refunds allowed" inside "no refunds allowed".
	if exactEvidenceSentences(evidenceText, claimText) {
		return contracts.EntailmentVerdict{Score: 1, Grounded: true, Reason: "complete claim sentences match cited evidence sentences"}, nil
	}
	evidenceSet := make(map[string]bool, len(evidenceTokens))
	for _, token := range evidenceTokens {
		evidenceSet[token] = true
	}
	if negationCount(evidenceTokens) != negationCount(claimTokens) {
		return contracts.EntailmentVerdict{Reason: "claim polarity is reversed relative to the cited evidence"}, nil
	}
	if hasCondition(evidenceTokens) && !hasCondition(claimTokens) {
		return contracts.EntailmentVerdict{Reason: "claim drops a condition stated in the cited evidence"}, nil
	}
	content, covered := 0, 0
	for _, token := range claimTokens {
		if stopwordTokens[token] {
			continue
		}
		content++
		if evidenceSet[token] {
			covered++
		}
	}
	if content == 0 {
		return contracts.EntailmentVerdict{Unknown: true, Reason: "claim has no content tokens"}, nil
	}
	minOverlap := m.MinOverlap
	if minOverlap <= 0 {
		minOverlap = defaultMinOverlap
	}
	score := float64(covered) / float64(content)
	if score < minOverlap {
		return contracts.EntailmentVerdict{Score: score, Reason: "claim content is not covered by the cited evidence"}, nil
	}
	return contracts.EntailmentVerdict{Score: score, Grounded: true, Reason: "claim content is covered by the cited evidence"}, nil
}

func exactEvidenceSentences(evidence, claim string) bool {
	split := func(text string) [][]string {
		parts := strings.FieldsFunc(text, func(r rune) bool {
			return r == '.' || r == '!' || r == '?' || r == '。' || r == '！' || r == '？'
		})
		var sentences [][]string
		for _, part := range parts {
			if tokens := tokenize(part); len(tokens) > 0 {
				sentences = append(sentences, tokens)
			}
		}
		return sentences
	}
	evidenceSentences, claimSentences := split(evidence), split(claim)
	if len(claimSentences) == 0 {
		return false
	}
	for _, wanted := range claimSentences {
		matched, content := false, false
		for _, token := range wanted {
			if !stopwordTokens[token] {
				content = true
			}
		}
		if !content {
			return false
		}
		for _, available := range evidenceSentences {
			if len(wanted) != len(available) {
				continue
			}
			equal := true
			for i := range wanted {
				if wanted[i] != available[i] {
					equal = false
					break
				}
			}
			if equal {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// EvaluateClaims runs the entailment metric over every claim against the pooled
// citations and returns the verdicts keyed by claim id, ready for the public
// grounding gate. A claim whose cited id is unknown maps to an Unknown verdict so
// the gate blocks it on reference integrity rather than passing it.
// EvaluateClaims 用蕴含指标对每个声明在其引用证据上求判定，返回以声明 id 为键的判定表，
// 供公共接地闸门使用。引用了未知 id 的声明映射为 Unknown 判定，使闸门按引用完整性拦截
// 而非放行。
func EvaluateClaims(metric contracts.EntailmentMetric, citations []contracts.Citation, claims []contracts.Claim) (map[string]contracts.EntailmentVerdict, error) {
	byID := make(map[string]contracts.Citation, len(citations))
	for _, citation := range citations {
		byID[strings.TrimSpace(citation.ID)] = citation
	}
	verdicts := make(map[string]contracts.EntailmentVerdict, len(claims))
	for _, claim := range claims {
		var evidence contracts.Citation
		for _, id := range claim.CitationIDs {
			if citation, ok := byID[strings.TrimSpace(id)]; ok {
				evidence = citation
				break
			}
		}
		verdict, err := metric.Entail(evidence, claim)
		if err != nil {
			return nil, err
		}
		verdicts[claim.ID] = verdict
	}
	return verdicts, nil
}

// tokenize splits text into lower-cased content tokens: latin letters/digits form
// whole-word tokens, while Han characters are emitted one rune at a time (as the
// script has no word delimiters). Punctuation and whitespace are separators.
// tokenize 把文本切分为小写内容词元：拉丁字母/数字组成整词词元，汉字按单字输出
// （该文字没有分词符）。标点与空白作为分隔符。
func tokenize(text string) []string {
	var tokens []string
	var buf []rune
	flush := func() {
		if len(buf) > 0 {
			tokens = append(tokens, string(buf))
			buf = buf[:0]
		}
	}
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Han, r):
			flush()
			tokens = append(tokens, string(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			buf = append(buf, unicode.ToLower(r))
		default:
			flush()
		}
	}
	flush()
	return tokens
}

// negationCount counts polarity cues among tokens.
// negationCount 统计词元中的极性线索数量。
func negationCount(tokens []string) int {
	count := 0
	for _, token := range tokens {
		if negationTokens[token] {
			count++
		}
	}
	return count
}

// hasCondition reports whether any token is a condition cue.
// hasCondition 报告是否存在任何条件线索词元。
func hasCondition(tokens []string) bool {
	for _, token := range tokens {
		if conditionalTokens[token] {
			return true
		}
	}
	return false
}
