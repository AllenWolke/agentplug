package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// pluginRequestKeys is the frozen request vocabulary a metric plugin may see.
// The runner builds this document itself, so a plugin never observes platform
// internals, secrets or unrelated evaluation state.
// pluginRequestKeys 是指标插件可见的冻结请求词汇。该文档由 Runner 自行构造，因此插件永远
// 看不到平台内部结构、密钥或无关的评测状态。
type PluginRequest struct {
	Metric        string    `json:"metric"`
	Version       string    `json:"version"`
	FormulaHash   string    `json:"formula_hash"`
	PluginVersion string    `json:"plugin_version,omitempty"`
	PluginDigest  string    `json:"plugin_digest,omitempty"`
	Relevant      []string  `json:"relevant"`
	Ranked        []string  `json:"ranked"`
	K             int       `json:"k"`
	Total         int       `json:"total"`
	Correct       int       `json:"correct"`
	Samples       []float64 `json:"samples"`
}

// PluginResponse is the only document a metric plugin may return. Value is a
// pointer so a missing number is distinguishable from a zero, which keeps
// "the plugin forgot" from being read as "the score is zero".
// PluginResponse 是指标插件唯一允许返回的文档。Value 为指针，使「缺失的数值」与「零」可区分，
// 从而不会把「插件忘了填」读成「分数为零」。
type PluginResponse struct {
	Status      string   `json:"status"`
	Numerator   float64  `json:"numerator"`
	Denominator float64  `json:"denominator"`
	Value       *float64 `json:"value"`
	Reason      string   `json:"reason"`
}

// Statuses a plugin may declare. A plugin cannot declare BLOCKED: blocking a
// run is the platform's decision, so a plugin attempting it is rejected rather
// than trusted.
// 插件可声明的状态。插件不能声明 BLOCKED：拦截一次运行是平台的决定，因此尝试声明它的插件会
// 被拒绝，而不是被信任。
const (
	PluginStatusOK      = "OK"
	PluginStatusUnknown = "UNKNOWN"
)

// DecodePluginResponse strictly decodes a plugin response, rejecting unknown
// fields and trailing data.
// DecodePluginResponse 严格解码插件响应，拒绝未知字段与尾随数据。
func DecodePluginResponse(raw []byte) (PluginResponse, error) {
	var resp PluginResponse
	if len(raw) == 0 {
		return resp, errors.New("metric plugin returned an empty document")
	}
	if err := DecodeStrict(raw, &resp); err != nil {
		return resp, fmt.Errorf("metric plugin response: %w", err)
	}
	return resp, nil
}

// Validate refuses a response the platform cannot faithfully persist: a status
// the plugin may not declare, a non-finite number, or an OK status without a
// usable numerator/denominator/value.
// Validate 拒绝平台无法忠实持久化的响应：插件无权声明的状态、非有限数值、或缺少可用
// 分子/分母/数值的 OK 状态。
func (r PluginResponse) Validate() error {
	for _, v := range []float64{r.Numerator, r.Denominator} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return errors.New("metric plugin response carries a non-finite numerator or denominator")
		}
	}
	switch r.Status {
	case PluginStatusUnknown:
		return nil
	case PluginStatusOK:
		if r.Value == nil {
			return errors.New("metric plugin OK response carries no value")
		}
		if math.IsNaN(*r.Value) || math.IsInf(*r.Value, 0) {
			return errors.New("metric plugin OK response carries a non-finite value")
		}
		if r.Denominator <= 0 {
			return errors.New("metric plugin OK response has a non-positive denominator")
		}
		return nil
	default:
		return fmt.Errorf("metric plugin declared an unsupported status %q", r.Status)
	}
}

// EncodePluginRequest serializes the frozen request document.
// EncodePluginRequest 序列化冻结的请求文档。
func EncodePluginRequest(req PluginRequest) ([]byte, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode metric plugin request: %w", err)
	}
	return raw, nil
}
