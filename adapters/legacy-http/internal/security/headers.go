// Package security builds the outbound request surface of a productized
// adapter. It forwards only an explicit allow-list of client headers and
// propagates W3C trace context and the idempotency key, so a legacy upstream
// never receives the caller's bearer material.
// Package security 构建产品化 Adapter 的出站请求面：只转发显式白名单内的客户端头，
// 并传播 W3C Trace 与幂等键，使存量上游永远拿不到调用方凭证。
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// allowedForwardHeaders is the closed set of client headers the adapter may
// forward. Authorization, Cookie, Host and every other credential or hop-by-hop
// header are absent by construction, so the list cannot leak them by accident.
// allowedForwardHeaders 是 Adapter 允许转发的客户端头的封闭集合。Authorization、
// Cookie、Host 以及其余凭证类或逐跳头天然不在其中，列表本身无法意外泄漏它们。
var allowedForwardHeaders = []string{
	"accept",
	"traceparent",
	"tracestate",
	"idempotency-key",
}

// Traceparent renders a W3C traceparent header for a 32-hex trace id. The span
// id is derived deterministically from the trace so two replicas handling the
// same run emit an identical header instead of each inventing a different
// parent. An id that is not 32 hex digits yields no header rather than a
// malformed one.
// Traceparent 为 32 位十六进制 trace id 生成 W3C traceparent 头。span id 由 trace
// 确定性派生，使处理同一 run 的两个副本发出完全一致的头，而非各自臆造父跨度。非 32 位
// 十六进制的 id 返回空串，而不是产出畸形头。
func Traceparent(traceID string) string {
	id := strings.ToLower(strings.TrimSpace(traceID))
	if len(id) != 32 || !isHex(id) {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return "00-" + id + "-" + hex.EncodeToString(sum[:8]) + "-01"
}

// OutboundHeaders builds the upstream header set from the inbound request. Only
// allow-listed keys are copied, and trace/idempotency values coming from the
// trusted execution contract take precedence over anything the caller sent.
// OutboundHeaders 从入站请求构建上游头集合。只复制白名单键，且来自可信执行契约的
// trace/幂等值优先于调用方发来的任何内容。
func OutboundHeaders(inbound http.Header, traceID, idempotencyKey string) http.Header {
	out := http.Header{}
	// The upstream always receives the mapped JSON document, never the v2
	// envelope, so the content type is fixed instead of forwarded.
	// 上游始终收到映射后的 JSON 文档而非 v2 信封，故内容类型固定而不转发。
	out.Set("Content-Type", "application/json")
	for _, name := range allowedForwardHeaders {
		if value := strings.TrimSpace(inbound.Get(name)); value != "" {
			out.Set(http.CanonicalHeaderKey(name), value)
		}
	}
	if parent := Traceparent(traceID); parent != "" {
		out.Set("Traceparent", parent)
	}
	if key := strings.TrimSpace(idempotencyKey); key != "" {
		out.Set("Idempotency-Key", key)
	}
	return out
}

func isHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
