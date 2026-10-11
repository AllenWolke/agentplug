package descriptor

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
)

// Limits are the resource bounds the published descriptor pins for one
// upstream call, so an operator cannot widen them through the environment.
// Limits 是已发布 Descriptor 为单次上游调用固定的资源边界，运维无法通过环境变量放宽。
type Limits struct {
	TimeoutSeconds   int   `json:"timeout_seconds,omitempty"`
	MaxResponseBytes int64 `json:"max_response_bytes,omitempty"`
}

type Descriptor struct {
	AdapterID    string   `json:"adapter_id"`
	Kind         string   `json:"kind"`
	Endpoint     string   `json:"endpoint"`
	Path         string   `json:"path"`
	MappingHash  string   `json:"mapping_hash"`
	MappingRef   string   `json:"mapping_ref"`
	Capabilities []string `json:"capabilities"`
	Limits       Limits   `json:"limits"`
	Revision     int64    `json:"revision"`
	// PlanPath points at the registered, signed mapping-plan document the
	// runtime loads instead of trusting a caller-supplied plan. PlanPublicKey
	// is the base64 ed25519 key that document must be signed with; when set,
	// an unsigned or badly signed plan is refused.
	// PlanPath 指向已登记且已签名的映射计划文档，运行时据此加载而不再信任调用方
	// 传入的计划；PlanPublicKey 是该文档必须使用的 base64 ed25519 公钥，设置后
	// 未签名或签名错误的计划一律拒绝。
	PlanPath      string `json:"plan_path"`
	PlanPublicKey string `json:"plan_public_key"`
	// EventsPath enables the execution-event stream when the descriptor also
	// declares the events capability. Leaving it empty keeps the adapter from
	// advertising a stream it cannot serve. / EventsPath 在 Descriptor 同时声明
	// events 能力时启用执行事件流；留空则 Adapter 不会对外宣告它无法提供的事件流。
	EventsPath string `json:"events_path"`
}

// supportedCapabilities is the closed set of capabilities this runtime actually
// implements: invoke, the readiness probe the container exposes, and the
// execution-event stream when an events path is configured. A descriptor that
// claims anything else is refused instead of silently advertising unimplemented
// behaviour. / supportedCapabilities 是本运行时真正实现的封闭能力集合：invoke、
// 容器暴露的就绪探针，以及配置了事件路径时的执行事件流。声明其他能力的 Descriptor
// 会被拒绝，而不是静默对外宣告未实现的行为。
var supportedCapabilities = map[string]bool{"invoke": true, "health": true, "events": true}

// unimplementedCapabilities are capability names the platform contract defines
// but this runtime cannot serve yet. They are rejected explicitly so an operator
// gets a clear reason rather than a vague "unsupported capability".
// unimplementedCapabilities 是平台契约已定义、但本运行时尚无法提供的能力名。它们被
// 显式拒绝，使运维得到明确原因而非笼统的「不支持的能力」。
var unimplementedCapabilities = map[string]bool{"cancel": true, "resume": true, "checkpoint": true}

func Load(path string) (Descriptor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Descriptor{}, err
	}
	var d Descriptor
	if json.Unmarshal(raw, &d) != nil {
		return Descriptor{}, errors.New("descriptor must be JSON")
	}
	if strings.TrimSpace(d.AdapterID) == "" || d.Kind != "legacy-http" || !strings.HasPrefix(d.Path, "/") || strings.Contains(d.Path, "..") || d.Revision < 1 {
		return Descriptor{}, errors.New("invalid descriptor")
	}
	if d.Endpoint != "" {
		if err := validateEndpoint(d.Endpoint); err != nil {
			return Descriptor{}, err
		}
	}
	for _, capability := range d.Capabilities {
		name := strings.TrimSpace(capability)
		if supportedCapabilities[name] {
			continue
		}
		if unimplementedCapabilities[name] {
			return Descriptor{}, errors.New("descriptor declares a capability this runtime does not implement")
		}
		return Descriptor{}, errors.New("descriptor declares an unsupported capability")
	}
	if eventsPath := strings.TrimSpace(d.EventsPath); eventsPath != "" && (!strings.HasPrefix(eventsPath, "/") || strings.Contains(eventsPath, "..")) {
		return Descriptor{}, errors.New("descriptor events_path must be a registered absolute path")
	}
	// Declaring the events capability without a registered events path would
	// advertise a stream the runtime cannot read, so it is refused up front
	// rather than failing at request time.
	// 声明 events 能力却未登记事件路径，等于对外宣告一个运行时读不到的事件流，因此
	// 在加载阶段即拒绝，而不是等到请求时才失败。
	if strings.TrimSpace(d.EventsPath) == "" {
		for _, capability := range d.Capabilities {
			if strings.TrimSpace(capability) == "events" {
				return Descriptor{}, errors.New("descriptor declares the events capability without an events_path")
			}
		}
	}
	if d.Limits.TimeoutSeconds < 0 || d.Limits.MaxResponseBytes < 0 {
		return Descriptor{}, errors.New("descriptor limits must not be negative")
	}
	if strings.TrimSpace(d.PlanPublicKey) != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(d.PlanPublicKey))
		if err != nil || len(key) != ed25519.PublicKeySize {
			return Descriptor{}, errors.New("descriptor plan_public_key must be a base64 ed25519 public key")
		}
	}
	if strings.TrimSpace(d.PlanPath) != "" && strings.Contains(d.PlanPath, "..") {
		return Descriptor{}, errors.New("descriptor plan_path must not traverse")
	}
	return d, nil
}

// validateEndpoint checks the shape of the descriptor endpoint. Address-family
// policy (HTTPS, private ranges, DNS) is enforced separately by the target
// package so one rule source owns reachability.
// validateEndpoint 只校验 Descriptor endpoint 的结构。地址族策略（HTTPS、私网、DNS）
// 由 target 包单独强制，使可达性规则只有一个来源。
func validateEndpoint(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed != raw || trimmed == "" {
		return errors.New("descriptor endpoint is not a clean URL")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Hostname() == "" {
		return errors.New("descriptor endpoint is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("descriptor endpoint must be http(s)")
	}
	if u.User != nil {
		return errors.New("descriptor endpoint must not embed credentials")
	}
	if strings.Contains(u.Path, "..") {
		return errors.New("descriptor endpoint path must not traverse")
	}
	return nil
}
