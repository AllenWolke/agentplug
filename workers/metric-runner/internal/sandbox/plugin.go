package sandbox

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/limits"
	"github.com/lexagent/metric-runner/internal/protocol"
)

// ErrPolicyDenied is returned when the launcher refuses a plugin before any
// third-party code is allowed to start. Every failure on this path is a refusal,
// never a silent downgrade to an unisolated run.
// ErrPolicyDenied 在允许任何第三方代码启动之前，由启动方拒绝插件时返回。此路径上的每次
// 失败都是拒绝，绝不会静默降级为无隔离运行。
var ErrPolicyDenied = errors.New("metric plugin launch denied by the isolation policy")

// PluginRunner launches one pre-registered, signed metric plugin inside the
// metric sandbox. It is the only component allowed to translate a plugin id
// into an executable, and it does so strictly through the signed registry: the
// request contributes a lookup key, nothing else.
// PluginRunner 在指标沙箱内启动一个预注册、已签名的指标插件。它是唯一被允许把插件 id 译为
// 可执行文件的组件，并且严格通过已签名注册表完成：请求只贡献一个查表键，别无其他。
type PluginRunner struct {
	// RegistryDir is the operator-owned registry root. Both the descriptor and
	// the artifact must live under it.
	// RegistryDir 是运维持有的注册根目录，描述符与制品都必须位于其下。
	RegistryDir string
	// PublicKey is the pinned Ed25519 key every descriptor must be signed with.
	// A missing key refuses every plugin.
	// PublicKey 是每个描述符都必须以其签名的固定 Ed25519 公钥。密钥缺失将拒绝所有插件。
	PublicKey ed25519.PublicKey
	// NetworkMode is the operator-selected enforcement mechanism: "none" makes
	// the trampoline install a process-level seccomp network-deny filter,
	// "container" delegates to the enclosing runtime and its NetworkPolicy.
	// NetworkMode 是运维选择的强制机制："none" 由跳板安装进程级 seccomp 网络拒绝过滤器，
	// "container" 交给外层运行时及其 NetworkPolicy。
	NetworkMode string
	// RequireNonRoot refuses to launch when the runner itself is root, so a
	// privilege escalation in the plugin does not start from uid 0.
	// RequireNonRoot 在 Runner 自身为 root 时拒绝启动，使插件内的提权不从 uid 0 开始。
	RequireNonRoot bool
}

// networkMode returns the configured mechanism, defaulting to the strictest
// one.
// networkMode 返回已配置的机制，默认取最严格的一种。
func (p PluginRunner) networkMode() string {
	if p.NetworkMode == limits.NetworkContainer {
		return limits.NetworkContainer
	}
	return limits.NetworkNone
}

// Envelope derives the sandbox envelope for a verified descriptor, clamped by
// the admission record the launcher stamped. The admission record may only
// tighten the descriptor; it can never widen it.
// Envelope 为已校验的描述符推导沙箱信封，并由启动方盖下的准入记录收紧。准入记录只能收紧
// 描述符，绝不能放宽它。
func (p PluginRunner) Envelope(d protocol.Descriptor, a Admission) (limits.Envelope, error) {
	envelope := limits.Envelope{
		MaxMemoryBytes: d.Limits.MaxMemoryBytes,
		MaxCPUSeconds:  d.Limits.MaxCPUSeconds,
		MaxProcesses:   d.Limits.MaxPIDs,
		MaxOutputBytes: d.Limits.MaxOutputBytes,
		TimeoutSeconds: d.Limits.TimeoutSeconds,
		Network:        p.networkMode(),
		RequireNonRoot: p.RequireNonRoot,
	}
	if int64(a.MaxOutputBytes) > 0 && int64(a.MaxOutputBytes) < envelope.MaxOutputBytes {
		envelope.MaxOutputBytes = int64(a.MaxOutputBytes)
	}
	if a.MaxSeconds > 0 && a.MaxSeconds < envelope.TimeoutSeconds {
		envelope.TimeoutSeconds = a.MaxSeconds
	}
	if a.MaxPIDs > 0 && a.MaxPIDs < envelope.MaxProcesses {
		envelope.MaxProcesses = a.MaxPIDs
	}
	if err := envelope.Validate(); err != nil {
		return envelope, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	return envelope, nil
}

// Execute verifies the registry entry and runs the plugin under the sandbox,
// returning a versioned outcome that uses the same result contract as every
// built-in metric. Any transport, decoding or policy failure is an error so the
// caller can fail closed instead of inventing a metric value.
// Execute 校验注册项并在沙箱下运行插件，返回与所有内置指标使用同一结果契约的带版本封套。
// 任何传输、解码或策略失败都以错误返回，使调用方可失败闭合而不是编造指标数值。
func (p PluginRunner) Execute(ctx context.Context, admission Admission, id string, req protocol.PluginRequest) (contracts.Outcome, error) {
	var outcome contracts.Outcome
	if err := Validate(admission); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if p.RegistryDir == "" {
		return outcome, fmt.Errorf("%w: plugin registry is not configured", ErrPolicyDenied)
	}
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return outcome, fmt.Errorf("%w: no pinned plugin public key", ErrPolicyDenied)
	}
	descriptor, artifact, err := protocol.ResolveRegistered(p.RegistryDir, id)
	if err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if err := descriptor.Validate(); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if err := descriptor.VerifySignature(p.PublicKey); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if err := descriptor.VerifyArtifact(artifact); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	// A published Product suite may pin a plugin release independently from the
	// plugin registry. If either pin is supplied, both must match the signed
	// descriptor; a moving registry entry can never silently change a frozen run.
	// Product 已发布 Suite 可独立固定插件版本；只要请求提供了任一固定值，两者就必须与签名描述符
	// 同时一致，注册表中的可变条目不能静默改变冻结运行。
	if req.PluginVersion != "" || req.PluginDigest != "" {
		if !matchesPluginPin(req.PluginVersion, req.PluginDigest, descriptor) {
			return outcome, fmt.Errorf("%w: pinned plugin version or digest mismatch", ErrPolicyDenied)
		}
	}
	envelope, err := p.Envelope(descriptor, admission)
	if err != nil {
		return outcome, err
	}
	if err := limits.Available(); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if err := limits.VerifyContainerMemoryLimit(envelope.MaxMemoryBytes); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if err := limits.VerifyContainerPidsLimit(envelope.MaxProcesses); err != nil {
		return outcome, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	payload, err := protocol.EncodePluginRequest(req)
	if err != nil {
		return outcome, err
	}
	result, err := limits.Launch(ctx, limits.Spec{
		Root:     p.RegistryDir,
		Envelope: envelope,
		Binary:   artifact,
		Args:     append([]string(nil), descriptor.Args...),
		Dir:      p.RegistryDir,
		Env:      []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C"},
	}, payload)
	if err != nil {
		return outcome, err
	}
	response, err := protocol.DecodePluginResponse(result.Stdout)
	if err != nil {
		return outcome, fmt.Errorf("metric plugin %s: %w", descriptor.ID, err)
	}
	if err := response.Validate(); err != nil {
		return outcome, fmt.Errorf("metric plugin %s: %w", descriptor.ID, err)
	}
	return contracts.NewOutcome(req.Metric, req.Version, "domain", req.FormulaHash, contracts.Result{
		Numerator:   response.Numerator,
		Denominator: response.Denominator,
		Value:       response.Value,
		Status:      response.Status,
		Reason:      response.Reason,
	}, nil), nil
}

func matchesPluginPin(version, digest string, descriptor protocol.Descriptor) bool {
	return version != "" && digest != "" && version == descriptor.Version &&
		protocol.NormalizeDigest(digest) == protocol.NormalizeDigest(descriptor.SHA256)
}
