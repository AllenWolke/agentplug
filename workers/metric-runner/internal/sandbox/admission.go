// Package sandbox defines the small, transport-neutral admission contract for
// metric plugins. The runner itself executes only built-in metrics; external
// plugins must arrive with an admission record produced by a sandbox launcher.
// Package sandbox 定义指标插件的最小隔离准入契约。Runner 只执行内置指标；
// 外部插件必须由隔离 Launcher 生成准入记录后才能进入执行边界。
package sandbox

import "errors"

var (
	ErrSignatureRequired = errors.New("metric plugin signature is required")
	ErrNetworkDenied     = errors.New("metric plugin network must be disabled")
	ErrSecretDenied      = errors.New("metric plugin secret access must be disabled")
	ErrResourceLimit     = errors.New("metric plugin resource limit is invalid")
)

// Admission is intentionally explicit so a future OCI/Kubernetes sandbox can
// map the same fields to seccomp, read-only mounts, cgroups and NetworkPolicy.
// Admission 字段显式表达隔离要求，后续可映射到 seccomp、只读挂载、cgroup 和 NetworkPolicy。
type Admission struct {
	SignatureVerified bool   `json:"signature_verified"`
	Network           string `json:"network"`
	SecretAccess      bool   `json:"secret_access"`
	MaxOutputBytes    int    `json:"max_output_bytes"`
	MaxSeconds        int    `json:"max_seconds"`
	MaxPIDs           int    `json:"max_pids"`
}

func Validate(a Admission) error {
	if !a.SignatureVerified {
		return ErrSignatureRequired
	}
	if a.Network != "none" {
		return ErrNetworkDenied
	}
	if a.SecretAccess {
		return ErrSecretDenied
	}
	if a.MaxOutputBytes <= 0 || a.MaxOutputBytes > 2<<20 || a.MaxSeconds <= 0 || a.MaxSeconds > 300 || a.MaxPIDs <= 0 || a.MaxPIDs > 128 {
		return ErrResourceLimit
	}
	return nil
}
