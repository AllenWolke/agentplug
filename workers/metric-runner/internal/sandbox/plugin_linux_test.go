//go:build linux

// This file is the PF-16 runtime evidence. It builds the real metric runner and
// the real plugin fixtures, registers them with a real Ed25519 signature, and
// drives the whole path as an attacker would: third-party bytes in, one JSON
// document out. Every assertion is on an observed outcome, never on a comment.
//
// The runtime evidence uses an unprivileged, resource-bounded container. The
// plugin-level seccomp filter blocks network syscalls without CAP_SYS_ADMIN or
// a privileged Docker seccomp override.
//
// 本文件是 PF-16 的运行态证据。它构建真实指标 Runner 与真实插件夹具、以真实 Ed25519 签名注册
// 它们，并像攻击者一样驱动整条路径：第三方字节进，一份 JSON 出。每个断言都基于观测到的结果，
// 绝不基于注释。
//
// 运行证据使用非特权、带资源上限的容器。插件级 seccomp 过滤器无需 CAP_SYS_ADMIN 或
// 放宽 Docker seccomp 配置即可阻断网络系统调用。
package sandbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lexagent/metric-runner/internal/limits"
	"github.com/lexagent/metric-runner/internal/protocol"
)

const (
	envRegistry = "LEXAGENT_METRIC_PLUGIN_ROOT"
	envKey      = "LEXAGENT_METRIC_PLUGIN_PUBKEY"
	envNetwork  = "LEXAGENT_METRIC_NETWORK_MODE"
	envNonRoot  = "LEXAGENT_METRIC_REQUIRE_NONROOT"
)

type sandboxHarness struct {
	moduleDir string
	registry  string
	binary    string
	key       ed25519.PrivateKey
}

func newSandboxHarness(t *testing.T) *sandboxHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("metric sandbox end-to-end test skipped in short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	moduleDir := metricRunnerModuleDir(t)
	registry := t.TempDir()
	binary := filepath.Join(t.TempDir(), "metric-runner")
	buildGo(t, moduleDir, binary, "./cmd/runner")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return &sandboxHarness{moduleDir: moduleDir, registry: registry, binary: binary, key: key}
}

// buildGo compiles one package with VCS stamping disabled. Stamping is switched
// off so the gate reports a compile result rather than failing on the owning
// user of a bind-mounted checkout, which says nothing about the code.
// buildGo 在关闭 VCS 标记的情况下编译一个包。关闭标记是为了让门禁报告编译结果，而不是因为
// 绑定挂载检出的属主问题失败——后者与代码无关。
func buildGo(t *testing.T, dir, output, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", output, pkg)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", pkg, err, out)
	}
}

// metricRunnerModuleDir walks up from the package directory to the repository
// root that holds the metric-runner module.
// metricRunnerModuleDir 从包目录逐级向上找到持有 metric-runner 模块的仓库根。
func metricRunnerModuleDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "workers", "metric-runner", "go.mod")); err == nil {
			return filepath.Join(dir, "workers", "metric-runner")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repository root not found from %s", dir)
		}
		dir = parent
	}
}

// register builds one fixture, signs its descriptor with the harness key and
// installs it into the registry exactly as an operator would.
// register 构建一个夹具，用夹具密钥签名其描述符，并像运维一样把它安装进注册表。
func (h *sandboxHarness) register(t *testing.T, id, pkg string, registeredLimits protocol.Limits, args []string) {
	t.Helper()
	dir := filepath.Join(h.registry, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create registry entry: %v", err)
	}
	artifact := filepath.Join(dir, "plugin")
	buildGo(t, h.moduleDir, artifact, "./plugins/"+pkg)
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	descriptor := protocol.Descriptor{
		ID:         id,
		Version:    "1.0.0",
		Entrypoint: "/plugins/" + id + "/plugin",
		SHA256:     protocol.DigestOf(raw),
		Args:       args,
		Network:    protocol.NetworkNone,
		Limits:     registeredLimits,
	}
	if err := h.install(t, descriptor); err != nil {
		t.Fatalf("install descriptor: %v", err)
	}
}

// install signs and writes a descriptor, returning any validation failure so a
// negative test can assert on it.
// install 签名并写入描述符，返回任何校验失败，使负例测试可以对其断言。
func (h *sandboxHarness) install(t *testing.T, descriptor protocol.Descriptor) error {
	t.Helper()
	signed := descriptor
	signed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(h.key, descriptor.CanonicalBytes()))
	if err := signed.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	return os.WriteFile(filepath.Join(h.registry, descriptor.ID, "plugin.json"), raw, 0o644)
}

// env is the operator configuration the runner is started with.
// env 是启动 Runner 时使用的运维配置。
func (h *sandboxHarness) env(networkMode string, requireNonRoot bool) []string {
	if networkMode == "" {
		networkMode = limits.NetworkContainer
	}
	nonRoot := "0"
	if requireNonRoot {
		nonRoot = "1"
	}
	return []string{
		envRegistry + "=" + h.registry,
		envKey + "=" + base64.StdEncoding.EncodeToString(h.key.Public().(ed25519.PublicKey)),
		envNetwork + "=" + networkMode,
		envNonRoot + "=" + nonRoot,
	}
}

// run drives the real runner binary over its stdin/stdout contract.
// run 通过 stdin/stdout 契约驱动真实 Runner 二进制。
func (h *sandboxHarness) run(t *testing.T, payload map[string]any, env []string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cmd := exec.Command(h.binary)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run metric-runner: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	dec := json.NewDecoder(&stdout)
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode metric-runner output: %v (%s)", err, strings.TrimSpace(stdout.String()))
	}
	return out
}

// registeredLimits is the envelope the fixtures register. The memory bound is
// deliberately generous so any container started with a sensible --memory
// passes the start-up cgroup verification; a container with no memory limit at
// all is refused, which is the point of that check. The process bound is
// generous too: RLIMIT_NPROC counts every task owned by the uid in the
// container, which already includes the test binary and the runner, so the
// bound must leave room for a Go runtime while still refusing a fork bomb that
// asks for far more.
// registeredLimits 是夹具登记的信封。内存上限刻意留有余量，使任何以合理 --memory 启动的容器
// 都能通过启动期 cgroup 核对；完全没有内存上限的容器会被拒绝，这正是该检查的意义。进程上限
// 同样留有余量：RLIMIT_NPROC 会计入容器内该 uid 拥有的每个任务，其中已包含测试二进制与 Runner，
// 因此该上限必须容得下一个 Go 运行时，同时仍能拒绝一次索取远超此数的 fork 炸弹。
func registeredLimits() protocol.Limits {
	return protocol.Limits{
		MaxCPUSeconds:  5,
		MaxMemoryBytes: 1 << 30,
		MaxPIDs:        128,
		MaxOutputBytes: 2 << 20,
		TimeoutSeconds: 30,
	}
}

func admission(maxSeconds int) map[string]any {
	return map[string]any{
		"signature_verified": true,
		"network":            "none",
		"secret_access":      false,
		"max_output_bytes":   2 << 20,
		"max_seconds":        maxSeconds,
		"max_pids":           128,
	}
}

func pluginPayload(id string, maxSeconds int) map[string]any {
	return map[string]any{
		"metric":       id,
		"version":      "1.0.0",
		"formula_hash": "sha256:caller-pinned-formula",
		"plugin":       id,
		"total":        4,
		"correct":      3,
		"admission":    admission(maxSeconds),
	}
}

func builtinPayload(metric string) map[string]any {
	return map[string]any{
		"metric":    metric,
		"version":   "1.0.0",
		"total":     4,
		"correct":   3,
		"admission": admission(30),
	}
}

// TestSandboxRunsRegisteredPluginUnderTheSharedResultContract proves the pilot
// requirement that a domain plugin and a public built-in metric emit the same
// result contract: the two documents carry an identical key set, so a consumer
// that can read one can read the other.
// TestSandboxRunsRegisteredPluginUnderTheSharedResultContract 证明试点要求：领域插件与公共内置
// 指标给出同一结果契约——两份文档的键集合完全一致，因此能读一份的下游就能读另一份。
func TestSandboxRunsRegisteredPluginUnderTheSharedResultContract(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root lane required for the plugin execution assertions")
	}
	h := newSandboxHarness(t)
	h.register(t, "example_metric", "example", registeredLimits(), nil)

	plugin := h.run(t, pluginPayload("example_metric", 30), h.env(limits.NetworkContainer, true))
	if statusOf(t, plugin) != "OK" {
		t.Fatalf("plugin outcome = %+v, want OK", plugin)
	}
	if number(t, plugin, "numerator") != 3 || number(t, plugin, "denominator") != 4 {
		t.Fatalf("plugin must return the registered numerator/denominator: %+v", plugin)
	}
	if number(t, plugin, "value") != 0.75 {
		t.Fatalf("plugin value = %v, want 0.75", plugin["value"])
	}
	if got := stringOf(plugin, "formula_hash"); got != "sha256:caller-pinned-formula" {
		t.Fatalf("plugin outcome must pin the caller's formula hash, got %q (%+v)", got, plugin)
	}

	builtin := h.run(t, builtinPayload("citation_coverage"), h.env(limits.NetworkContainer, true))
	if statusOf(t, builtin) != "OK" {
		t.Fatalf("built-in outcome = %+v, want OK", builtin)
	}
	if got, want := sortedKeys(plugin), sortedKeys(builtin); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("domain and built-in metrics must share one contract:\n domain : %v\n builtin: %v", got, want)
	}
}

// TestSandboxRefusesUnsignedOrTamperedArtifacts proves the registry is a real
// gate, not a naming convention.
// TestSandboxRefusesUnsignedOrTamperedArtifacts 证明注册表是真实闸门，而不是命名约定。
func TestSandboxRefusesUnsignedOrTamperedArtifacts(t *testing.T) {
	h := newSandboxHarness(t)

	t.Run("artifact changed after signing", func(t *testing.T) {
		h.register(t, "tampered_metric", "example", registeredLimits(), nil)
		artifact := filepath.Join(h.registry, "tampered_metric", "plugin")
		raw, err := os.ReadFile(artifact)
		if err != nil {
			t.Fatalf("read artifact: %v", err)
		}
		if err := os.WriteFile(artifact, append(raw, 0x00), 0o755); err != nil {
			t.Fatalf("tamper artifact: %v", err)
		}
		out := h.run(t, pluginPayload("tampered_metric", 30), h.env(limits.NetworkContainer, true))
		assertStatus(t, out, "BLOCKED", "SANDBOX_ADMISSION_DENIED")
	})

	t.Run("descriptor signed by a foreign key", func(t *testing.T) {
		_, foreign, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate foreign key: %v", err)
		}
		dir := filepath.Join(h.registry, "foreign_metric")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create registry entry: %v", err)
		}
		build := exec.Command("go", "build", "-buildvcs=false", "-o", filepath.Join(dir, "plugin"), "./plugins/example")
		build.Dir = h.moduleDir
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %v: %s", err, out)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "plugin"))
		if err != nil {
			t.Fatalf("read artifact: %v", err)
		}
		descriptor := protocol.Descriptor{
			ID: "foreign_metric", Version: "1.0.0", Entrypoint: "/plugins/foreign_metric/plugin",
			SHA256: protocol.DigestOf(raw), Network: protocol.NetworkNone, Limits: registeredLimits(),
		}
		descriptor.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(foreign, descriptor.CanonicalBytes()))
		encoded, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatalf("marshal descriptor: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "plugin.json"), encoded, 0o644); err != nil {
			t.Fatalf("write descriptor: %v", err)
		}
		out := h.run(t, pluginPayload("foreign_metric", 30), h.env(limits.NetworkContainer, true))
		assertStatus(t, out, "BLOCKED", "SANDBOX_ADMISSION_DENIED")
	})

	t.Run("root is refused by default", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires a root runner to observe the refusal")
		}
		h.register(t, "root_metric", "example", registeredLimits(), nil)
		out := h.run(t, pluginPayload("root_metric", 30), h.env(limits.NetworkContainer, true))
		assertStatus(t, out, "BLOCKED", "SANDBOX_ADMISSION_DENIED")
	})
}

// TestSandboxBlocksMaliciousPlugins is the core PF-16 assertion set. Each
// fixture attempts one hostile action and reports the outcome; a sandbox that
// fails to block it produces a failing assertion.
// TestSandboxBlocksMaliciousPlugins 是 PF-16 的核心断言集。每个夹具尝试一次恶意动作并上报结果；
// 未能拦截它的沙箱会产生失败的断言。
func TestSandboxBlocksMaliciousPlugins(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root lane required: RLIMIT_NPROC is not enforced for uid 0")
	}
	h := newSandboxHarness(t)
	pluginEnv := h.env(limits.NetworkContainer, true)

	t.Run("fork bomb is capped", func(t *testing.T) {
		h.register(t, "malicious_forkbomb", "malicious/forkbomb", registeredLimits(), []string{"--armed"})
		out := h.run(t, pluginPayload("malicious_forkbomb", 20), pluginEnv)
		assertBlockedReason(t, out, "fork_bomb:blocked")
	})

	t.Run("host file read and oversize write are refused", func(t *testing.T) {
		h.register(t, "malicious_file", "malicious/file", registeredLimits(), []string{"--armed"})
		out := h.run(t, pluginPayload("malicious_file", 30), pluginEnv)
		assertBlockedReason(t, out, "host_file_access:blocked")
	})

	t.Run("platform environment never reaches the plugin", func(t *testing.T) {
		h.register(t, "malicious_environment", "malicious/environment", registeredLimits(), []string{"--armed"})
		out := h.run(t, pluginPayload("malicious_environment", 30), pluginEnv)
		assertBlockedReason(t, out, "secret_probe:blocked")
	})

	t.Run("output flood is refused", func(t *testing.T) {
		h.register(t, "malicious_hugeout", "malicious/hugeout", registeredLimits(), []string{"--armed"})
		out := h.run(t, pluginPayload("malicious_hugeout", 30), pluginEnv)
		assertStatus(t, out, "ERROR", "METRIC_PLUGIN_ERROR")
	})
}

// TestSandboxKillsRunawayPlugin proves the wall-clock deadline, not the CPU
// rlimit, ends a plugin that never returns.
// TestSandboxKillsRunawayPlugin 证明终止一个永不返回的插件的是墙钟截止时间，而非 CPU rlimit。
func TestSandboxKillsRunawayPlugin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root lane required for the plugin execution assertions")
	}
	h := newSandboxHarness(t)
	h.register(t, "malicious_timeout", "malicious/timeout", registeredLimits(), []string{"--armed"})
	out := h.run(t, pluginPayload("malicious_timeout", 2), h.env(limits.NetworkContainer, true))
	assertStatus(t, out, "ERROR", "METRIC_PLUGIN_ERROR")
}

// TestSandboxSeccompDeniesEgress proves a real signed plugin cannot create a
// socket under the "none" policy while running unprivileged.
// TestSandboxSeccompDeniesEgress 证明真实签名插件在非特权进程下，仍无法在 "none" 策略中
// 创建网络 socket。
func TestSandboxSeccompDeniesEgress(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root lane required for the plugin execution assertions")
	}
	// The runner fails closed unless the enclosing container applies memory and
	// pids cgroup limits. Those exist in the dedicated lane, not a bare shell.
	// Runner 要求外层容器明确设置内存和 PID cgroup 上限；专用测试通道会设置，裸 shell 通常没有。
	bounds := registeredLimits()
	if err := limits.VerifyContainerMemoryLimit(bounds.MaxMemoryBytes); err != nil {
		t.Skipf("lane does not bound container memory for the sandbox: %v", err)
	}
	if err := limits.VerifyContainerPidsLimit(bounds.MaxPIDs); err != nil {
		t.Skipf("lane does not bound container pids for the sandbox: %v", err)
	}
	h := newSandboxHarness(t)
	h.register(t, "malicious_net", "malicious/net", registeredLimits(), []string{"--armed"})
	out := h.run(t, pluginPayload("malicious_net", 20), h.env(limits.NetworkNone, false))
	assertBlockedReason(t, out, "network_egress:blocked")
}

// A native service without an enforced cgroup must refuse even a signed plugin.
// The dedicated unbounded lane requires this test to PASS rather than skip.
func TestSandboxRefusesMissingCgroupBounds(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root lane required")
	}
	bounds := registeredLimits()
	if limits.VerifyContainerMemoryLimit(bounds.MaxMemoryBytes) == nil && limits.VerifyContainerPidsLimit(bounds.MaxPIDs) == nil {
		t.Skip("bounded lane; exercise this assertion in the unbounded lane")
	}
	h := newSandboxHarness(t)
	h.register(t, "example_metric", "example", bounds, nil)
	out := h.run(t, pluginPayload("example_metric", 30), h.env(limits.NetworkNone, true))
	assertStatus(t, out, "BLOCKED", "SANDBOX_ADMISSION_DENIED")
}

func assertStatus(t *testing.T, out map[string]any, status, code string) {
	t.Helper()
	if got := statusOf(t, out); got != status {
		t.Fatalf("status = %q, want %q (%+v)", got, status, out)
	}
	if got := stringOf(out, "code"); got != code {
		t.Fatalf("code = %q, want %q (%+v)", got, code, out)
	}
}

// assertBlockedReason asserts an UNKNOWN outcome whose reason records that the
// sandbox blocked the action the fixture attempted. The fixture may append what
// it observed, so the expected verdict is a prefix rather than the whole reason.
// assertBlockedReason 断言一条 UNKNOWN 结果，其原因记录沙箱拦截了夹具尝试的动作。夹具可以
// 追加它所观测到的细节，因此期望的判定是前缀而非完整原因。
func assertBlockedReason(t *testing.T, out map[string]any, want string) {
	t.Helper()
	if got := statusOf(t, out); got != "UNKNOWN" {
		t.Fatalf("status = %q, want UNKNOWN (%+v)", got, out)
	}
	reason := stringOf(out, "reason")
	if !strings.HasPrefix(reason, want) {
		t.Fatalf("reason = %q, want prefix %q (%+v)", reason, want, out)
	}
}

func statusOf(t *testing.T, out map[string]any) string {
	t.Helper()
	return stringOf(out, "status")
}

func stringOf(out map[string]any, key string) string {
	value, _ := out[key].(string)
	return value
}

func number(t *testing.T, out map[string]any, key string) float64 {
	t.Helper()
	switch value := out[key].(type) {
	case json.Number:
		parsed, err := value.Float64()
		if err != nil {
			t.Fatalf("field %q is not a number: %v", key, err)
		}
		return parsed
	case float64:
		return value
	default:
		t.Fatalf("field %q missing or not numeric: %+v", key, out)
		return 0
	}
}

func sortedKeys(out map[string]any) []string {
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
