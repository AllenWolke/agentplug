// Package limits applies the registered resource envelope to a metric plugin
// process and launches it as an isolated one-shot child. Go cannot lower
// resource limits between fork and exec, so the runner re-executes its own
// binary as a trampoline, the trampoline lowers the limits on that fresh image
// and only then execs the pre-registered plugin entrypoint.
// Package limits 为指标插件进程施加已登记的资源边界，并把它作为隔离的一次性子进程启动。
// Go 无法在 fork 与 exec 之间降低资源上限，因此 Runner 以「跳板」身份重启自身二进制，
// 跳板在新镜像上收紧上限后，才 exec 预注册的插件入口。
package limits

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lexagent/metric-runner/internal/protocol"
)

// TrampolineArg re-enters the runner binary as the sandbox trampoline.
// TrampolineArg 让 Runner 二进制以「沙箱跳板」身份重启自身。
const TrampolineArg = "__lexagent_metric_sandbox_exec"

// SpecEnv carries the launch envelope to the trampoline. The registered command
// travels through the environment, never through argv, so it never appears in a
// process listing and cannot be influenced by the request payload.
// SpecEnv 把启动信封传给跳板。预注册命令经环境变量（而非 argv）传递，不会出现在进程列表里，
// 也无法被请求载荷影响。
const SpecEnv = "LEXAGENT_METRIC_SANDBOX_SPEC"

// failureMarker prefixes the one line the trampoline writes when it refuses to
// start a plugin. The launcher reads it back to recover the failure *class*
// across the process boundary, so "the sandbox could not isolate this plugin"
// never degrades into "the plugin crashed".
// failureMarker 是跳板拒绝启动插件时写出的那一行的前缀。启动方读回它，以便跨越进程边界恢复
// 失败的 *类别*，使「沙箱无法隔离该插件」永远不会退化成「插件崩溃」。
const failureMarker = "LEXAGENT_METRIC_SANDBOX_FAILURE:"

// Failure classes the trampoline can report.
// 跳板可以上报的失败类别。
const (
	classInvalid   = "invalid"
	classRoot      = "root"
	classNetwork   = "network"
	classUnavail   = "unavailable"
	classExec      = "exec"
	exitRefused    = 120
	exitRootDenied = 121
	exitNoNetns    = 122
	exitNoSandbox  = 123
	exitExecFailed = 126
)

// Network modes. "none" installs a process-level seccomp filter that rejects
// socket and io_uring network operations before plugin exec, without granting
// CAP_SYS_ADMIN. "container" delegates isolation to the enclosing runtime and
// its NetworkPolicy, exactly as the process adapter does.
// 网络模式。"none" 在插件 exec 前安装进程级 seccomp 过滤器，拒绝 socket 与 io_uring 网络操作，
// 无需授予 CAP_SYS_ADMIN。"container" 把隔离交给外层容器运行时及其 NetworkPolicy，与
// Process 适配器一致。
const (
	NetworkNone      = "none"
	NetworkContainer = "container"
)

// MaxStderrBytes bounds retained plugin stderr before sanitization.
// MaxStderrBytes 限定脱敏前保留的插件 stderr 大小。
const MaxStderrBytes = 16 << 10

var (
	ErrInvalid         = errors.New("metric sandbox envelope is invalid")
	ErrUnavailable     = errors.New("metric sandbox is unavailable on this platform")
	ErrRootForbidden   = errors.New("metric sandbox refuses to run a plugin as root")
	ErrOutputLimit     = errors.New("metric plugin output exceeds the registered sandbox limit")
	ErrNetworkRequired = errors.New("metric sandbox could not enforce the required no-network policy")
	ErrPluginExited    = errors.New("metric plugin exited unsuccessfully")
)

// Envelope is the immutable isolation boundary registered for one plugin. Every
// bound is explicit and positive; an incomplete envelope is refused rather than
// silently run unisolated.
// Envelope 是为单个插件登记的不可变隔离边界。所有上限必须显式且为正；不完整的信封会被
// 拒绝，而不是被静默地无隔离执行。
type Envelope struct {
	MaxMemoryBytes int64  `json:"max_memory_bytes"`
	MaxCPUSeconds  int    `json:"max_cpu_seconds"`
	MaxProcesses   int    `json:"max_processes"`
	MaxOutputBytes int64  `json:"max_output_bytes"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Network        string `json:"network"`
	RequireNonRoot bool   `json:"require_non_root"`
}

// Validate refuses an incomplete or self-contradictory envelope. A zero value is
// invalid on purpose so a missing configuration can never degrade into an
// unisolated run.
// Validate 拒绝不完整或自相矛盾的信封。零值刻意判定为非法，使缺失配置永远不会退化成
// 无隔离执行。
func (e Envelope) Validate() error {
	if e.MaxMemoryBytes <= 0 || e.MaxCPUSeconds <= 0 || e.MaxProcesses <= 0 || e.MaxOutputBytes <= 0 || e.TimeoutSeconds <= 0 {
		return fmt.Errorf("%w: every limit must be positive", ErrInvalid)
	}
	if e.Network != NetworkNone && e.Network != NetworkContainer {
		return fmt.Errorf("%w: network must be %q or %q", ErrInvalid, NetworkNone, NetworkContainer)
	}
	return nil
}

// Timeout is the wall-clock deadline for one plugin invocation.
// Timeout 是单次插件调用的墙钟截止时间。
func (e Envelope) Timeout() time.Duration {
	return time.Duration(e.TimeoutSeconds) * time.Second
}

// Spec is what the trampoline reads to apply the limits and exec the
// pre-registered plugin. Root is the operator-owned registry root the launcher
// resolved the plugin under; carrying it in the spec is what lets the
// trampoline -- a brand new process -- re-verify the same boundary.
// Spec 是跳板读取的内容：据此施加限制并 exec 预注册插件。Root 是启动方据以解析插件的运维
// 自有注册根；把它放进 Spec 正是为了让跳板（一个全新进程）能重新核对同一条边界。
type Spec struct {
	Root     string   `json:"root"`
	Envelope Envelope `json:"envelope"`
	Binary   string   `json:"binary"`
	Args     []string `json:"args"`
	Dir      string   `json:"dir"`
	Env      []string `json:"env"`
}

// Validate refuses a spec whose target could escape the registered boundary: a
// relative or traversing binary path, a binary outside the plugin root, or an
// incomplete envelope.
// Validate 拒绝目标可能逃逸已登记边界的 Spec：相对或含穿越的二进制路径、位于插件根之外的
// 二进制、或不完整的信封。
func (s Spec) Validate() error {
	if err := s.Envelope.Validate(); err != nil {
		return err
	}
	if err := validateRoot(s.Root); err != nil {
		return err
	}
	if err := validateBinary(s.Root, s.Binary); err != nil {
		return err
	}
	if s.Dir != "" && (!filepath.IsAbs(s.Dir) || strings.Contains(s.Dir, "..")) {
		return fmt.Errorf("%w: working directory %q", ErrInvalid, s.Dir)
	}
	for _, arg := range s.Args {
		if strings.ContainsAny(arg, ";|&$><`\\\"'\n\r\t") {
			return fmt.Errorf("%w: arg %q", ErrInvalid, arg)
		}
	}
	return nil
}

func validateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || strings.Contains(root, "..") {
		return fmt.Errorf("%w: plugin root %q", ErrInvalid, root)
	}
	return nil
}

// validateBinary requires the artifact to be a plain file directly inside its
// own registry entry, so a symlink or a traversing name cannot smuggle in a
// different executable than the one the descriptor was signed for.
// validateBinary 要求制品是其自身注册项内的普通文件，使符号链接或含穿越的名称无法夹带一个
// 与描述符签名对象不同的可执行文件。
func validateBinary(root, binary string) error {
	if binary == "" || !filepath.IsAbs(binary) || strings.Contains(binary, "..") {
		return fmt.Errorf("%w: binary %q", ErrInvalid, binary)
	}
	cleaned := filepath.Clean(binary)
	if cleaned != filepath.Join(filepath.Clean(root), filepath.Base(filepath.Dir(cleaned)), filepath.Base(cleaned)) {
		return fmt.Errorf("%w: binary %q must sit directly inside its registry entry under %s", ErrInvalid, binary, root)
	}
	return nil
}

// Encode serializes the spec for the trampoline.
// Encode 为跳板序列化 Spec。
func (s Spec) Encode() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// DecodeSpec is the single decode path shared by the trampoline and tests.
// DecodeSpec 是跳板与测试共用的唯一解码路径。
func DecodeSpec(raw string) (Spec, error) {
	var spec Spec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		return spec, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := spec.Validate(); err != nil {
		return spec, err
	}
	return spec, nil
}

// Available reports whether this platform can enforce the sandbox. Callers must
// treat a non-nil result as "refuse to run the plugin".
// Available 报告本平台是否能强制执行该沙箱。调用方必须把非 nil 结果视为「拒绝运行插件」。
func Available() error { return available() }

// Main is the single entry point the runner binary calls at start-up. It
// returns for a normal start and only takes over when the binary was re-entered
// as the sandbox trampoline.
// Main 是 Runner 二进制启动时调用的唯一入口：正常启动时直接返回，只有在以沙箱跳板身份
// 重启时才接管。
func Main() {
	if len(os.Args) < 2 || os.Args[1] != TrampolineArg {
		return
	}
	err := runTrampoline()
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "%s%s: %v\n", failureMarker, classOf(err), err)
	os.Exit(exitCodeFor(err))
}

func classOf(err error) string {
	switch {
	case errors.Is(err, ErrNetworkRequired):
		return classNetwork
	case errors.Is(err, ErrRootForbidden):
		return classRoot
	case errors.Is(err, ErrUnavailable):
		return classUnavail
	case errors.Is(err, ErrInvalid):
		return classInvalid
	default:
		return classExec
	}
}

func exitCodeFor(err error) int {
	switch classOf(err) {
	case classNetwork:
		return exitNoNetns
	case classRoot:
		return exitRootDenied
	case classUnavail:
		return exitNoSandbox
	case classInvalid:
		return exitRefused
	default:
		return exitExecFailed
	}
}

// sentinelFor maps a reported class back to the sentinel error the launcher
// classifies on.
// sentinelFor 把上报的类别映射回启动方据以归类的哨兵错误。
func sentinelFor(class string) error {
	switch class {
	case classNetwork:
		return ErrNetworkRequired
	case classRoot:
		return ErrRootForbidden
	case classUnavail:
		return ErrUnavailable
	case classInvalid:
		return ErrInvalid
	default:
		return ErrPluginExited
	}
}

// Result is the bounded outcome of one sandboxed plugin invocation.
// Result 是一次沙箱化插件调用的有界结果。
type Result struct {
	Stdout   []byte
	Stderr   string
	TimedOut bool
}

// Self returns the path of the running runner binary, which doubles as the
// trampoline image so no extra executable has to ship in the image.
// Self 返回正在运行的 Runner 二进制路径；它同时充当跳板镜像，因此镜像无需额外可执行文件。
func Self() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return path, nil
}

// Launch runs the spec as an isolated one-shot child and returns its bounded
// stdout plus sanitized stderr. The caller owns the strict decoding of stdout;
// this layer guarantees only that the process ran under the registered envelope
// and that its output never exceeded the registered budget.
// Launch 把 Spec 作为隔离的一次性子进程运行，返回有界 stdout 与已脱敏 stderr。stdout 的
// 严格解码由调用方负责；本层只保证进程确实运行在已登记信封之下，且输出未超过已登记预算。
func Launch(ctx context.Context, spec Spec, stdin []byte) (Result, error) {
	var result Result
	if err := Available(); err != nil {
		return result, err
	}
	if err := spec.Validate(); err != nil {
		return result, err
	}
	if spec.Envelope.RequireNonRoot && os.Geteuid() == 0 {
		return result, ErrRootForbidden
	}
	self, err := Self()
	if err != nil {
		return result, err
	}
	encoded, err := spec.Encode()
	if err != nil {
		return result, err
	}
	runCtx, cancel := context.WithTimeout(ctx, spec.Envelope.Timeout())
	defer cancel()
	cmd := exec.CommandContext(runCtx, self, TrampolineArg)
	cmd.Env = []string{SpecEnv + "=" + encoded}
	cmd.Stdin = bytes.NewReader(stdin)
	stdout := &boundedBuffer{limit: spec.Envelope.MaxOutputBytes}
	stderr := &boundedBuffer{limit: MaxStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := cmd.Run()
	rawStderr := stderr.buf.String()
	result.Stdout = stdout.buf.Bytes()
	result.Stderr = protocol.SanitizeStderr(rawStderr, MaxStderrBytes)
	if runCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, fmt.Errorf("%w: exceeded %s", ErrPluginExited, spec.Envelope.Timeout())
	}
	if stdout.overflow {
		return result, ErrOutputLimit
	}
	if runErr != nil {
		if sentinel := reportedFailure(rawStderr); sentinel != nil {
			return result, fmt.Errorf("%w: %s", sentinel, result.Stderr)
		}
		return result, fmt.Errorf("%w: %v: %s", ErrPluginExited, runErr, result.Stderr)
	}
	if len(result.Stdout) == 0 {
		return result, fmt.Errorf("%w: plugin produced no output", ErrPluginExited)
	}
	return result, nil
}

// reportedFailure recovers the trampoline's failure class from its raw stderr.
// Reading the marker rather than the exit code keeps a plugin that happens to
// exit with a reserved code from being mistaken for a sandbox refusal.
// reportedFailure 从跳板的原始 stderr 恢复失败类别。读取标记而非退出码，可避免一个恰好使用
// 保留退出码的插件被误判为沙箱拒绝。
func reportedFailure(rawStderr string) error {
	index := strings.Index(rawStderr, failureMarker)
	if index < 0 {
		return nil
	}
	rest := rawStderr[index+len(failureMarker):]
	class, _, _ := strings.Cut(rest, ":")
	return sentinelFor(strings.TrimSpace(class))
}

// SanitizeStderr keeps untrusted plugin output safe to persist and bound in
// size.
// SanitizeStderr 让不可信的插件输出可以安全持久化且有大小上限。
func SanitizeStderr(raw []byte) string {
	return protocol.SanitizeStderr(string(raw), MaxStderrBytes)
}

// boundedBuffer captures at most limit bytes and records whether more arrived,
// so an oversized writer is detected instead of silently truncated into a
// plausible-looking result.
// boundedBuffer 最多捕获 limit 字节并记录是否还有更多数据，因此超量写入会被检出，
// 而不是被静默截断成一个看似合理的结果。
type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		b.buf.Write(p[:remaining])
		b.overflow = true
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}
