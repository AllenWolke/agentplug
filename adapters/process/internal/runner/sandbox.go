package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// TrampolineArg re-enters the adapter binary as the sandbox trampoline. Go
// cannot lower resource limits between fork and exec, so the adapter re-execs
// itself, applies the limits to that fresh image, and only then execs the
// registered target. / TrampolineArg 让 Adapter 二进制以「沙箱跳板」身份重启自身。
// Go 无法在 fork 与 exec 之间设置资源上限，因此 Adapter 先重启自身、在该镜像里施加
// 限制，再 exec 预注册目标命令。
const TrampolineArg = "__lexagent_sandbox_exec"

// sandboxSpecEnv carries the launch envelope to the trampoline. The registered
// command travels through the environment, never through argv, so it does not
// appear in process listings and cannot be fed by a request. / sandboxSpecEnv 把
// 启动信封传给跳板。预注册命令经环境变量（而非 argv）传递，不会出现在进程列表里，
// 也无法由请求方提供。
const sandboxSpecEnv = "LEXAGENT_SANDBOX_SPEC"

// Network isolation modes. "none" makes the adapter create an empty network
// namespace for the target; it needs CAP_SYS_ADMIN and therefore fails closed
// when the runtime does not grant it. "container" means the enclosing container
// runtime and its NetworkPolicy own network isolation and the adapter does not
// create a namespace of its own. / 网络隔离模式："none" 由 Adapter 为目标命令创建
// 空网络命名空间，需要 CAP_SYS_ADMIN，运行时未授予时失败闭合；"container" 表示由外层
// 容器运行时及其 NetworkPolicy 负责网络隔离，Adapter 不自行创建命名空间。
const (
	NetworkNone      = "none"
	NetworkContainer = "container"
)

var (
	ErrInvalidDescriptor  = errors.New("process command is not pre-registered")
	ErrSandboxRequired    = errors.New("process sandbox is required")
	ErrSandboxInvalid     = errors.New("process sandbox limits are invalid")
	ErrSandboxUnavailable = errors.New("process sandbox is unavailable on this platform")
	ErrOutputLimit        = errors.New("process output exceeds the registered sandbox limit")
	ErrProcessFailed      = errors.New("registered process execution failed")
)

// Sandbox is the immutable isolation envelope the operator registers for one
// pre-registered command. Every bound is explicit and positive; a command whose
// envelope is incomplete is refused instead of silently run unisolated.
// Sandbox 是运维为单个预注册命令登记的不可变隔离边界。所有上限都必须显式且为正；边界
// 不完整的命令会被拒绝，绝不静默地无隔离执行。
type Sandbox struct {
	// MaxMemoryBytes is the memory bound the enclosing container must enforce
	// through its cgroup. The adapter verifies the running cgroup limit against
	// this value when RequireCgroupMemory is set. / MaxMemoryBytes 是外层容器
	// 必须通过 cgroup 强制实施的内存上限；设置 RequireCgroupMemory 时 Adapter 会在
	// 启动时核对当前 cgroup 限额。
	MaxMemoryBytes int64 `json:"max_memory_bytes"`
	// MaxCPUSeconds caps the target's cumulative CPU time (RLIMIT_CPU); the
	// kernel sends SIGXCPU and then SIGKILL once the budget is spent.
	// MaxCPUSeconds 限制目标命令的累计 CPU 时间（RLIMIT_CPU），超支后内核先发
	// SIGXCPU 再 SIGKILL。
	MaxCPUSeconds int `json:"max_cpu_seconds"`
	// MaxProcesses caps the target's process/thread count (RLIMIT_NPROC).
	// MaxProcesses 限制目标命令的进程/线程数（RLIMIT_NPROC）。
	MaxProcesses int `json:"max_processes"`
	// MaxOutputBytes caps the captured stdout document.
	MaxOutputBytes int64 `json:"max_output_bytes"`
	// Timeout is the wall-clock deadline for a single invocation.
	Timeout time.Duration `json:"timeout"`
	// Network is NetworkNone or NetworkContainer.
	Network string `json:"network"`
}

// Validate refuses an incomplete or self-contradictory envelope. A zero value
// is invalid on purpose so a missing configuration can never degrade into an
// unisolated run. / Validate 拒绝不完整或自相矛盾的信封。零值刻意判定为非法，
// 使缺失配置永远不会退化成无隔离执行。
func (s Sandbox) Validate() error {
	if s.MaxMemoryBytes <= 0 || s.MaxCPUSeconds <= 0 || s.MaxProcesses <= 0 || s.MaxOutputBytes <= 0 || s.Timeout <= 0 {
		return ErrSandboxInvalid
	}
	if s.Network != NetworkNone && s.Network != NetworkContainer {
		return ErrSandboxInvalid
	}
	return nil
}

// sandboxEnvelope is what the trampoline reads to apply the limits and exec the
// registered target.
type sandboxEnvelope struct {
	Sandbox Sandbox  `json:"sandbox"`
	Binary  string   `json:"binary"`
	Args    []string `json:"args"`
	Dir     string   `json:"dir"`
	Env     []string `json:"env"`
}

// Main is the single entry point the adapter binary calls at start-up. It
// returns for a normal start and only takes over when the binary was re-entered
// as the sandbox trampoline. / Main 是 Adapter 二进制启动时调用的唯一入口：正常
// 启动时直接返回，只有在以沙箱跳板身份重启时才接管。
func Main() {
	if len(os.Args) < 2 || os.Args[1] != TrampolineArg {
		return
	}
	if err := runTrampoline(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(126)
	}
	os.Exit(0)
}

// encode serializes the envelope the trampoline will read.
func (e sandboxEnvelope) encode() (string, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// decodeEnvelope is the single decode path shared by the trampoline and tests.
// decodeEnvelope 是跳板与测试共用的唯一解码路径。
func decodeEnvelope(raw string, envelope *sandboxEnvelope) error {
	return json.Unmarshal([]byte(raw), envelope)
}
