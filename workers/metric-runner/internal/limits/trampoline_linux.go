//go:build linux

package limits

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func available() error { return nil }

// applyEnvelope lowers the resource limits of the current process. The limits
// are inherited across exec, so the registered plugin runs under them without
// the plugin having to cooperate.
//
// CPU and the file-size bound are lowered here. Memory and the process count
// are deliberately *not* set here: RLIMIT_AS is not honoured by the Go runtime
// and RLIMIT_NPROC counts every task owned by the real uid across the whole
// host user namespace, which a PID-namespaced container cannot even observe.
// Both of those are therefore owned by the container or host-service cgroup and
// verified at start-up instead, so the declared bound is checked rather than
// merely asserted.
// applyEnvelope 收紧当前进程的资源上限；这些上限跨越 exec 继承，因此预注册插件在无需自身
// 配合的情况下即受其约束。
//
// 这里只收紧 CPU 与文件大小上限。内存与进程数刻意不在此设置：Go 运行时不遵循 RLIMIT_AS，
// 而 RLIMIT_NPROC 统计的是整个宿主用户命名空间内真实 uid 拥有的全部任务，处于 PID 命名空间内的
// 容器连观测都做不到。因此这两项由外层容器 cgroup 承担并在启动期核对，使声明的边界是被校验的，
// 而不仅仅是被声称的。
func applyEnvelope(e Envelope) error {
	if os.Geteuid() == 0 && e.RequireNonRoot {
		return ErrRootForbidden
	}
	if e.Network == NetworkNone {
		if err := denyNetworkSyscalls(); err != nil {
			return fmt.Errorf("%w: %v", ErrNetworkRequired, err)
		}
	}
	cpu := uint64(e.MaxCPUSeconds)
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: cpu, Max: cpu}); err != nil {
		return fmt.Errorf("metric sandbox cpu limit: %w", err)
	}
	// The registered output budget also caps how many bytes a plugin may write
	// to any file: emitting bytes is emitting bytes, and a plugin that writes a
	// multi-gigabyte file has left its contract just as surely as one that
	// floods stdout.
	// 已登记的输出预算同时限制插件可写入任何文件的字节数：产出字节就是产出字节，
	// 一个写出数 GB 文件的插件与一个刷爆 stdout 的插件同样越界。
	fsize := uint64(e.MaxOutputBytes)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: fsize, Max: fsize}); err != nil {
		return fmt.Errorf("metric sandbox file size limit: %w", err)
	}
	return nil
}

// denyNetworkSyscalls installs a seccomp filter on the one-shot plugin process
// before exec. Blocking socket creation and every operation that can use a
// socket gives the plugin a no-network contract without granting CAP_SYS_ADMIN
// or depending on Docker's default seccomp profile to permit network namespace
// creation. io_uring is denied as well because it can submit socket operations
// without issuing the corresponding direct syscalls.
// denyNetworkSyscalls 在一次性插件进程 exec 前安装 seccomp 过滤器。阻止创建 socket 及所有
// 可通过 socket 通信的操作，使插件获得明确的无网络契约，而无需 CAP_SYS_ADMIN，也不依赖
// Docker 默认 seccomp 配置是否允许创建网络命名空间。io_uring 同样被禁用，因为它可在不直接
// 发出对应系统调用的情况下提交 socket 操作。
func denyNetworkSyscalls() error {
	arch, ok := auditArchitecture(runtime.GOARCH)
	if !ok {
		return fmt.Errorf("unsupported seccomp architecture %q", runtime.GOARCH)
	}
	filters := []sockFilter{
		{Code: bpfLoadWordAbsolute, K: seccompDataArchOffset},
		{Code: bpfJumpEqualConstant, JT: 1, K: arch},
		{Code: bpfReturnConstant, K: seccompReturnKillProcess},
		{Code: bpfLoadWordAbsolute, K: seccompDataNumberOffset},
	}
	for _, number := range blockedNetworkSyscalls(runtime.GOARCH) {
		filters = append(filters,
			sockFilter{Code: bpfJumpEqualConstant, JT: 0, JF: 1, K: number},
			sockFilter{Code: bpfReturnConstant, K: seccompReturnErrno | uint32(syscall.EPERM)},
		)
	}
	filters = append(filters, sockFilter{Code: bpfReturnConstant, K: seccompReturnAllow})
	program := sockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivileges, 1, 0); errno != 0 {
		return fmt.Errorf("set no_new_privs before seccomp: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&program))); errno != 0 {
		return fmt.Errorf("install plugin network seccomp filter: %w", errno)
	}
	runtime.KeepAlive(filters)
	runtime.KeepAlive(&program)
	return nil
}

func auditArchitecture(goarch string) (uint32, bool) {
	switch goarch {
	case "amd64":
		return 0xc000003e, true // AUDIT_ARCH_X86_64
	case "arm64":
		return 0xc00000b7, true // AUDIT_ARCH_AARCH64
	default:
		return 0, false
	}
}

func blockedNetworkSyscalls(goarch string) []uint32 {
	switch goarch {
	case "amd64":
		return []uint32{41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307, 425, 426, 427}
	case "arm64":
		return []uint32{198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242, 243, 269, 425, 426, 427}
	default:
		return nil
	}
}

type sockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

const (
	bpfLoadWordAbsolute  uint16 = 0x20
	bpfJumpEqualConstant uint16 = 0x15
	bpfReturnConstant    uint16 = 0x06

	seccompDataNumberOffset uint32  = 0
	seccompDataArchOffset   uint32  = 4
	seccompModeFilter       uintptr = 2
	prSetNoNewPrivileges    uintptr = 38
	prSetSeccomp            uintptr = 22

	seccompReturnKillProcess uint32 = 0x80000000
	seccompReturnErrno       uint32 = 0x00050000
	seccompReturnAllow       uint32 = 0x7fff0000
)

// VerifyContainerMemoryLimit fails closed unless the process's effective cgroup
// memory limit is set and no larger than the registered bound. This turns the
// declared memory limit from a comment into an enforced invariant.
// VerifyContainerMemoryLimit 在运行容器的 cgroup 内存上限未设置或大于已登记上限时失败闭合，
// 把「声明的内存边界」从注释变成被强制的不变量。
func VerifyContainerMemoryLimit(maxBytes int64) error {
	if maxBytes <= 0 {
		return ErrInvalid
	}
	limit, err := processCgroupLimit("memory", "memory.max", "memory.limit_in_bytes")
	if err != nil {
		return err
	}
	if limit <= 0 || limit > maxBytes {
		return fmt.Errorf("container memory limit %d is not within the registered sandbox bound %d", limit, maxBytes)
	}
	return nil
}

// VerifyContainerPidsLimit does the same for the process bound: the effective
// PID cgroup must be set and no larger than the registered budget, so a fork
// bomb is stopped by the kernel rather than by the plugin's good manners.
// VerifyContainerPidsLimit 对进程边界做同样的事：容器的 PID cgroup 必须已设置且不大于已登记
// 预算，使 fork 炸弹由内核拦截，而不是靠插件的自觉。
func VerifyContainerPidsLimit(maxProcesses int) error {
	if maxProcesses <= 0 {
		return ErrInvalid
	}
	limit, err := processCgroupLimit("pids", "pids.max", "pids.max")
	if err != nil {
		return err
	}
	if limit <= 0 || limit > int64(maxProcesses) {
		return fmt.Errorf("container pids limit %d is not within the registered sandbox bound %d", limit, maxProcesses)
	}
	return nil
}

// readCgroupLimit returns the smallest finite bound in the visible hierarchy.
// An unlimited hierarchy returns zero and is refused by the callers; no
// readable files returns ErrUnavailable. Both v1 and v2 are supported.
// readCgroupLimit 读取第一个可读的 cgroup 上限文件，同时兼容 v1 与 v2 布局。未设置（"max"）
// 或不可读的上限一律报错，使没有上限的容器被拒绝而不是被信任。
func readCgroupLimit(paths []string) (int64, error) {
	var smallest int64
	readable := false
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			continue
		}
		if value == "max" {
			readable = true
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		if parsed <= 0 {
			return 0, fmt.Errorf("%w: invalid cgroup resource limit", ErrUnavailable)
		}
		readable = true
		if smallest == 0 || parsed < smallest {
			smallest = parsed
		}
	}
	if readable {
		return smallest, nil
	}
	return 0, fmt.Errorf("%w: no cgroup limit is readable at %s", ErrUnavailable, strings.Join(paths, ", "))
}

// runTrampoline applies the registered envelope and replaces this process image
// with the pre-registered plugin entrypoint. Everything is parsed *before* the
// limits are lowered so no allocation is required between setrlimit and exec.
// runTrampoline 施加已登记信封并把当前进程镜像替换为预注册插件入口。全部解析都在收紧上限
// 之前完成，确保 setrlimit 与 exec 之间不再需要内存分配。
func runTrampoline() error {
	spec, err := DecodeSpec(os.Getenv(SpecEnv))
	if err != nil {
		return err
	}
	argv := append([]string{spec.Binary}, spec.Args...)
	env := append([]string(nil), spec.Env...)
	if spec.Dir != "" {
		if err := os.Chdir(spec.Dir); err != nil {
			return fmt.Errorf("metric sandbox working directory: %w", err)
		}
	}
	if err := applyEnvelope(spec.Envelope); err != nil {
		return err
	}
	return syscall.Exec(spec.Binary, argv, env)
}
