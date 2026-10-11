//go:build linux

package runner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// rlimitNProc is Linux RLIMIT_NPROC. The syscall package does not export it.
// rlimitNProc 是 Linux 的 RLIMIT_NPROC，syscall 包未导出该常量。
const rlimitNProc = 6

func sandboxSupported() error { return nil }

// applySandbox lowers the resource limits of the current process. The limits
// are inherited across exec, so the registered target runs under them without
// the target having to cooperate. / applySandbox 收紧当前进程的资源上限；这些
// 上限会跨越 exec 继承，因此目标命令在无需自身配合的情况下即受其约束。
func applySandbox(s Sandbox) error {
	if s.Network == NetworkNone {
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			return fmt.Errorf("process sandbox network namespace: %w", err)
		}
	}
	cpu := uint64(s.MaxCPUSeconds)
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: cpu, Max: cpu}); err != nil {
		return fmt.Errorf("process sandbox cpu limit: %w", err)
	}
	processes := uint64(s.MaxProcesses)
	if err := syscall.Setrlimit(rlimitNProc, &syscall.Rlimit{Cur: processes, Max: processes}); err != nil {
		return fmt.Errorf("process sandbox process limit: %w", err)
	}
	return nil
}

// runTrampoline applies the registered envelope and replaces this process image
// with the target command. It parses everything it needs *before* lowering the
// limits so no allocation is required between setrlimit and exec.
// runTrampoline 施加已登记信封并把当前进程镜像替换为目标命令。它在收紧上限之前完成
// 全部解析，确保 setrlimit 与 exec 之间不再需要分配内存。
func runTrampoline() error {
	var envelope sandboxEnvelope
	if err := decodeEnvelope(os.Getenv(sandboxSpecEnv), &envelope); err != nil {
		return fmt.Errorf("process sandbox envelope: %w", err)
	}
	if err := envelope.Sandbox.Validate(); err != nil {
		return err
	}
	if envelope.Binary == "" || !strings.HasPrefix(envelope.Binary, "/") || strings.Contains(envelope.Binary, "..") {
		return ErrInvalidDescriptor
	}
	argv := append([]string{envelope.Binary}, envelope.Args...)
	env := append([]string(nil), envelope.Env...)
	if envelope.Dir != "" {
		if err := os.Chdir(envelope.Dir); err != nil {
			return fmt.Errorf("process sandbox working directory: %w", err)
		}
	}
	if err := applySandbox(envelope.Sandbox); err != nil {
		return err
	}
	return syscall.Exec(envelope.Binary, argv, env)
}

// VerifyContainerMemoryLimit fails closed unless the running container's cgroup
// memory limit is set and no larger than the registered sandbox bound. This
// turns the declared memory bound from a comment into an enforced invariant.
// VerifyContainerMemoryLimit 在运行容器的 cgroup 内存上限未设置或大于已登记沙箱上限时
// 失败闭合，把「声明的内存边界」从注释变成被强制的不变量。
func VerifyContainerMemoryLimit(maxBytes int64) error {
	if maxBytes <= 0 {
		return ErrSandboxInvalid
	}
	limit, err := containerMemoryLimitBytes()
	if err != nil {
		return err
	}
	if limit <= 0 || limit > maxBytes {
		return fmt.Errorf("container memory limit %d is not within the registered sandbox bound %d", limit, maxBytes)
	}
	return nil
}

func containerMemoryLimitBytes() (int64, error) {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			continue
		}
		if value == "max" {
			return 0, nil
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		return parsed, nil
	}
	return 0, fmt.Errorf("%w: no cgroup memory limit is readable", ErrSandboxUnavailable)
}
