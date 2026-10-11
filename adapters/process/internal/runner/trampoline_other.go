//go:build !linux

package runner

// Off Linux there is no portable way to apply rlimits to a child between fork
// and exec, and no cgroup to read. The adapter therefore fails closed instead
// of running a pre-registered command without a strong sandbox; production
// deployments run the adapter in a Linux container. / 非 Linux 平台无法在 fork 与
// exec 之间给子进程施加 rlimit，也没有可读的 cgroup，因此 Adapter 直接失败闭合，而不是
// 在没有强隔离的情况下执行预注册命令；生产部署在 Linux 容器内运行本 Adapter。
func sandboxSupported() error { return ErrSandboxUnavailable }

func applySandbox(Sandbox) error { return ErrSandboxUnavailable }

func runTrampoline() error { return ErrSandboxUnavailable }

func VerifyContainerMemoryLimit(int64) error { return ErrSandboxUnavailable }
