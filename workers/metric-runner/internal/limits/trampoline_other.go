//go:build !linux

package limits

// Off Linux there is no portable way to apply rlimits and the process-level
// seccomp filter to a child between fork and exec, or to verify a cgroup. The
// sandbox therefore fails closed instead of running third-party plugin code
// without a strong boundary; Docker supplies the supported Linux runtime on
// Windows, macOS and Linux hosts.
// 非 Linux 平台无法可移植地在 fork 与 exec 之间向子进程施加 rlimit 和进程级 seccomp 过滤器，
// 也无法验证 cgroup。因此沙箱直接失败闭合，而不是在缺少强边界时运行第三方插件代码；Windows、
// macOS 和 Linux 主机均通过 Docker 提供受支持的 Linux 运行环境。
func available() error { return ErrUnavailable }

func runTrampoline() error { return ErrUnavailable }

func VerifyContainerMemoryLimit(int64) error { return ErrUnavailable }

func VerifyContainerPidsLimit(int) error { return ErrUnavailable }
