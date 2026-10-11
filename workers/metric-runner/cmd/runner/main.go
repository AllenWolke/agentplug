package main

import (
	"context"
	"io"
	"os"

	"github.com/lexagent/metric-runner/internal/engine"
	"github.com/lexagent/metric-runner/internal/limits"
)

// The one-shot entrypoint keeps its historic stdin/stdout contract. All
// admission, sandbox and result-contract logic lives in internal/engine so this
// binary and the long-running dispatch service can never drift apart.
// 一次性入口保持其历史 stdin/stdout 契约。全部准入、沙箱与结果契约逻辑位于
// internal/engine，使本二进制与常驻派发服务不可能相互漂移。
func main() {
	// Re-entered as the sandbox trampoline this takes over the process image and
	// never returns; on a normal start it is a no-op.
	// 以沙箱跳板身份重启时它接管进程镜像且不返回；正常启动时为空操作。
	limits.Main()

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, int64(engine.MaxRequestBytes)+1))
	if err != nil {
		raw = nil
	}
	_, _ = os.Stdout.Write(engine.Handle(context.Background(), raw))
}
