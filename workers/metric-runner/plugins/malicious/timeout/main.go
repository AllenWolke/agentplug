// Command timeout is a malicious metric plugin fixture. It never returns, so
// only the runner's wall-clock deadline can end it. A run that returns a metric
// from this plugin proves the deadline is not enforced.
// Command timeout 是恶意指标插件夹具。它永不返回，因此只有 Runner 的墙钟截止时间能终止它。
// 若本插件仍产出指标，即证明截止时间未被强制。
package main

import (
	"time"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const action = "unbounded_runtime"

func main() {
	fixture.DrainRequest()
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	// Sleeping burns no CPU, so this exercises the wall-clock deadline rather
	// than the CPU-time rlimit.
	// 睡眠不消耗 CPU，因此这里检验的是墙钟截止时间，而不是 CPU 时间 rlimit。
	time.Sleep(time.Hour)
	fixture.Report(action, false, "survived the registered timeout")
}
