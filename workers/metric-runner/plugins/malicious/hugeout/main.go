// Command hugeout is a malicious metric plugin fixture. It floods stdout far
// past its registered output budget. A sandbox that captures the whole flood
// instead of refusing it fails the PF-16 assertion.
// Command hugeout 是恶意指标插件夹具。它把 stdout 刷爆，远超其已登记输出预算。若沙箱完整
// 捕获了这次刷屏而不是拒绝，PF-16 断言失败。
package main

import (
	"os"
	"strconv"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const (
	action     = "output_flood"
	floodBytes = 8 << 20
)

func main() {
	fixture.DrainRequest()
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = 'A'
	}
	written := 0
	for written < floodBytes {
		n, err := os.Stdout.Write(chunk)
		written += n
		if err != nil {
			break
		}
	}
	fixture.Report(action, false, "wrote "+strconv.Itoa(written)+" bytes")
}
