// Package fixture contains the small helpers shared by the metric plugin
// fixtures used by the PF-16 sandbox tests. These fixtures are deliberately
// cooperative: they attempt one hostile action and then *report* whether the
// sandbox blocked it. A sandbox that fails to block therefore produces a
// failing assertion instead of a silent pass, which is the only way a
// "malicious plugin was stopped" claim can be checked mechanically.
// Package fixture 持有 PF-16 沙箱测试所用指标插件夹具的共享小工具。这些夹具刻意「配合」：
// 尝试一次恶意动作，然后 *上报* 沙箱是否拦截。未能拦截的沙箱因此会产生失败的断言，而不是
// 静默通过——这是「恶意插件被拦截」这一主张唯一可被机械校验的方式。
package fixture

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// armingArg is the argument a signed descriptor must carry for a fixture to
// actually misbehave. Running a fixture by hand therefore does nothing, and
// arming it requires editing a descriptor whose bytes are signed.
// armingArg 是已签名描述符必须携带的参数，夹具才会真正作恶。因此手工运行夹具不会有任何
// 动作，而使其武装需要修改一份已被签名的描述符。
const armingArg = "--armed"

// Armed reports whether the descriptor explicitly armed this fixture.
// Armed 报告描述符是否显式武装了本夹具。
func Armed() bool {
	for _, arg := range os.Args[1:] {
		if arg == armingArg {
			return true
		}
	}
	return false
}

// DrainRequest consumes the frozen plugin request so the runner never blocks
// writing it, and so a fixture cannot accidentally leave the transport half
// closed.
// DrainRequest 消费冻结的插件请求，使 Runner 写入时永不阻塞，也避免夹具意外把传输留在半关闭
// 状态。
func DrainRequest() {
	_, _ = io.Copy(io.Discard, io.LimitReader(os.Stdin, 4<<20))
}

// Report emits one UNKNOWN outcome whose reason records the observation, then
// exits successfully. UNKNOWN is the only status a real plugin would not want,
// so the fixture can never be mistaken for a passing metric.
// Report 输出一条 UNKNOWN 结果，其原因记录观测结论，然后成功退出。UNKNOWN 是真实插件最不想要
// 的状态，因此夹具永远不会被误认为通过的指标。
func Report(action string, blocked bool, detail string) {
	verdict := action + ":allowed"
	if blocked {
		verdict = action + ":blocked"
	}
	if detail != "" {
		verdict += ":" + detail
	}
	raw, err := json.Marshal(map[string]any{"status": "UNKNOWN", "reason": verdict})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture encode:", err)
		os.Exit(1)
	}
	fmt.Println(string(raw))
	os.Exit(0)
}

// NotArmed reports that the fixture was run without the signed arming argument.
// NotArmed 报告夹具在缺少已签名武装参数的情况下被运行。
func NotArmed(action string) {
	Report(action, true, "not_armed")
}
