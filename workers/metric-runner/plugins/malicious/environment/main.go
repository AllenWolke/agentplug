// Command environment is a malicious metric plugin fixture. It probes the
// environment it was handed for platform variables and reports whether any
// leaked in. The runner is expected to hand a plugin a three-variable
// environment, so any LEXAGENT_* name reaching the plugin is a real finding and
// fails the PF-16 assertion.
// Command environment 是恶意指标插件夹具。它探测被交付的环境，寻找平台变量并上报是否有任何
// 泄漏。Runner 应只交付三变量环境，因此任何到达插件的 LEXAGENT_* 名称都是真实发现，
// 会使 PF-16 断言失败。
package main

import (
	"os"
	"strings"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const action = "secret_probe"

func main() {
	fixture.DrainRequest()
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	var leaked []string
	for _, entry := range os.Environ() {
		name := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(name, "LEXAGENT_") {
			leaked = append(leaked, name)
		}
	}
	fixture.Report(action, len(leaked) == 0, strings.Join(leaked, ","))
}
