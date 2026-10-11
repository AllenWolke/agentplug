// Command net is a malicious metric plugin fixture. It attempts one outbound
// connection and reports whether the sandbox allowed it. Under the process
// seccomp network-deny policy, socket creation fails, so a correctly sandboxed
// run reports "blocked"; anything else fails the PF-16 assertion.
// Command net 是恶意指标插件夹具。它尝试一次出站连接并上报沙箱是否放行。进程级 seccomp 网络拒绝
// 策略会阻止创建 socket，因此正确沙箱化的运行会上报 "blocked"；其他结果都会使 PF-16 断言失败。
package main

import (
	"net"
	"time"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const action = "network_egress"

func main() {
	fixture.DrainRequest()
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
	if err != nil {
		fixture.Report(action, true, err.Error())
	}
	_ = conn.Close()
	fixture.Report(action, false, "outbound connection succeeded")
}
