// Command forkbomb is a malicious metric plugin fixture. It spawns child
// processes until the sandbox refuses, then reports how many it managed to
// create. A sandbox that does not cap processes lets it reach maxAttempts and
// fails the PF-16 assertion.
// Command forkbomb 是恶意指标插件夹具。它持续派生子进程直到沙箱拒绝，然后上报创建成功的数量。
// 未限制进程数的沙箱会让它达到 maxAttempts 并使 PF-16 断言失败。
package main

import (
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const (
	action      = "fork_bomb"
	maxAttempts = 512
	childLife   = 30 * time.Second
)

func main() {
	fixture.DrainRequest()
	if isChild() {
		// A short-lived child would never accumulate, so each child holds still
		// long enough for the process limit to be the thing that stops the bomb.
		// 秒退的子进程不会累积，因此每个子进程停留足够久，让进程数上限成为真正终止炸弹的因素。
		time.Sleep(childLife)
		os.Exit(0)
	}
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	created, err := detonate()
	if err != nil {
		fixture.Report(action, true, "fork denied after "+strconv.Itoa(created)+" children: "+err.Error())
	}
	fixture.Report(action, false, "created "+strconv.Itoa(created)+" processes")
}

func isChild() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--child" {
			return true
		}
	}
	return false
}

// detonate forks until the sandbox refuses. It reaps every child *before*
// returning, because the fixture reports with os.Exit, which would otherwise
// skip deferred cleanup and leave sleeping children behind to distort the
// process accounting of every later assertion in the same test binary.
// detonate 持续 fork 直到沙箱拒绝。它在返回 *之前* 回收所有子进程，因为夹具用 os.Exit 上报，
// 否则会跳过延迟清理，留下睡眠中的子进程，干扰同一个测试二进制里后续每个断言的进程计数。
func detonate() (int, error) {
	var children []*exec.Cmd
	created := 0
	var failure error
	for i := 0; i < maxAttempts; i++ {
		cmd := exec.Command(os.Args[0], "--child")
		if err := cmd.Start(); err != nil {
			failure = err
			break
		}
		children = append(children, cmd)
		created++
	}
	for _, child := range children {
		if child.Process != nil {
			_ = child.Process.Kill()
		}
	}
	for _, child := range children {
		_ = child.Wait()
	}
	return created, failure
}
