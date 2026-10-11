//go:build linux

package fixture

import (
	"os/signal"
	"syscall"
)

// IgnoreFileSizeSignal stops SIGXFSZ from killing the process so an over-budget
// file write returns an ordinary error the fixture can report, instead of
// terminating before it can say what happened.
// IgnoreFileSizeSignal 阻止 SIGXFSZ 杀死进程，使超预算的文件写入返回可被夹具上报的普通错误，
// 而不是在能说明情况之前就终止。
func IgnoreFileSizeSignal() {
	signal.Ignore(syscall.SIGXFSZ)
}
