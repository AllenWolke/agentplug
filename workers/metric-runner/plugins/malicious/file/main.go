// Command file is a malicious metric plugin fixture. It attempts to read a host
// credential file and to write a file far larger than its registered output
// budget, then reports whether both were refused. A sandboxed run must report
// "blocked"; writing the whole file, or reading the host file, fails the PF-16
// assertion.
// Command file 是恶意指标插件夹具。它尝试读取宿主凭据文件，并写一个远大于其已登记输出预算的
// 文件，然后上报两者是否都被拒绝。被沙箱化的运行必须上报 "blocked"；若整份文件写完或读到宿主
// 文件，PF-16 断言失败。
package main

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/lexagent/metric-runner/plugins/internal/fixture"
)

const (
	action        = "host_file_access"
	oversizeBytes = 64 << 20
)

func main() {
	fixture.DrainRequest()
	if !fixture.Armed() {
		fixture.NotArmed(action)
	}
	fixture.IgnoreFileSizeSignal()
	readDenied := hostFileDenied()
	written, writeBlocked := oversizeWriteBlocked()
	detail := "read_denied=" + strconv.FormatBool(readDenied) +
		";write_blocked=" + strconv.FormatBool(writeBlocked) +
		";bytes=" + strconv.Itoa(written)
	fixture.Report(action, readDenied && writeBlocked, detail)
}

// hostFileDenied attempts to read a file the plugin has no business reading.
// hostFileDenied 尝试读取插件无权读取的文件。
func hostFileDenied() bool {
	_, err := os.ReadFile("/etc/shadow")
	return err != nil
}

// oversizeWriteBlocked attempts to write past the registered output budget. It
// stops at oversizeBytes so a sandbox that does not enforce the limit still
// cannot fill the disk.
// oversizeWriteBlocked 尝试写到已登记输出预算之外。它在 oversizeBytes 处停止，使未强制该
// 上限的沙箱也无法填满磁盘。
func oversizeWriteBlocked() (int, bool) {
	path := filepath.Join(os.TempDir(), "lexagent-metric-plugin-oversize")
	file, err := os.Create(path)
	if err != nil {
		return 0, true
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(path)
	}()
	chunk := make([]byte, 1<<20)
	written := 0
	for written < oversizeBytes {
		n, err := file.Write(chunk)
		written += n
		if err != nil {
			return written, true
		}
	}
	return written, false
}
