//go:build !linux

package fixture

// IgnoreFileSizeSignal is a no-op off Linux: the file-size rlimit and its
// signal are Linux concepts, and the sandbox itself fails closed there.
// IgnoreFileSizeSignal 在非 Linux 上是空操作：文件大小 rlimit 及其信号是 Linux 概念，
// 且沙箱本身在非 Linux 上失败闭合。
func IgnoreFileSizeSignal() {}
