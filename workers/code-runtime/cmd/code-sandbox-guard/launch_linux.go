//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux assigns these generic numbers on both supported architectures.
const (
	landlockCreateRuleset = 444
	landlockAddRule       = 445
	landlockRestrictSelf  = 446
	closeRange            = 436
	openPath              = 0x200000
	fsExecute             = uint64(1 << 0)
	fsWriteFile           = uint64(1 << 1)
	fsReadFile            = uint64(1 << 2)
	fsReadDir             = uint64(1 << 3)
	fsRemoveDir           = uint64(1 << 4)
	fsRemoveFile          = uint64(1 << 5)
	fsMakeDir             = uint64(1 << 7)
	fsMakeReg             = uint64(1 << 8)
	fsMakeSym             = uint64(1 << 12)
	fsRefer               = uint64(1 << 13)
	fsTruncate            = uint64(1 << 14)
)

type rulesetAttr struct{ HandledAccessFS uint64 }
type pathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	Padding       uint32
}

func launch(language string) error {
	var executable string
	var args []string
	switch language {
	case "python":
		executable = "/usr/local/bin/python3"
		args = []string{executable, "-I", "-B", "-"}
	case "javascript":
		executable = "/usr/local/bin/node"
		args = []string{executable, "--input-type=module", "-"}
	case "shell":
		executable = "/bin/sh"
		args = []string{executable, "-s"}
	default:
		return errors.New("language denied")
	}
	if syscall.Getuid() != 65532 || syscall.Geteuid() != 65532 || syscall.Getgid() != 65532 {
		return errors.New("identity denied")
	}
	// Restrict the exact OS thread that will exec. The interpreter and every
	// descendant inherit the kernel rules; no untrusted code runs in Go.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	abi, _, errno := syscall.Syscall(landlockCreateRuleset, 0, 0, 1)
	if errno != 0 || abi < 3 {
		return guardStage("landlock_abi", errors.New("landlock ABI 3 required"))
	}
	handled := uint64((1 << 15) - 1) // All filesystem rights through ABI 3.
	if abi >= 5 {
		handled |= 1 << 15
	} // Also deny device ioctl unless granted.
	attr := rulesetAttr{HandledAccessFS: handled}
	fd, _, errno := syscall.Syscall(landlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return guardStage("landlock_create", errno)
	}
	ruleset := int(fd)
	defer syscall.Close(ruleset)
	readDirectory := fsExecute | fsReadFile | fsReadDir
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		if err := allowPath(ruleset, path, readDirectory, true, false); err != nil {
			return guardStage("image_read_directory", err)
		}
	}
	// These are fixed image/runtime files, never host paths or caller input.
	for _, path := range []string{"/etc/ld.so.cache", "/etc/localtime", "/dev/zero", "/dev/random", "/dev/urandom"} {
		if err := allowPath(ruleset, path, fsReadFile, false, false); err != nil {
			return guardStage("image_read_file", err)
		}
	}
	if err := allowPath(ruleset, "/dev/null", fsReadFile|fsWriteFile, false, true); err != nil {
		return guardStage("image_null_device", err)
	}
	writeDirectory := fsReadFile | fsReadDir | fsWriteFile | fsRemoveDir | fsRemoveFile | fsMakeDir | fsMakeReg | fsMakeSym | fsRefer | fsTruncate
	for _, path := range []string{"/workspace", "/tmp", "/dev/shm"} {
		if err := allowPath(ruleset, path, writeDirectory, true, true); err != nil {
			return guardStage("workspace_directory", err)
		}
	}
	if _, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); errno != 0 {
		return guardStage("no_new_privileges", errno)
	}
	if _, _, errno = syscall.Syscall(landlockRestrictSelf, uintptr(ruleset), 0, 0); errno != 0 {
		return guardStage("landlock_restrict", errno)
	}
	// Keep only the bounded code input and captured output descriptors. Closing
	// all other inherited descriptors avoids pre-opened-file bypasses.
	if _, _, errno = syscall.Syscall(closeRange, 3, ^uintptr(0), 0); errno != 0 {
		return guardStage("close_descriptors", errno)
	}
	return guardStage("interpreter_exec", syscall.Exec(executable, args, []string{"HOME=/workspace", "TMPDIR=/workspace", "PATH=/usr/local/bin:/usr/bin:/bin", "NODE_OPTIONS=", "PYTHONPATH="}))
}

func allowPath(ruleset int, path string, rights uint64, directory, required bool) error {
	fd, err := syscall.Open(path, openPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		if !required && errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if (stat.Mode&syscall.S_IFMT == syscall.S_IFDIR) != directory {
		return errors.New("path kind denied")
	}
	attr := pathBeneathAttr{AllowedAccess: rights, ParentFD: int32(fd)}
	_, _, errno := syscall.Syscall6(landlockAddRule, uintptr(ruleset), 1, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return errno
	}
	return nil
}
