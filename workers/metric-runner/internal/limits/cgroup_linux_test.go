//go:build linux

package limits

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProcessCgroupPathsResolveHostServiceAndContainerNamespace(t *testing.T) {
	cases := []struct {
		name, membership, mounts, controller, v2, v1 string
		want                                         []string
	}{
		{"systemd-v2", "0::/system.slice/runner.service", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw", "memory", "memory.max", "memory.limit_in_bytes", []string{"/sys/fs/cgroup/system.slice/runner.service/memory.max", "/sys/fs/cgroup/system.slice/memory.max", "/sys/fs/cgroup/memory.max"}},
		{"systemd-v1", "4:memory:/system.slice/runner.service\n3:pids:/system.slice/runner.service", "1 0 0:1 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory", "memory", "memory.max", "memory.limit_in_bytes", []string{"/sys/fs/cgroup/memory/system.slice/runner.service/memory.limit_in_bytes", "/sys/fs/cgroup/memory/system.slice/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}},
		{"namespaced", "0::/", "1 0 0:1 /docker/instance /sys/fs/cgroup ro - cgroup2 cgroup rw", "pids", "pids.max", "pids.max", []string{"/sys/fs/cgroup/pids.max"}},
		{"subtree-mount", "0::/slice/service", "1 0 0:1 /slice /sys/fs/cgroup rw - cgroup2 cgroup rw", "pids", "pids.max", "pids.max", []string{"/sys/fs/cgroup/service/pids.max", "/sys/fs/cgroup/pids.max"}},
		{"mount-space", "0::/service", `1 0 0:1 / /sys/fs/cgroup\040space rw - cgroup2 cgroup rw`, "pids", "pids.max", "pids.max", []string{"/sys/fs/cgroup space/service/pids.max", "/sys/fs/cgroup space/pids.max"}},
		{"wrong-controller", "4:pids:/service", "1 0 0:1 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory", "memory", "memory.max", "memory.limit_in_bytes", nil},
		{"traversal", "0::/../escape", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw", "pids", "pids.max", "pids.max", nil},
		{"outside-subtree", "0::/other/service", "1 0 0:1 /slice /sys/fs/cgroup rw - cgroup2 cgroup rw", "pids", "pids.max", "pids.max", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := processCgroupPaths(tc.membership, tc.mounts, tc.controller, tc.v2, tc.v1)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("paths=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestCgroupEffectiveLimitHonorsFiniteAncestorAndFailsWithoutBounds(t *testing.T) {
	dir := t.TempDir()
	leaf, parent, root := filepath.Join(dir, "leaf"), filepath.Join(dir, "parent"), filepath.Join(dir, "root")
	for path, value := range map[string]string{leaf: "max", parent: "128", root: "256"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	limit, err := readCgroupLimit([]string{leaf, parent, root})
	if err != nil || limit != 128 {
		t.Fatalf("effective limit=%d, err=%v", limit, err)
	}
	if limit, err := readCgroupLimit([]string{leaf}); err != nil || limit != 0 {
		t.Fatalf("unbounded cgroup=%d, err=%v", limit, err)
	}
	if _, err := readCgroupLimit([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("unreadable hierarchy accepted")
	}
	if err := os.WriteFile(leaf, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCgroupLimit([]string{leaf, parent}); err == nil {
		t.Fatal("invalid leaf limit accepted")
	}
}
