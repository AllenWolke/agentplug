//go:build linux

package limits

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// processCgroupLimit resolves the current process's controller, including
// systemd service paths and container cgroup namespaces. No configured path
// can substitute for the kernel's membership and mount information.
func processCgroupLimit(controller, v2File, v1File string) (int64, error) {
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, fmt.Errorf("%w: cgroup membership unavailable", ErrUnavailable)
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, fmt.Errorf("%w: cgroup mounts unavailable", ErrUnavailable)
	}
	paths := processCgroupPaths(string(membership), string(mounts), controller, v2File, v1File)
	return readCgroupLimit(paths)
}

func processCgroupPaths(membership, mounts, controller, v2File, v1File string) []string {
	var paths []string
	for _, line := range strings.Split(membership, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		v2 := fields[0] == "0" && fields[1] == ""
		if !v2 && !hasController(fields[1], controller) {
			continue
		}
		member := fields[2]
		if !filepath.IsAbs(member) || filepath.Clean(member) != member {
			continue
		}
		for _, mount := range strings.Split(mounts, "\n") {
			before, after, ok := strings.Cut(mount, " - ")
			left, right := strings.Fields(before), strings.Fields(after)
			if !ok || len(left) < 6 || len(right) < 3 {
				continue
			}
			if v2 && right[0] != "cgroup2" || !v2 && (right[0] != "cgroup" || !hasController(right[2], controller)) {
				continue
			}
			root, point := unescapeMountPath(left[3]), unescapeMountPath(left[4])
			if !filepath.IsAbs(root) || !filepath.IsAbs(point) || filepath.Clean(root) != root || filepath.Clean(point) != point {
				continue
			}
			relative, err := filepath.Rel(root, member)
			// A cgroup namespace reports its own root as /, while mountinfo
			// may retain the host-side subtree root.
			if member == "/" {
				relative, err = ".", nil
			}
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				continue
			}
			file := v1File
			if v2 {
				file = v2File
			}
			current := filepath.Join(point, relative)
			// The smallest finite ancestor limit is the effective bound.
			for {
				paths = append(paths, filepath.Join(current, file))
				if current == point {
					break
				}
				current = filepath.Dir(current)
			}
		}
	}
	return paths
}

func hasController(controllers, wanted string) bool {
	for _, controller := range strings.Split(controllers, ",") {
		if controller == wanted {
			return true
		}
	}
	return false
}

func unescapeMountPath(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}
