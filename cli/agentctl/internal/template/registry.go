// Package template validates the immutable local template registry.
// template 包校验不可变本地模板注册表。
package template

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Registry struct{ Root string }

func Load(root string) (Registry, error) {
	root = filepath.Clean(root)
	if root == "." || strings.TrimSpace(root) == "" {
		return Registry{}, errors.New("template root is required")
	}
	if info, err := os.Stat(filepath.Join(root, "registry", "index.yaml")); err != nil || !info.Mode().IsRegular() {
		return Registry{}, errors.New("template registry index is missing")
	}
	return Registry{Root: root}, nil
}

func (r Registry) Verify() error {
	if r.Root == "" {
		return errors.New("template registry is not loaded")
	}
	return filepath.WalkDir(r.Root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template symlink is not allowed: %s", path)
		}
		if filepath.Ext(path) == ".json" {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var value any
			if json.Unmarshal(data, &value) != nil {
				return fmt.Errorf("invalid template JSON: %s", path)
			}
		}
		return nil
	})
}
