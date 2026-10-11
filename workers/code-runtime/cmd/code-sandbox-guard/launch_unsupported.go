//go:build !linux || (!amd64 && !arm64)

package main

import "errors"

func launch(string) error { return errors.New("unsupported isolated execution host") }
