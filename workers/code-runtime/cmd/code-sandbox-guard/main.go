// code-sandbox-guard installs kernel path restrictions before an interpreter.
// The immutable execution image and controller choose the language; untrusted
// code is read only from the existing stdin after all restrictions succeed.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Only fixed setup-stage names may leave the guard. Never include paths,
// environment values, code input or the raw underlying exception.
type guardFailure struct {
	stage string
	cause error
}

func (e *guardFailure) Error() string { return "code filesystem guard setup failed" }
func (e *guardFailure) Unwrap() error { return e.cause }
func guardStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &guardFailure{stage: stage, cause: err}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "CODE_FILESYSTEM_GUARD_DENIED")
		os.Exit(125)
	}
	if err := launch(os.Args[1]); err != nil {
		var failure *guardFailure
		if errors.As(err, &failure) {
			fmt.Fprintln(os.Stderr, "CODE_FILESYSTEM_GUARD_DENIED", "stage="+failure.stage)
		} else {
			fmt.Fprintln(os.Stderr, "CODE_FILESYSTEM_GUARD_DENIED")
		}
		os.Exit(125)
	}
}
