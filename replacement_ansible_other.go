//go:build !unix

package guard

import (
	"context"
	"os/exec"
)

const replacementAnsibleSupported = false

func replacementCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
