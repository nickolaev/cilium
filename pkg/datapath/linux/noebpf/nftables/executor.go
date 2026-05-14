// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes nft(8). It exists so the Phase 0 executor can be tested
// without requiring CAP_NET_ADMIN in unit tests.
type Runner interface {
	Run(ctx context.Context, args []string, stdin string) ([]byte, error)
}

// CommandRunner runs the host nft(8) binary.
type CommandRunner struct {
	Path string
}

func (r CommandRunner) Run(ctx context.Context, args []string, stdin string) ([]byte, error) {
	path := r.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// Apply replaces the owned cilium_noebpf table with the rendered desired state.
// It intentionally deletes only the dedicated table before creating it again,
// which keeps the compatibility surface small for nft v1.0.6 in kind.
func Apply(ctx context.Context, runner Runner, state DesiredState) error {
	if runner == nil {
		runner = CommandRunner{}
	}

	script, err := Render(state)
	if err != nil {
		return err
	}

	if out, err := runner.Run(ctx, []string{"list", "table", "inet", TableName}, ""); err == nil {
		if out, err := runner.Run(ctx, []string{"delete", "table", "inet", TableName}, ""); err != nil {
			return fmt.Errorf("delete existing nftables table %s: %w: %s", TableName, err, bytes.TrimSpace(out))
		}
	} else if !isMissingTableError(out) {
		return fmt.Errorf("inspect nftables table %s: %w: %s", TableName, err, bytes.TrimSpace(out))
	}

	if out, err := runner.Run(ctx, []string{"-f", "-"}, script); err != nil {
		return fmt.Errorf("apply nftables table %s: %w: %s", TableName, err, bytes.TrimSpace(out))
	}
	return nil
}

func isMissingTableError(out []byte) bool {
	msg := string(out)
	return strings.Contains(msg, "No such file or directory") ||
		strings.Contains(msg, "No such file") ||
		strings.Contains(msg, "does not exist")
}
