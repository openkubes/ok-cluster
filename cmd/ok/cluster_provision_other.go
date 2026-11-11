//go:build !darwin && !linux

package main

import (
	"context"
	"os/exec"
)

func clusterProvisionSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

func configureClusterProvisionProcess(command *exec.Cmd) {}
