//go:build !darwin && !linux

package main

import (
	"context"
	"errors"
	"os/exec"
)

func clusterProvisionSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

func configureClusterProvisionProcess(command *exec.Cmd) {}

func lockProvisionAllocation(string) (func(), error) {
	return nil, errors.New("ok up provisioning requires macOS or Linux")
}
