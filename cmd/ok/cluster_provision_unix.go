//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func clusterProvisionSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func configureClusterProvisionProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 2 * time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		if err == nil {
			// Make may otherwise leave recipe children running after the CLI exits.
			// Terminate only this command's isolated process group.
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			return nil
		}
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
}
