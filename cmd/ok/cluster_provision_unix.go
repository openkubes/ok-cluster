//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
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

// lockProvisionAllocation takes a non-blocking exclusive flock on
// <clusters>/.allocate.lock. It serializes allocation for this user on this
// machine only; independent machines or operators are not coordinated.
func lockProvisionAllocation(clustersDir string) (func(), error) {
	if err := ensurePrivateDirs(filepath.Dir(clustersDir), clustersDir); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(clustersDir, ".allocate.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another ok up on this machine is allocating a cluster network; try again when it has finished")
	}
	var once sync.Once
	return func() { once.Do(func() { file.Close() }) }, nil
}
