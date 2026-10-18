package runner

import (
	"bytes"
	"errors"
	"os"
)

func writeExclusivePrivateMaterial(path string, raw []byte) error {
	if len(raw) == 0 || validateRuntimeBindingOutputPath(path) != nil {
		return errors.New("private workload authority output is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create exclusive private workload authority output")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return errors.New("write private workload authority output")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync private workload authority output")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private workload authority output")
	}
	stored, err := readBoundedRegular(path, int64(len(raw)))
	if err != nil || !bytes.Equal(stored, raw) {
		return errors.New("private workload authority output differs after write")
	}
	return nil
}
