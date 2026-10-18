package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

// Discovery is local routing, never create authorization or teardown evidence.
// In particular, do not load runtime credentials, check the old CLI executable,
// or remove a terminal/start fence to find the retained render.
func discoverDestroyDirectory(name, legacy string) (string, *clusterIntentTargets, error) {
	base, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(base) {
		return "", nil, errors.New("cannot locate managed runs; select --cluster-dir explicitly")
	}
	root := filepath.Join(base, "ok", "runs", name)
	for _, dir := range []string{filepath.Join(base, "ok"), filepath.Join(base, "ok", "runs"), root} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			return legacy, nil, nil
		}
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return "", nil, errors.New("managed run directories must be private and non-symlink; select reviewed --cluster-dir explicitly")
		}
	}
	preparation := filepath.Join(root, "preparation")
	directory := filepath.Join(preparation, name)
	for _, dir := range []string{preparation, directory} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return "", nil, errors.New("managed render is incomplete or unsafe; no fallback; select reviewed --cluster-dir explicitly")
		}
	}
	legacy, err = filepath.Abs(legacy)
	if err != nil {
		return "", nil, err
	}
	if legacy != directory {
		if _, err := os.Lstat(legacy); err == nil {
			return "", nil, errors.New("both managed and legacy cluster directories exist; select reviewed --cluster-dir explicitly")
		} else if !os.IsNotExist(err) {
			return "", nil, fmt.Errorf("cannot inspect legacy cluster directory: %w", err)
		}
	}
	raw, err := readPrivatePreparationFile(filepath.Join(preparation, "binding-receipt.json"))
	if err != nil {
		return "", nil, errors.New("managed binding receipt unavailable; no fallback")
	}
	var binding clusterIntentBindingReceipt
	if jsonstrict.Decode(raw, &binding) != nil || binding.Format != "ok-cli-cluster-static-binding/v1" ||
		binding.State != "CONTRACT_PROJECTION_BOUND_NO_GO" || binding.Identity.Name != name || binding.Identity.Namespace != name ||
		!sha256DigestPattern.MatchString(binding.NormalizedIntentDigest) || binding.Targets == nil ||
		binding.APIContacted || binding.MutationAllowed || binding.AuthorizationConsumed || binding.RunnerReady {
		return "", nil, errors.New("managed binding has no unambiguous name/plane targets; select reviewed --cluster-dir explicitly")
	}
	fixtureRaw, err := readPrivatePreparationFile(filepath.Join(preparation, "execution-fixture.json"))
	var fixture clusterIntentExecutionFixture
	if err != nil || jsonstrict.Decode(fixtureRaw, &fixture) != nil || fixture.Format != "ok-cli-local-execution-fixture/v2" ||
		fixture.AuthorizationState != "NO-GO" ||
		fixture.BindingReceiptDigest != digest.SHA256(raw) || fixture.ContractIdentity != binding.Identity || fixture.IntentRevision != binding.IntentRevision {
		return "", nil, errors.New("managed execution fixture differs from binding receipt; no fallback")
	}
	return directory, binding.Targets, nil
}

func verifyDestroyTargets(targets *clusterIntentTargets, management, provider string) error {
	if targets == nil {
		return nil // Explicit directory and legacy routing retain their contract.
	}
	for _, plane := range []struct {
		name, path string
		target     kubeconfigtarget.Target
	}{{"management", management, targets.Management}, {"infrastructure", provider, targets.Infrastructure}} {
		// The delegated Python lifecycle uses these files' current-context. Inspect
		// that exact identity without invoking kubectl or an authentication plugin.
		current, err := kubeconfigtarget.ReadCurrent(plane.path)
		if err != nil || current != plane.target {
			return fmt.Errorf("%s kubeconfig effective target differs from managed preparation or cannot be verified; no teardown", plane.name)
		}
	}
	return nil
}
