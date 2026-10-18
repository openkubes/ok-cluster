package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

var verifyPreparedManifestFixture = func(path string, fixture []byte) (runner.FullRunExecutionManifestReceipt, error) {
	verified, receipt, err := runner.LoadFullRunExecutionManifest(path)
	if err != nil {
		return receipt, err
	}
	return receipt, verified.VerifyExecutionFixture(fixture)
}

// Bind the current friendly intent through the immutable fixture to the
// existing runner manifest. Receipt command hints are never execution inputs.
type preparedClusterIntent struct {
	ManifestPath string
	Receipt      runner.FullRunExecutionManifestReceipt
	Binding      clusterIntentBindingReceipt
}

func resolvePreparedClusterIntent(intentPath, directory, expectedDigest string) (preparedClusterIntent, error) {
	var result preparedClusterIntent
	intent, err := readClusterIntent(intentPath)
	if err != nil {
		return result, err
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return result, errors.New("--prepared-dir must be an existing private non-symlink directory")
	}
	fixtureRaw, err := readPrivatePreparationFile(filepath.Join(root, "execution-fixture.json"))
	if err != nil {
		return result, err
	}
	var fixture clusterIntentExecutionFixture
	if jsonstrict.Decode(fixtureRaw, &fixture) != nil || fixture.Format != "ok-cli-local-execution-fixture/v2" || fixture.AuthorizationState != "NO-GO" {
		return result, errors.New("prepared YAML requires a fresh local v2 execution fixture")
	}
	bindingRaw, err := readPrivatePreparationFile(filepath.Join(root, "binding-receipt.json"))
	if err != nil {
		return result, err
	}
	var binding clusterIntentBindingReceipt
	if jsonstrict.Decode(bindingRaw, &binding) != nil || binding.Format != "ok-cli-cluster-static-binding/v1" || binding.State != "CONTRACT_PROJECTION_BOUND_NO_GO" ||
		binding.APIContacted || binding.AuthorizationConsumed || binding.MutationAllowed || binding.RunnerReady ||
		digest.SHA256(bindingRaw) != fixture.BindingReceiptDigest || fixture.ContractIdentity != binding.Identity || fixture.IntentRevision != binding.IntentRevision {
		return result, errors.New("prepared YAML binding differs from its immutable fixture")
	}
	intentRaw, err := json.Marshal(intent)
	if (intent.Spec.Management == nil) != (binding.Targets == nil) {
		return result, errors.New("prepared binding must retain exactly the selected YAML target references")
	}
	if err != nil || digest.SHA256(intentRaw) != binding.NormalizedIntentDigest || binding.Identity.Name != intent.Metadata.Name || binding.Identity.Namespace != intent.Metadata.Name {
		return result, errors.New("cluster YAML differs from the prepared intent; no rendering, replay or execution performed")
	}
	path := filepath.Join(root, "full-run-manifest.json")
	if _, err := readPrivatePreparationFile(path); err != nil {
		return result, err
	}
	receipt, err := verifyPreparedManifestFixture(path, fixtureRaw)
	if err != nil || !validFullRunManifestReceiptFormat(receipt.Format) || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		receipt.CompletionMode != stageplan.CompletionModeBareClusterMVP || receipt.ExecutionAttemptDigest != "" ||
		!sha256DigestPattern.MatchString(receipt.ManifestDigest) || (expectedDigest != "" && expectedDigest != receipt.ManifestDigest) {
		return result, errors.New("prepared YAML manifest/fixture verification failed or differs from the approved digest")
	}
	if err := verifyClusterIntentTargets(intentPath, binding, path, receipt.ManifestDigest); err != nil {
		return result, err
	}
	return preparedClusterIntent{ManifestPath: path, Receipt: receipt, Binding: binding}, nil
}

func readPrivatePreparationFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1024*1024 {
		return nil, errors.New("prepared inputs must be bounded private regular non-symlink files")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("prepared input changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, errors.New("cannot read bounded prepared input")
	}
	return raw, nil
}
