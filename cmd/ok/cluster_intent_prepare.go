package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/submission"
)

type localCLIFixtureRunner struct {
	ExecutionMode             string `json:"executionMode"`
	Version                   string `json:"version"`
	SourceRevision            string `json:"sourceRevision"`
	BinaryDigest              string `json:"binaryDigest"`
	ImagePublicationPerformed bool   `json:"imagePublicationPerformed"`
}

// This fixture is a content identity for local inputs, not a unique execution
// attempt, image publication proof, stage receipt or authorization.
type clusterIntentExecutionFixture struct {
	Format               string                `json:"format"`
	AuthorizationState   string                `json:"authorizationState"`
	ContractIdentity     contract.Identity     `json:"contractIdentity"`
	IntentRevision       string                `json:"intentRevision"`
	BindingReceiptDigest string                `json:"bindingReceiptDigest"`
	Runner               localCLIFixtureRunner `json:"runner"`
}

type clusterIntentPreparationReceipt struct {
	Format                     string            `json:"format"`
	State                      string            `json:"state"`
	ContractIdentity           contract.Identity `json:"contractIdentity"`
	IntentRevision             string            `json:"intentRevision"`
	BindingReceiptDigest       string            `json:"bindingReceiptDigest"`
	ExecutionFixtureDigest     string            `json:"executionFixtureDigest"`
	ProviderAccessPolicyDigest string            `json:"providerAccessPolicyDigest"`
	APIContacted               bool              `json:"apiContacted"`
	AuthorizationConsumed      bool              `json:"authorizationConsumed"`
	MutationAllowed            bool              `json:"mutationAllowed"`
	RunnerReady                bool              `json:"runnerReady"`
	Missing                    []string          `json:"missingBindings"`
}

func runClusterIntentPrepare(ctx context.Context, arguments []string, output string, stdout, stderr io.Writer) error {
	// Hash only this running executable, not a configured external runner or a
	// previous Candidate binary. No source checkout or image identity is guessed.
	executable, err := os.Executable()
	if err != nil {
		return errors.New("identify local CLI executable")
	}
	binaryDigest, err := localCLIExecutableDigest(executable)
	if err != nil {
		return err
	}
	var bound bytes.Buffer
	if err := runClusterIntentBind(ctx, arguments, &bound, stderr); err != nil {
		return err
	}
	var binding clusterIntentBindingReceipt
	if err := json.Unmarshal(bound.Bytes(), &binding); err != nil {
		return errors.New("decode internally verified static binding; partial output retained")
	}
	root, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	fixture := clusterIntentExecutionFixture{
		Format: "ok-cli-local-execution-fixture/v1", AuthorizationState: "NO-GO",
		ContractIdentity: binding.Identity, IntentRevision: binding.IntentRevision,
		BindingReceiptDigest: digest.SHA256(bound.Bytes()),
		Runner:               localCLIFixtureRunner{ExecutionMode: "local-cli", Version: version, SourceRevision: revision, BinaryDigest: binaryDigest},
	}
	fixtureRaw, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	fixtureRaw = append(fixtureRaw, '\n')
	fixtureDigest := digest.SHA256(fixtureRaw)
	policyRaw, err := submission.BuildProviderAccessPolicy(submission.ProviderAccessPolicyConfig{
		ContractIdentity: binding.Identity, IntentRevision: binding.IntentRevision, ExecutionFixture: fixtureDigest,
		ManagementAuthority: binding.Projection.ManagementPlane.Identity,
		ProviderAuthority:   binding.Projection.InfrastructurePlane.Identity,
	})
	if err != nil {
		return errors.New("build owning provider-access policy; partial output retained")
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{"execution-fixture.json", fixtureRaw}, {"provider-access-policy.json", policyRaw},
	} {
		if err := writeStaticBindingFile(filepath.Join(root, file.name), file.raw); err != nil {
			return err
		}
	}
	receipt := clusterIntentPreparationReceipt{
		Format: "ok-cli-cluster-preparation/v1", State: "LOCAL_EXECUTION_INPUTS_BOUND_NO_GO",
		ContractIdentity: binding.Identity, IntentRevision: binding.IntentRevision, BindingReceiptDigest: fixture.BindingReceiptDigest,
		ExecutionFixtureDigest: fixtureDigest, ProviderAccessPolicyDigest: digest.SHA256(policyRaw),
		Missing: []string{"enablement/network/target-access artifacts", "seven-stage Plan", "reviewed authority policies and existing credentials", "full-run manifest and independent evidence inputs"},
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeStaticBindingFile(filepath.Join(root, "preparation-receipt.json"), raw); err != nil {
		return err
	}
	if _, err := stdout.Write(raw); err != nil {
		return err
	}
	return errors.New("YAML preparation incomplete (NO-GO): local fixture and provider-access policy bound; full Plan, stage artifacts, authority, credential and independent evidence bindings are still required; no live approval digest was produced")
}

func localCLIExecutableDigest(path string) (string, error) {
	const maximumExecutableBytes = 256 * 1024 * 1024
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("open local CLI executable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumExecutableBytes {
		return "", errors.New("local CLI executable must be a bounded regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maximumExecutableBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("local CLI executable changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
