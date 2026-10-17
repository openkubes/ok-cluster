package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/runner"
	"golang.org/x/term"
)

var prepareGuidedClusterIntent = runClusterIntentPrepare
var verifyGuidedEvidenceKey = runner.VerifyIndependentEvidencePublicKey

type guidedUpRuntime struct {
	input    io.Reader
	terminal bool
}

// Private path metadata, not a grant, retry state or operation outcome.
type guidedUpPreparation struct {
	Format              string `json:"format"`
	IntentDigest        string `json:"intentDigest"`
	ManifestDigest      string `json:"manifestDigest"`
	RuntimeInputsPath   string `json:"runtimeInputsPath"`
	RuntimeInputsDigest string `json:"runtimeInputsDigest"`
	EvidenceKeyID       string `json:"evidenceKeyId"`
}

func runGuidedClusterUp(ctx context.Context, path string, stdout, stderr io.Writer) error {
	return runAutomaticClusterUp(ctx, path, stdout, stderr, guidedUpRuntime{os.Stdin, term.IsTerminal(int(os.Stdin.Fd()))}, false)
}

func runGuidedClusterUpWithRuntime(ctx context.Context, path string, stdout, stderr io.Writer, runtime guidedUpRuntime) error {
	if !runtime.terminal || runtime.input == nil {
		return errors.New("guided ok up requires a terminal; use --dry-run or the explicit expert --prepare/--live workflow in scripts")
	}
	intent, err := readClusterIntent(path)
	if err != nil {
		return err
	}
	intentRaw, _ := json.Marshal(intent)
	intentDigest := digest.SHA256(intentRaw)
	stateBase, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(stateBase) {
		return errors.New("user configuration directory must be absolute; no preparation created")
	}
	root := filepath.Join(stateBase, "ok", "runs", intent.Metadata.Name)
	for _, parent := range []string{filepath.Join(stateBase, "ok"), filepath.Join(stateBase, "ok", "runs")} {
		info, err := os.Lstat(parent)
		if os.IsNotExist(err) {
			break
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("managed preparation parent must be private and non-symlink; not reused")
		}
	}
	reader := bufio.NewReaderSize(runtime.input, 4096)
	var setup guidedUpPreparation
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("managed preparation directory is not private; not reused")
		}
		if err := guidedUpNotStarted(root); err != nil {
			return err
		}
		raw, err := readPrivatePreparationFile(filepath.Join(root, "managed-preparation.json"))
		if err != nil || jsonstrict.Decode(raw, &setup) != nil {
			return fmt.Errorf("existing incomplete preparation retained at %q; no automatic rendering or retry; expert review required", root)
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if _, err := readClusterIntentTargets(path, intent); err != nil {
			return err
		}
		configPath, err := localConfigPath("")
		if err != nil {
			return err
		}
		sources, err := loadLocalConfig(configPath)
		if err != nil {
			return errors.New("guided preparation needs trusted source paths; run ok config init first (no credentials are inferred from config)")
		}
		if _, err := fmt.Fprintln(stderr, "Prepare locally first; no cluster contact or credential renewal.\nSelect existing reviewed files (literal paths, not credential contents)."); err != nil {
			return err
		}
		contractPath, err := guidedUpPath(ctx, reader, stderr, "Reviewed Contract file")
		if err != nil {
			return err
		}
		runtimePath, err := guidedUpPath(ctx, reader, stderr, "Private runtime references file")
		if err != nil {
			return err
		}
		// Validate supplied files before reserving a create-only managed directory.
		if _, err := readIntentBindingFile(contractPath); err != nil {
			return err
		}
		if _, err := readPrivatePreparationFile(runtimePath); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, dir := range []string{filepath.Join(stateBase, "ok"), filepath.Join(stateBase, "ok", "runs")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return errors.New("managed preparation parent must be private and non-symlink; permissions are never changed")
			}
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return errors.New("managed preparation already exists or cannot be reserved; no retry")
		}
		var output bytes.Buffer
		if err := prepareGuidedClusterIntent(ctx, []string{"--file", path, "--contract", contractPath, "--runtime-inputs", runtimePath, "--output", filepath.Join(root, "preparation"), "--lifecycle-root", sources.LifecycleRoot, "--ok-linux-path", sources.OKLinuxPath}, &output, stderr); err != nil {
			return fmt.Errorf("local preparation incomplete; retained at %q; no automatic retry: %w", root, err)
		}
		var handoff struct {
			Format                      string `json:"format"`
			State                       string `json:"state"`
			ManifestDigest              string `json:"manifestDigest"`
			RuntimeInputsDigest         string `json:"runtimeInputsDigest"`
			EvidenceKeyID               string `json:"independentEvidenceKeyId"`
			APIContacted                bool   `json:"apiContacted"`
			MutationAllowed             bool   `json:"mutationAllowed"`
			LiveAuthorized              bool   `json:"liveAuthorized"`
			AuthorizationConsumed       bool   `json:"authorizationConsumed"`
			AuthorityDeploymentVerified bool   `json:"authorityDeploymentVerified"`
			RunnerReady                 bool   `json:"runnerReady"`
		}
		if json.Unmarshal(output.Bytes(), &handoff) != nil || handoff.Format != "ok-cli-cluster-runner-handoff/v1" || handoff.State != "PREPARED_NOT_AUTHORIZED" || !handoff.RunnerReady || handoff.APIContacted || handoff.MutationAllowed || handoff.LiveAuthorized || handoff.AuthorizationConsumed || handoff.AuthorityDeploymentVerified || !sha256DigestPattern.MatchString(handoff.ManifestDigest) || !sha256DigestPattern.MatchString(handoff.EvidenceKeyID) || !sha256DigestPattern.MatchString(handoff.RuntimeInputsDigest) {
			return errors.New("guided preparation did not produce a non-authorizing verified handoff; partial files retained")
		}
		setup = guidedUpPreparation{"ok-cli-managed-preparation/v1", intentDigest, handoff.ManifestDigest, runtimePath, handoff.RuntimeInputsDigest, handoff.EvidenceKeyID}
		raw, _ := json.MarshalIndent(setup, "", "  ")
		if err := writeStaticBindingFile(filepath.Join(root, "managed-preparation.json"), raw); err != nil {
			return err
		}
	}
	if setup.Format != "ok-cli-managed-preparation/v1" || setup.IntentDigest != intentDigest || !sha256DigestPattern.MatchString(setup.ManifestDigest) {
		return errors.New("YAML differs from managed preparation or metadata is invalid; no new render or automatic retry")
	}
	if err := guidedUpNotStarted(root); err != nil {
		return err
	}
	prepared, err := resolvePreparedClusterIntent(path, filepath.Join(root, "preparation"), setup.ManifestDigest)
	if err != nil {
		return err
	}
	if prepared.Binding.NormalizedIntentDigest != intentDigest {
		return errors.New("YAML changed during local preparation; no execution and no automatic retry")
	}
	keyPath, err := guidedUpEvidencePath(setup)
	if err != nil {
		return err
	}
	marker := filepath.Join(root, "executor-terminal")
	if err := validateClusterCreateTerminalMarker(marker); err != nil {
		return err
	}
	if targets := prepared.Binding.Targets; targets != nil {
		if _, err := fmt.Fprintf(stderr, "\nSelected management context %q -> %q\nSelected infrastructure context %q -> %q\n", targets.Management.Context, targets.Management.Endpoint, targets.Infrastructure.Context, targets.Infrastructure.Endpoint); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stderr, "\nCreate cluster %q\n  Profile: %s (1 control plane, 1 worker; each 2 CPU / 4Gi RAM / 20Gi disk)\n  Endpoint: %s\n  Pod CIDR: %s; service CIDR: %s\n  Infrastructure authority: %q; management authority: %q\n  Preparation: %q\n  Manifest: %s\n  Independent evidence key: %s (%q)\n\nThis may install shared provider prerequisites/RBAC access and create infrastructure, VMs and workload/network resources.\nLocal verification does NOT prove name/IP availability, deployed authority, valid access or convergence.\nConfirm you have separately reviewed name/IP absence and authority deployment and approve this exact plan.\nNo automatic retry, rollback or credential renewal.\nType ok to create, or no [no]: ", intent.Metadata.Name, intent.Spec.Profile, intent.Spec.Network.Endpoint, intent.Spec.Network.PodCIDR, intent.Spec.Network.ServiceCIDR, prepared.Binding.Projection.InfrastructurePlane.Identity, prepared.Binding.Projection.ManagementPlane.Identity, root, setup.ManifestDigest, setup.EvidenceKeyID, keyPath); err != nil {
		return err
	}
	answer, err := guidedUpLine(ctx, reader)
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != "ok" {
		return errors.New("cluster creation cancelled; no runner started; local preparation retained")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Recheck mutable inputs after human review, before recording a single start.
	prepared, err = resolvePreparedClusterIntent(path, filepath.Join(root, "preparation"), setup.ManifestDigest)
	if err != nil {
		return err
	}
	if prepared.Binding.NormalizedIntentDigest != intentDigest {
		return errors.New("YAML changed after review; no execution")
	}
	if _, err := guidedUpEvidencePath(setup); err != nil {
		return err
	}
	if err := validateClusterCreateTerminalMarker(marker); err != nil {
		return err
	}
	started, _ := json.Marshal(struct {
		Format         string `json:"format"`
		ManifestDigest string `json:"manifestDigest"`
	}{"ok-cli-managed-execution-start/v1", setup.ManifestDigest})
	if err := writeStaticBindingFile(filepath.Join(root, "execution-started.json"), started); err != nil {
		return errors.New("execution already claimed or start fence could not be persisted; no automatic retry")
	}
	for _, parent := range []string{root, filepath.Dir(root), filepath.Dir(filepath.Dir(root))} {
		dir, err := os.Open(parent)
		if err != nil {
			return err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return fmt.Errorf("cannot sync execution start fence; no runner started and no automatic retry: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return executeClusterCreateLive(ctx, clusterCreateLiveConfig{ManifestPath: prepared.ManifestPath, ExpectedManifestDigest: setup.ManifestDigest, IndependentEvidencePublicKey: keyPath, TerminalMarker: marker}, stdout, stderr)
}

func guidedUpNotStarted(root string) error {
	for _, name := range []string{"execution-started.json", "executor-terminal"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			return fmt.Errorf("a managed execution already started or stopped at %q; evidence retained; no automatic retry or replay", root)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func guidedUpEvidencePath(setup guidedUpPreparation) (string, error) {
	if !filepath.IsAbs(setup.RuntimeInputsPath) {
		return "", errors.New("managed runtime references must be explicit absolute paths")
	}
	raw, err := readPrivatePreparationFile(setup.RuntimeInputsPath)
	if err != nil || digest.SHA256(raw) != setup.RuntimeInputsDigest {
		return "", errors.New("runtime references changed since preparation; no execution")
	}
	var refs struct {
		Path string `json:"independentEvidencePublicKeyPath"`
	}
	if json.Unmarshal(raw, &refs) != nil || !filepath.IsAbs(refs.Path) {
		return "", errors.New("missing explicit independent evidence public key path")
	}
	if err := verifyGuidedEvidenceKey(refs.Path, setup.EvidenceKeyID); err != nil {
		return "", err
	}
	return refs.Path, nil
}

func guidedUpPath(ctx context.Context, reader *bufio.Reader, output io.Writer, label string) (string, error) {
	if _, err := fmt.Fprintf(output, "%s: ", label); err != nil {
		return "", err
	}
	line, err := guidedUpLine(ctx, reader)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("an existing literal file path is required; creation cancelled")
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if value == "~" {
			value = home
		} else {
			value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return filepath.Abs(value)
}

func guidedUpLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	answer := make(chan result, 1)
	go func() { line, err := reader.ReadSlice('\n'); answer <- result{string(line), err} }()
	select {
	case <-ctx.Done():
		return "", errors.New("cluster creation interrupted; no runner started")
	case value := <-answer:
		if value.err != nil {
			return "", errors.New("cluster creation input ended or exceeded 4096 bytes; no runner started")
		}
		return strings.TrimSuffix(strings.TrimSuffix(value.line, "\n"), "\r"), nil
	}
}
