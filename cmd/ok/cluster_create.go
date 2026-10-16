package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const clusterCreateWorkflowFormat = "ok-cli-cluster-create/v1"
const clusterCreateRequirementsFormat = "ok-cli-cluster-create-requirements/v1"

type clusterCreateRequirements struct {
	Format                      string                               `json:"format"`
	Operation                   string                               `json:"operation"`
	AcceptedManifestFormats     []string                             `json:"acceptedManifestFormats"`
	RequiredCompletionMode      string                               `json:"requiredCompletionMode"`
	ManifestPathRules           []string                             `json:"manifestPathRules"`
	RequiredManifestSections    []string                             `json:"requiredManifestSections"`
	UnusedPostRuntimeSections   []string                             `json:"unusedPostRuntimeSections"`
	OfflineModes                []string                             `json:"offlineModes"`
	OfflineAPIContacted         bool                                 `json:"offlineApiContacted"`
	OfflineMutationAllowed      bool                                 `json:"offlineMutationAllowed"`
	LiveRequiredFlags           []string                             `json:"liveRequiredFlags"`
	TerminalMarkerName          string                               `json:"terminalMarkerName"`
	LiveStageOrder              []string                             `json:"liveStageOrder"`
	AcceptedPlanStageCounts     []int                                `json:"acceptedPlanStageCounts"`
	PreferredPlanStageCount     int                                  `json:"preferredPlanStageCount"`
	PostRuntimeMaterialRequired bool                                 `json:"postRuntimeMaterialRequired"`
	LiveMutationAllowed         bool                                 `json:"liveMutationAllowed"`
	ProviderAccessOwnership     clusterCreateProviderAccessOwnership `json:"providerAccessOwnership"`
}

// Descriptive requirements metadata only: this adds no manifest input,
// credential capability, renewal path or execution gate.
type clusterCreateProviderAccessOwnership struct {
	LifecycleOwner                       string   `json:"lifecycleOwner"`
	RequiredAfterExecution               bool     `json:"requiredAfterExecution"`
	AutomaticRenewalByCLI                bool     `json:"automaticRenewalByCli"`
	OfflineValidationProvesOngoingAccess bool     `json:"offlineValidationProvesOngoingAccess"`
	OperatorHandoff                      []string `json:"operatorHandoff"`
}

type clusterCreateWorkflowReceipt struct {
	Format                string `json:"format"`
	Operation             string `json:"operation"`
	Mode                  string `json:"mode"`
	State                 string `json:"state"`
	ManifestDigest        string `json:"manifestDigest"`
	PlanDigest            string `json:"planDigest"`
	CompletionMode        string `json:"completionMode"`
	APIContacted          bool   `json:"apiContacted"`
	AuthorizationConsumed bool   `json:"authorizationConsumed"`
	MutationAllowed       bool   `json:"mutationAllowed"`
	NextAction            string `json:"nextAction"`
}

type clusterCreateLiveConfig struct {
	ManifestPath                 string
	ExpectedManifestDigest       string
	IndependentEvidencePublicKey string
	TerminalMarker               string
}

var executeClusterCreateLive = func(ctx context.Context, config clusterCreateLiveConfig, stdout, stderr io.Writer) error {
	return runClusterStageRunFullExecute(ctx, []string{
		"--manifest", config.ManifestPath,
		"--expected-manifest-digest", config.ExpectedManifestDigest,
		"--independent-evidence-public-key", config.IndependentEvidencePublicKey,
		"--terminal-marker", config.TerminalMarker,
		"--execute",
	}, stdout, stderr)
}

var validateClusterCreateTerminalMarker = runner.ValidateFullRunExecutorTerminalMarkerDestination

func runClusterCreateRequirements(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("ok cluster create requirements accepts no flags or positional arguments")
	}
	requirements := clusterCreateRequirements{
		Format: clusterCreateRequirementsFormat, Operation: "CreateCluster",
		AcceptedManifestFormats: []string{runner.FullRunExecutionManifestFormat, runner.FullRunExecutionManifestFormatV4},
		RequiredCompletionMode:  stageplan.CompletionModeBareClusterMVP,
		ManifestPathRules: []string{
			"absolute path", "regular non-symlink file", "owner-only permissions (0600 or stricter)",
			"all referenced private inputs present and digest-bound",
		},
		RequiredManifestSections: []string{
			"format", "plan", "projection", "authorization", "profiles.network", "providerPrerequisites",
			"providerAccess", "clusterLifecycle", "lifecycleObservation", "enablement", "networkObservation",
			"runtimeBinding", "targetAccess", "receiptDirectory",
		},
		UnusedPostRuntimeSections: []string{
			"profiles.platform", "profiles.aggregate", "targetCredential", "targetRegistration",
			"platformApplications", "observabilityCredentials", "platformObservation", "aggregateEvidence",
			"observabilityCollector",
		},
		OfflineModes: []string{"--dry-run", "--prepare"}, OfflineAPIContacted: false, OfflineMutationAllowed: false,
		LiveRequiredFlags: []string{
			"--live", "--execute", "--expected-manifest-digest", "--independent-evidence-public-key", "--terminal-marker",
		},
		TerminalMarkerName: runner.FullRunExecutorTerminalMarkerName,
		LiveStageOrder: []string{
			"provider-prerequisites", "cluster-lifecycle", "lifecycle-observation", "enablement",
			"network-observation", "runtime-binding", "target-access",
		},
		AcceptedPlanStageCounts: []int{stageplan.BareClusterStageCount, 12}, PreferredPlanStageCount: stageplan.BareClusterStageCount,
		PostRuntimeMaterialRequired: false, LiveMutationAllowed: true,
		ProviderAccessOwnership: clusterCreateProviderAccessOwnership{
			LifecycleOwner: "lifecycle-operator", RequiredAfterExecution: true,
			AutomaticRenewalByCLI: false, OfflineValidationProvesOngoingAccess: false,
			OperatorHandoff: []string{"provider credential validity window", "credential rotation responsibility", "current convergence evidence"},
		},
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(requirements)
}

func runClusterCreateWorkflow(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if countClusterCreateFileFlags(arguments) != 1 {
		return errors.New("exactly one --file or -f input is required")
	}
	flags := flag.NewFlagSet("ok cluster create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var manifestPath string
	flags.StringVar(&manifestPath, "file", "", "private Bare-MVP full-run manifest")
	flags.StringVar(&manifestPath, "f", "", "private Bare-MVP full-run manifest (shorthand)")
	dryRun := flags.Bool("dry-run", false, "verify locally and emit a non-mutating summary")
	prepare := flags.Bool("prepare", false, "verify locally and emit the identity required by live mode")
	live := flags.Bool("live", false, "select live cluster execution")
	execute := flags.Bool("execute", false, "explicitly authorize the selected live execution")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact digest emitted by --prepare")
	evidencePublicKey := flags.String("independent-evidence-public-key", "", "pinned independent evidence public key")
	terminalMarker := flags.String("terminal-marker", "", "new create-only private terminal marker")
	// YAML preparation inputs are local-only; never passed to the JSON runner.
	yamlInputs := map[string]*string{}
	for _, name := range []string{"contract", "output", "lifecycle-root", "ok-linux-path", "config"} {
		yamlInputs[name] = flags.String(name, "", "local YAML preparation input")
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if manifestPath == "" {
		return errors.New("--file is required")
	}
	modeCount := 0
	for _, selected := range []bool{*dryRun, *prepare, *live} {
		if selected {
			modeCount++
		}
	}
	if modeCount != 1 {
		return errors.New("exactly one of --dry-run, --prepare, or --live is required")
	}
	if !*live && (*execute || *expectedManifestDigest != "" || *evidencePublicKey != "" || *terminalMarker != "") {
		return errors.New("--execute and live-only inputs require --live")
	}
	yamlInputSelected := false
	flags.Visit(func(f *flag.Flag) {
		if _, ok := yamlInputs[f.Name]; ok {
			yamlInputSelected = true
		}
	})
	isYAML := isClusterYAMLFile(manifestPath)
	if yamlInputSelected && (!isYAML || !*prepare) {
		return errors.New("--contract, --output and local source paths are only accepted with YAML --prepare")
	}
	if isYAML && *prepare {
		if _, err := readClusterIntent(manifestPath); err != nil {
			return err
		}
		if *yamlInputs["contract"] == "" || *yamlInputs["output"] == "" {
			return errors.New("YAML preparation is NO-GO: currently requires an explicit reviewed --contract and new --output directory; full runner preparation is not yet implemented")
		}
		material := []string{"--file", manifestPath}
		for _, name := range []string{"contract", "output", "lifecycle-root", "ok-linux-path", "config"} {
			flags.Visit(func(f *flag.Flag) {
				if f.Name == name {
					material = append(material, "--"+name, *yamlInputs[name])
				}
			})
		}
		if err := runClusterIntentBind(ctx, material, stdout, stderr); err != nil {
			return err
		}
		return errors.New("YAML preparation incomplete (NO-GO): static Contract/projection receipt written; full Plan, fixture, authority, credential and independent evidence bindings are still required; no live approval digest was produced")
	}
	if isYAML {
		return validateClusterYAMLWorkflow(manifestPath, *dryRun, stdout)
	}
	if *live {
		if !*execute {
			return errors.New("live cluster creation requires explicit --live --execute")
		}
		if !sha256DigestPattern.MatchString(*expectedManifestDigest) || *evidencePublicKey == "" || *terminalMarker == "" {
			return errors.New("--live requires a lowercase SHA-256 --expected-manifest-digest, --independent-evidence-public-key, and --terminal-marker")
		}
		if err := validateClusterCreateTerminalMarker(*terminalMarker); err != nil {
			return errors.New("--terminal-marker must be an absent executor-terminal file in an existing private directory")
		}
	}

	manifest, err := prepareFullRunExecutionManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("verify Bare-MVP manifest: %w", err)
	}
	if !validFullRunManifestReceiptFormat(manifest.Format) || manifest.State != "VERIFIED" || manifest.MutationAllowed {
		return errors.New("Bare-MVP manifest preparation did not verify")
	}
	if manifest.CompletionMode != stageplan.CompletionModeBareClusterMVP {
		return fmt.Errorf("cluster create requires completionMode %q", stageplan.CompletionModeBareClusterMVP)
	}

	if *live {
		if manifest.ManifestDigest != *expectedManifestDigest {
			return errors.New("Bare-MVP manifest differs from the prepared identity")
		}
		return executeClusterCreateLive(ctx, clusterCreateLiveConfig{
			ManifestPath: manifestPath, ExpectedManifestDigest: *expectedManifestDigest,
			IndependentEvidencePublicKey: *evidencePublicKey, TerminalMarker: *terminalMarker,
		}, stdout, stderr)
	}

	mode, state := "dry-run", "VALIDATED"
	nextAction := "review the validated identities, then run --prepare with the same file"
	if *prepare {
		mode, state = "prepare", "PREPARED"
		nextAction = "obtain separate live approval; pass manifestDigest as --expected-manifest-digest"
	}
	receipt := clusterCreateWorkflowReceipt{
		Format: clusterCreateWorkflowFormat, Operation: "CreateCluster", Mode: mode, State: state,
		ManifestDigest: manifest.ManifestDigest, PlanDigest: manifest.PlanDigest,
		CompletionMode: manifest.CompletionMode, APIContacted: false, AuthorizationConsumed: false,
		MutationAllowed: false, NextAction: nextAction,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func countClusterCreateFileFlags(arguments []string) int {
	count := 0
	for _, argument := range arguments {
		if argument == "--file" || argument == "-f" || strings.HasPrefix(argument, "--file=") || strings.HasPrefix(argument, "-f=") {
			count++
		}
	}
	return count
}
