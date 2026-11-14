package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	localCAPIStateFormat         = "ok-cli-local-capi/v1"
	localCAPIVersion             = "v1.14.4"
	localCAPIKubernetesVersion   = "v1.35.8"
	localCAPINodeImage           = "kindest/node:v1.35.8"
	localCAPICertManagerVersion  = "v1.21.3"
	localCAPIMinMemoryBytes      = uint64(6 * 1024 * 1024 * 1024)
	localCAPIMinCPUs             = 2
	localCAPIMaxOutput           = 8 << 20
	localCAPIProviderWaitTimeout = 15 * time.Minute
)

var errLocalCAPIInitArgumentsRejected = errors.New("clusterctl rejected init arguments")

var localCAPIProviderVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
var localCAPISHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var localCAPIClusterctlSimpleVersionPattern = regexp.MustCompile(`^clusterctl version: (v[0-9]+\.[0-9]+\.[0-9]+)$`)
var localCAPIClusterctlInfoVersionPattern = regexp.MustCompile(`^clusterctl version: &version\.Info\{Major:"([0-9]+)", Minor:"([0-9]+)", GitVersion:"(v[0-9]+\.[0-9]+\.[0-9]+)", GitCommit:"[^"\\]*", GitTreeState:"[^"\\]*", BuildDate:"[^"\\]*", GoVersion:"[^"\\]*", Compiler:"[^"\\]*", Platform:"[^"\\]*"\}$`)

type localCAPIPhase string

const (
	localCAPIPhaseCreating       localCAPIPhase = "CREATING"
	localCAPIPhaseBootstrapReady localCAPIPhase = "BOOTSTRAP_READY"
	localCAPIPhaseInitializing   localCAPIPhase = "CAPI_INITIALIZING"
	localCAPIPhaseCAPIReady      localCAPIPhase = "CAPI_READY"
	localCAPIPhaseIncomplete     localCAPIPhase = "INCOMPLETE"
)

type localCAPIResourceState string

const (
	localCAPIResourceUnknown           localCAPIResourceState = "UNKNOWN"
	localCAPIResourceAbsent            localCAPIResourceState = "ABSENT"
	localCAPIResourcePresentUnverified localCAPIResourceState = "PRESENT_UNVERIFIED"
	localCAPIResourceVerified          localCAPIResourceState = "VERIFIED"
	localCAPIResourceAmbiguous         localCAPIResourceState = "AMBIGUOUS"
)

type localCAPIContainerEvidence struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Role            string `json:"role"`
	KindClusterName string `json:"kindClusterName"`
}

type localCAPIDeploymentEvidence struct {
	Namespace           string   `json:"namespace"`
	Name                string   `json:"name"`
	UID                 string   `json:"uid"`
	Replicas            int32    `json:"replicas"`
	AvailableReplicas   int32    `json:"availableReplicas"`
	Images              []string `json:"images"`
	ManagerImage        string   `json:"managerImage,omitempty"`
	ClusterTopology     bool     `json:"clusterTopologyEnabled"`
	DockerSocketMounted bool     `json:"dockerSocketMounted"`
}

type localCAPIDeploymentObservation struct {
	Metadata struct {
		Name, Namespace, UID string
		Generation           int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
		Template struct {
			Spec struct {
				Containers []struct {
					Name         string   `json:"name"`
					Image        string   `json:"image"`
					Args         []string `json:"args"`
					VolumeMounts []struct {
						Name      string `json:"name"`
						MountPath string `json:"mountPath"`
					} `json:"volumeMounts"`
				} `json:"containers"`
				Volumes []struct {
					Name     string `json:"name"`
					HostPath *struct {
						Path string `json:"path"`
					} `json:"hostPath"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		AvailableReplicas  int32 `json:"availableReplicas"`
	} `json:"status"`
}

// localCAPIInitEvidence is a bounded, secret-free snapshot of resources that
// clusterctl may have installed before returning an error. The observed flags
// distinguish an empty inventory from a query that could not be trusted.
type localCAPIInitEvidence struct {
	ProvidersObserved   bool                        `json:"providersObserved"`
	Providers           []localCAPIProviderEvidence `json:"providers,omitempty"`
	DeploymentsObserved bool                        `json:"deploymentsObserved"`
	Deployments         []localCAPIWorkloadEvidence `json:"deployments,omitempty"`
	CRDsObserved        bool                        `json:"crdsObserved"`
	CRDs                []string                    `json:"crds,omitempty"`
}

type localCAPIProviderEvidence struct {
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type localCAPIProviderList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		ProviderName string `json:"providerName"`
		Type         string `json:"type"`
		Version      string `json:"version"`
	} `json:"items"`
}

type localCAPIWorkloadEvidence struct {
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	Replicas           int32  `json:"replicas"`
	AvailableReplicas  int32  `json:"availableReplicas"`
}

// localCAPIState is separate from the existing local Kind/Console receipt. It
// describes only the temporary CAPI bootstrap and never claims handover.
type localCAPIState struct {
	Format                        string                        `json:"format"`
	Phase                         localCAPIPhase                `json:"phase"`
	Name                          string                        `json:"name"`
	OwnerID                       string                        `json:"ownerID"`
	ColimaProfile                 string                        `json:"colimaProfile,omitempty"`
	Provider                      localProviderIdentity         `json:"provider"`
	BootstrapKindName             string                        `json:"bootstrapKindName"`
	BootstrapKubeconfig           string                        `json:"bootstrapKubeconfig"`
	KindConfigPath                string                        `json:"kindConfigPath"`
	KindConfigSHA256              string                        `json:"kindConfigSHA256"`
	ClusterctlConfigPath          string                        `json:"clusterctlConfigPath"`
	ClusterctlConfigSHA256        string                        `json:"clusterctlConfigSHA256"`
	KubernetesVersion             string                        `json:"kubernetesVersion"`
	NodeImage                     string                        `json:"nodeImage"`
	ProviderVersions              map[string]string             `json:"providerVersions"`
	Containers                    []localCAPIContainerEvidence  `json:"containers,omitempty"`
	BootstrapResourceState        localCAPIResourceState        `json:"bootstrapResourceState"`
	BootstrapKubeconfigSeen       bool                          `json:"bootstrapKubeconfigSeen"`
	Node                          *localNodeIdentity            `json:"node,omitempty"`
	NodeOwnerID                   string                        `json:"nodeOwnerID,omitempty"`
	KubeSystemUID                 string                        `json:"kubeSystemUID,omitempty"`
	Deployments                   []localCAPIDeploymentEvidence `json:"deployments,omitempty"`
	CRDs                          []string                      `json:"crds,omitempty"`
	InstalledProviderVersions     map[string]string             `json:"installedProviderVersions,omitempty"`
	InitEvidence                  *localCAPIInitEvidence        `json:"initEvidence,omitempty"`
	DevelopmentTemplatesAttempted bool                          `json:"developmentTemplatesAttempted,omitempty"`
	DevelopmentTemplatesSHA256    string                        `json:"developmentTemplatesSHA256,omitempty"`
	DevelopmentTemplatesComplete  bool                          `json:"developmentTemplatesComplete,omitempty"`
	DevelopmentTemplates          []localCAPITemplateEvidence   `json:"developmentTemplates,omitempty"`
	FailureStage                  string                        `json:"failureStage,omitempty"`
	FailureCode                   string                        `json:"failureCode,omitempty"`
}

type localCAPITemplateEvidence struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	Status             string `json:"status"`
	ReasonCode         string `json:"reasonCode,omitempty"`
	ObservedAPIVersion string `json:"observedAPIVersion,omitempty"`
	ObservedKind       string `json:"observedKind,omitempty"`
	ObservedNamespace  string `json:"observedNamespace,omitempty"`
	ObservedName       string `json:"observedName,omitempty"`
	ObservedOwnerID    string `json:"observedOwnerID,omitempty"`
	UID                string `json:"uid,omitempty"`
	SpecSHA256         string `json:"specSHA256,omitempty"`
}

type localCAPIVerificationReport struct {
	Format                   string `json:"format"`
	Result                   string `json:"result"`
	Observation              string `json:"observation"`
	HistoricalLifecyclePhase string `json:"historicalLifecyclePhase,omitempty"`
	ReasonCode               string `json:"reasonCode,omitempty"`
	ObservedAt               string `json:"observedAt"`
}

const localCAPIVerificationFormat = "ok-cli-local-capi-verification/v1"

func runLocalVerify(ctx context.Context, arguments []string, runtime localRuntime, stdout, stderr io.Writer) error {
	if len(arguments) > 0 && isHelpArgument(arguments[0]) {
		writeLocalCommandHelp("verify", stdout)
		return nil
	}
	flags := flag.NewFlagSet("ok local verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "Logical CAPI bootstrap name")
	bootstrap := flags.String("bootstrap", "", "Bootstrap lifecycle to verify (capi)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	bootstrapSet := false
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "bootstrap" {
			bootstrapSet = true
		}
	})
	if flags.NArg() != 0 || !localClusterNamePattern.MatchString(*name) || !bootstrapSet || *bootstrap != "capi" {
		return errors.New("usage: ok local verify --name <name> --bootstrap capi")
	}
	report := verifyLocalCAPIBootstrap(ctx, runtime, *name)
	raw, err := json.Marshal(report)
	if err != nil {
		return errors.New("could not encode CAPI verification result")
	}
	_, err = fmt.Fprintln(stdout, string(raw))
	return err
}

func verifyLocalCAPIBootstrap(ctx context.Context, runtime localRuntime, name string) localCAPIVerificationReport {
	report := localCAPIVerificationReport{
		Format: localCAPIVerificationFormat, Result: "UNVERIFIABLE", Observation: "CURRENT_READ_ONLY",
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
	}
	finish := func(result, reason string) localCAPIVerificationReport {
		report.Result, report.ReasonCode = result, reason
		return report
	}
	state, err := readLocalCAPIState(runtime.stateRoot, name)
	if err != nil {
		return finish("UNVERIFIABLE", "STATE_UNREADABLE")
	}
	report.HistoricalLifecyclePhase = string(state.Phase)
	if state.Phase != localCAPIPhaseIncomplete && state.Phase != localCAPIPhaseCAPIReady {
		return finish("UNVERIFIABLE", "STATE_PHASE_UNSUPPORTED")
	}
	for _, conflictPath := range []string{localStateFilePath(runtime.stateRoot, name), localBootstrapDiagnosticPath(runtime.stateRoot, name)} {
		if _, err := os.Lstat(conflictPath); err == nil {
			return finish("IDENTITY_MISMATCH", "OWNERSHIP_CONFLICT")
		} else if !errors.Is(err, os.ErrNotExist) {
			return finish("UNVERIFIABLE", "OWNERSHIP_CONFLICT_UNVERIFIABLE")
		}
	}
	// Keep the exact receipt bytes as the observation baseline. Verification
	// operates on copies and refuses to report a result if another actor changes
	// the receipt while the live checks are running.
	statePath := localCAPIStateFilePath(runtime.stateRoot, name)
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		return finish("UNVERIFIABLE", "STATE_UNREADABLE")
	}
	if err := verifyLocalCAPIPreflightProfile(ctx, runtime, localCAPIStateProfile(state), state.Provider); err != nil {
		if strings.Contains(err.Error(), "changed") || strings.Contains(err.Error(), "does not match") {
			return finish("IDENTITY_MISMATCH", "PROVIDER_IDENTITY_MISMATCH")
		}
		return finish("UNVERIFIABLE", "PROVIDER_UNVERIFIABLE")
	}
	if err := verifyLocalCAPIRecordedIdentity(ctx, runtime, state); err != nil {
		result, reason := classifyLocalCAPIIdentityFailure(err)
		return finish(result, reason)
	}
	observed := state
	if err := verifyLocalCAPIReady(ctx, runtime, state.Provider, &observed); err != nil {
		result, reason := classifyLocalCAPIReadinessFailure(err)
		return finish(result, reason)
	}
	if state.DevelopmentTemplatesAttempted {
		if err := verifyLocalCAPITemplateReceipt(ctx, runtime, state); err != nil {
			return finish("IDENTITY_MISMATCH", "DEVELOPMENT_TEMPLATE_OWNERSHIP_MISMATCH")
		}
	}
	if _, err := readLocalCAPIState(runtime.stateRoot, name); err != nil {
		return finish("UNVERIFIABLE", "STATE_CHANGED_DURING_OBSERVATION")
	}
	stateBytesAfter, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(stateBytes, stateBytesAfter) {
		return finish("UNVERIFIABLE", "STATE_CHANGED_DURING_OBSERVATION")
	}
	return finish("VERIFIED", "")
}

// verifyLocalCAPIRecordedIdentity checks the live bootstrap against the
// identities already recorded in the receipt. captureLocalCAPIIdentity alone
// observes and replaces those fields on its argument, so it is performed only
// on a copy and compared before any readiness result can be reported.
func verifyLocalCAPIRecordedIdentity(ctx context.Context, runtime localRuntime, state localCAPIState) error {
	clustersRaw, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "clusters")
	if err != nil {
		return errors.New("cannot enumerate bootstrap Kind clusters")
	}
	clusters, err := parseLocalKindClusterNames(clustersRaw)
	if err != nil {
		return errors.New("bootstrap Kind cluster inventory is ambiguous")
	}
	found := false
	for _, name := range clusters {
		if name == state.BootstrapKindName {
			found = true
			break
		}
	}
	if !found {
		return errors.New("owner-bound Kind cluster is absent")
	}
	info, err := os.Lstat(state.BootstrapKubeconfig)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("private bootstrap kubeconfig is unavailable or unsafe")
	}
	if !localCAPIConfigMatches(state.KindConfigPath, state.KindConfigSHA256) || !localCAPIConfigMatches(state.ClusterctlConfigPath, state.ClusterctlConfigSHA256) {
		return errors.New("owner-bound bootstrap configuration differs from the receipt")
	}
	observed := state
	if err := captureLocalCAPIIdentity(ctx, runtime, &observed); err != nil {
		return err
	}
	if len(observed.Containers) != 1 || (len(state.Containers) > 0 && (len(state.Containers) != 1 || state.Containers[0] != observed.Containers[0])) {
		return errors.New("bootstrap container identity differs from the receipt")
	}
	if observed.Node == nil || (state.Node != nil && *state.Node != *observed.Node) || (state.NodeOwnerID != "" && state.NodeOwnerID != observed.NodeOwnerID) || (state.KubeSystemUID != "" && state.KubeSystemUID != observed.KubeSystemUID) {
		return errors.New("bootstrap Kubernetes identity differs from the receipt")
	}
	return nil
}

func classifyLocalCAPIIdentityFailure(err error) (string, string) {
	message := err.Error()
	switch {
	case strings.Contains(message, "differs from the receipt"), strings.Contains(message, "does not match the owner-bound bootstrap cluster"), strings.Contains(message, "is absent"), strings.Contains(message, "identity changed"), strings.Contains(message, "not unique and owner-bound"), strings.Contains(message, "owner identity does not match"):
		return "IDENTITY_MISMATCH", "BOOTSTRAP_IDENTITY_MISMATCH"
	case strings.Contains(message, "is not Ready"):
		return "NOT_READY", "BOOTSTRAP_NODE_NOT_READY"
	default:
		return "UNVERIFIABLE", "BOOTSTRAP_IDENTITY_UNVERIFIABLE"
	}
}

func classifyLocalCAPIReadinessFailure(err error) (string, string) {
	message := err.Error()
	switch {
	case strings.Contains(message, "Docker provider identity changed"), strings.Contains(message, "identity changed during"):
		return "IDENTITY_MISMATCH", "PROVIDER_IDENTITY_MISMATCH"
	case strings.Contains(message, "not fully Available"):
		return "NOT_READY", "CONTROLLER_NOT_READY"
	case strings.Contains(message, "feature gate"), strings.Contains(message, "image version"), strings.Contains(message, "image or ClusterTopology"), strings.Contains(message, "does not mount"), strings.Contains(message, "provider inventory does not exactly"), strings.Contains(message, "CRD is missing"):
		return "NOT_READY", "CAPI_COMPONENT_MISMATCH"
	case strings.Contains(message, "bootstrap node is not Ready"):
		return "NOT_READY", "BOOTSTRAP_NODE_NOT_READY"
	default:
		return "UNVERIFIABLE", "CAPI_OBSERVATION_UNAVAILABLE"
	}
}

type localCAPICommandRunner func(context.Context, localProviderIdentity, string, map[string]string, string, ...string) ([]byte, error)

func localCAPIStateDirectory(root, name string) string {
	return filepath.Join(root, "capi", "clusters", name)
}
func localCAPIStateFilePath(root, name string) string {
	return filepath.Join(localCAPIStateDirectory(root, name), "state.json")
}

func validateLocalCAPIState(root string, state localCAPIState) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("CAPI state root must be an absolute clean path")
	}
	if state.Format != localCAPIStateFormat || !localClusterNamePattern.MatchString(state.Name) || !localOwnerIDPattern.MatchString(state.OwnerID) {
		return errors.New("invalid CAPI lifecycle format, cluster name, or owner identifier")
	}
	switch state.Phase {
	case localCAPIPhaseCreating, localCAPIPhaseBootstrapReady, localCAPIPhaseInitializing, localCAPIPhaseCAPIReady, localCAPIPhaseIncomplete:
	default:
		return errors.New("unsupported CAPI lifecycle phase")
	}
	profile := localCAPIStateProfile(state)
	if !validLocalColimaProfileSyntax(profile) || state.Provider.Kind != "docker" || !validLocalDockerContextName(state.Provider.Context) ||
		(profile == "default" && state.Provider.Context != "colima") || !localCAPIColimaEndpoint(state.Provider.Endpoint, profile) || len(state.Provider.DaemonID) < 3 || len(state.Provider.DaemonID) > 128 ||
		!regexp.MustCompile(`^[A-Za-z0-9._:-]+$`).MatchString(state.Provider.DaemonID) {
		return errors.New("CAPI lifecycle requires a complete pinned Colima Docker identity")
	}
	if state.BootstrapKindName != localKindClusterName(state.Name, state.OwnerID) || !validLocalKindClusterName(state.BootstrapKindName) {
		return errors.New("CAPI bootstrap cluster name is not bound to the logical name and owner")
	}
	switch state.BootstrapResourceState {
	case localCAPIResourceUnknown, localCAPIResourceAbsent, localCAPIResourcePresentUnverified, localCAPIResourceVerified, localCAPIResourceAmbiguous:
	default:
		return errors.New("unsupported CAPI bootstrap resource classification")
	}
	dir := localCAPIStateDirectory(root, state.Name)
	if state.BootstrapKubeconfig != filepath.Join(dir, "bootstrap.kubeconfig") ||
		state.KindConfigPath != filepath.Join(dir, "kind.yaml") || state.ClusterctlConfigPath != filepath.Join(dir, "clusterctl.yaml") {
		return errors.New("CAPI private paths must remain in the isolated lifecycle directory")
	}
	if !localCAPISHA256Pattern.MatchString(state.KindConfigSHA256) || !localCAPISHA256Pattern.MatchString(state.ClusterctlConfigSHA256) ||
		state.KubernetesVersion != localCAPIKubernetesVersion || state.NodeImage != localCAPINodeImage {
		return errors.New("CAPI configuration evidence is incomplete or unsupported")
	}
	wantVersions := map[string]string{"cluster-api": localCAPIVersion, "kubeadm-bootstrap": localCAPIVersion,
		"kubeadm-control-plane": localCAPIVersion, "docker-infrastructure": localCAPIVersion,
		"cert-manager": localCAPICertManagerVersion}
	if len(state.ProviderVersions) != len(wantVersions) {
		return errors.New("CAPI provider version inventory is incomplete")
	}
	for key, version := range wantVersions {
		if state.ProviderVersions[key] != version || !localCAPIProviderVersionPattern.MatchString(version) {
			return errors.New("CAPI provider version inventory is invalid")
		}
	}
	if !state.DevelopmentTemplatesAttempted && (state.DevelopmentTemplatesSHA256 != "" || state.DevelopmentTemplatesComplete || len(state.DevelopmentTemplates) != 0) {
		return errors.New("CAPI template evidence exists without a durable installation intent")
	}
	if state.DevelopmentTemplatesAttempted && !localCAPISHA256Pattern.MatchString(state.DevelopmentTemplatesSHA256) {
		return errors.New("CAPI template installation intent lacks a manifest digest")
	}
	if len(state.DevelopmentTemplates) > len(localCAPIWorkloadExpectedManifestObjects(""))-1 {
		return errors.New("CAPI template ownership inventory exceeds its bounded limit")
	}
	templateEvidenceSeen := map[string]bool{}
	for _, evidence := range state.DevelopmentTemplates {
		key := evidence.APIVersion + "/" + evidence.Kind + "/" + evidence.Name
		if evidence.Namespace != localCAPIWorkloadNamespace || !localCAPITemplateIdentityExpected(key) || templateEvidenceSeen[key] || !validLocalCAPITemplateEvidence(evidence) {
			return errors.New("CAPI template ownership inventory is invalid")
		}
		if evidence.Status == localCAPITemplateVerified && evidence.ObservedOwnerID != state.OwnerID {
			return errors.New("verified CAPI template owner differs from the management receipt")
		}
		templateEvidenceSeen[key] = true
	}
	if state.DevelopmentTemplatesComplete && !localCAPITemplateInventoryComplete(state.DevelopmentTemplates) {
		return errors.New("completed CAPI template inventory is not fully verified")
	}
	if state.Phase == localCAPIPhaseCAPIReady && state.DevelopmentTemplatesAttempted && !state.DevelopmentTemplatesComplete {
		return errors.New("CAPI_READY receipt lacks complete management-owned development templates")
	}
	if state.Phase == localCAPIPhaseCAPIReady && (state.BootstrapResourceState != localCAPIResourceVerified || !state.BootstrapKubeconfigSeen || state.Node == nil || state.Node.UID == "" || state.NodeOwnerID != state.OwnerID || state.KubeSystemUID == "" || len(state.Containers) != 1 || state.Containers[0].KindClusterName != state.BootstrapKindName || len(state.Deployments) != 7 || len(state.CRDs) < 4 || len(state.InstalledProviderVersions) != 5 || state.FailureCode != "") {
		return errors.New("CAPI_READY receipt lacks independent readiness evidence")
	}
	if (state.Phase == localCAPIPhaseBootstrapReady || state.Phase == localCAPIPhaseInitializing) && (state.BootstrapResourceState != localCAPIResourceVerified || !state.BootstrapKubeconfigSeen || state.Node == nil || state.Node.UID == "" || state.NodeOwnerID != state.OwnerID || state.KubeSystemUID == "" || len(state.Containers) != 1) {
		return errors.New("bootstrap lifecycle receipt lacks independent bootstrap identity evidence")
	}
	if state.Phase == localCAPIPhaseCAPIReady {
		container := state.Containers[0]
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(container.ID) || container.Name != state.BootstrapKindName+"-control-plane" || container.Role != "control-plane" || state.Node.Name != container.Name || strings.ContainsAny(state.Node.UID+state.KubeSystemUID, "\r\n\x00") {
			return errors.New("CAPI_READY receipt has inconsistent bootstrap container or Kubernetes identities")
		}
		wantDeployments := map[string]bool{
			"capi-system/capi-controller-manager":                                             true,
			"capi-kubeadm-bootstrap-system/capi-kubeadm-bootstrap-controller-manager":         true,
			"capi-kubeadm-control-plane-system/capi-kubeadm-control-plane-controller-manager": true,
			"capd-system/capd-controller-manager":                                             true,
			"cert-manager/cert-manager":                                                       true,
			"cert-manager/cert-manager-cainjector":                                            true,
			"cert-manager/cert-manager-webhook":                                               true,
		}
		for _, deployment := range state.Deployments {
			key := deployment.Namespace + "/" + deployment.Name
			if !wantDeployments[key] || deployment.UID == "" || deployment.Replicas < 1 || deployment.AvailableReplicas != deployment.Replicas || len(deployment.Images) == 0 {
				return errors.New("CAPI_READY receipt has incomplete controller evidence")
			}
			if localCAPIDeploymentIsCAPIController(deployment.Namespace) {
				if !strings.HasSuffix(deployment.ManagerImage, ":"+localCAPIVersion) ||
					(localCAPIControllerRequiresClusterTopology(deployment.Namespace, deployment.Name) && !deployment.ClusterTopology) {
					return errors.New("CAPI_READY receipt lacks pinned controller image or required ClusterTopology evidence")
				}
			}
			if deployment.Namespace == "capd-system" && !deployment.DockerSocketMounted {
				return errors.New("CAPI_READY receipt lacks CAPD Docker socket mount evidence")
			}
			delete(wantDeployments, key)
		}
		if len(wantDeployments) != 0 {
			return errors.New("CAPI_READY receipt is missing required deployment evidence")
		}
		for key, version := range localCAPIVersions() {
			if state.InstalledProviderVersions[key] != version {
				return errors.New("CAPI_READY receipt has incomplete installed provider version evidence")
			}
		}
	}
	if state.FailureCode != "" && !localCAPIFailureCodes[state.FailureCode] {
		return errors.New("CAPI receipt has an unapproved diagnostic code")
	}
	if state.FailureStage != "" && !localCAPIFailureStages[state.FailureStage] {
		return errors.New("CAPI receipt has an unapproved diagnostic stage")
	}
	if state.Phase == localCAPIPhaseIncomplete && (state.FailureCode == "" || state.FailureStage == "") {
		return errors.New("INCOMPLETE CAPI receipt requires a bounded failure classification")
	}
	if state.InitEvidence != nil {
		if state.Phase != localCAPIPhaseIncomplete || state.FailureStage != "capi-init" ||
			len(state.InitEvidence.Providers) > 8 || len(state.InitEvidence.Deployments) > 16 || len(state.InitEvidence.CRDs) > 128 ||
			(!state.InitEvidence.ProvidersObserved && len(state.InitEvidence.Providers) != 0) ||
			(!state.InitEvidence.DeploymentsObserved && len(state.InitEvidence.Deployments) != 0) ||
			(!state.InitEvidence.CRDsObserved && len(state.InitEvidence.CRDs) != 0) {
			return errors.New("CAPI partial inventory exceeds its bounded limits")
		}
		providerSeen := map[string]bool{}
		for _, provider := range state.InitEvidence.Providers {
			key := provider.Type + "/" + provider.Name
			want, ok := expectedLocalCAPIProviders()[key]
			if !ok || provider.Namespace != want.Namespace || provider.Version != want.Version || providerSeen[key] {
				return errors.New("CAPI partial provider inventory contains invalid metadata")
			}
			providerSeen[key] = true
		}
		deploymentSeen := map[string]bool{}
		for _, deployment := range state.InitEvidence.Deployments {
			key := deployment.Namespace + "/" + deployment.Name
			if !expectedLocalCAPIDeployment(deployment.Namespace, deployment.Name) || deploymentSeen[key] || deployment.UID == "" ||
				strings.ContainsAny(deployment.UID, "\r\n\x00") || deployment.Generation < 0 || deployment.ObservedGeneration < 0 ||
				deployment.Replicas < 0 || deployment.AvailableReplicas < 0 || deployment.AvailableReplicas > deployment.Replicas {
				return errors.New("CAPI partial deployment inventory contains invalid metadata")
			}
			deploymentSeen[key] = true
		}
		crdSeen := map[string]bool{}
		for _, crd := range state.InitEvidence.CRDs {
			if !regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`).MatchString(crd) || crdSeen[crd] {
				return errors.New("CAPI partial CRD inventory contains invalid metadata")
			}
			crdSeen[crd] = true
		}
	}
	if state.Phase != localCAPIPhaseIncomplete && (state.FailureCode != "" || state.FailureStage != "") {
		return errors.New("non-INCOMPLETE CAPI receipt cannot contain failure classification")
	}
	wantFailureStage := map[string]string{"PREFLIGHT_FAILED": "preflight", "KIND_CREATE_FAILED": "kind-create", "BOOTSTRAP_VERIFY_FAILED": "bootstrap-verify", "CAPI_INIT_FAILED": "capi-init", "CAPI_INIT_ARGUMENTS_REJECTED": "capi-init", "CAPI_VERIFY_FAILED": "capi-verify", "CAPI_TEMPLATES_INSTALL_FAILED": "template-install", "STATE_PERSIST_FAILED": "state"}
	if state.FailureCode != "" && wantFailureStage[state.FailureCode] != state.FailureStage {
		return errors.New("CAPI failure code and stage do not match")
	}
	return nil
}

var localCAPIFailureCodes = map[string]bool{
	"PREFLIGHT_FAILED": true, "KIND_CREATE_FAILED": true, "BOOTSTRAP_VERIFY_FAILED": true,
	"CAPI_INIT_FAILED": true, "CAPI_INIT_ARGUMENTS_REJECTED": true, "CAPI_VERIFY_FAILED": true, "CAPI_TEMPLATES_INSTALL_FAILED": true, "STATE_PERSIST_FAILED": true,
}
var localCAPIFailureStages = map[string]bool{"preflight": true, "kind-create": true, "bootstrap-verify": true, "capi-init": true, "capi-verify": true, "template-install": true, "state": true}

type localCAPIDockerInfo struct {
	CPUs   int    `json:"cpus"`
	Memory uint64 `json:"memory"`
	Root   string `json:"root"`
}
type localCAPIKubectlVersion struct {
	ClientVersion struct {
		GitVersion string `json:"gitVersion"`
	} `json:"clientVersion"`
}

// runLocalCAPIUp is an isolated lifecycle. It never invokes the normal Console
// verifier and never deletes/retries resources after intent is persisted.
func runLocalCAPIUp(name, profile string, runtime localRuntime) error {
	return runLocalCAPIUpContext(context.Background(), name, profile, runtime)
}

func runLocalCAPIUpContext(ctx context.Context, name, profile string, runtime localRuntime) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if !localClusterNamePattern.MatchString(name) {
		return errors.New("CAPI bootstrap requires a valid logical cluster name")
	}
	if !validLocalColimaProfileName(profile) {
		return errors.New("CAPI bootstrap requires an explicit valid Colima profile")
	}
	if runtime.stateRoot == "" || !filepath.IsAbs(runtime.stateRoot) || filepath.Clean(runtime.stateRoot) != runtime.stateRoot {
		return errors.New("cannot safely inspect the private local CAPI state root")
	}
	// Check both lifecycle namespaces before any provider query or local write.
	for _, path := range []string{filepath.Join(runtime.stateRoot, "clusters", name), localCAPIStateDirectory(runtime.stateRoot, name), localCAPIWorkloadDirectory(runtime.stateRoot, name)} {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("existing local ownership material; CAPI mode will not overwrite, adopt, or retry it")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot safely inspect existing local ownership material")
		}
	}
	if runtime.run == nil {
		return errors.New("CAPI bootstrap command runner is unavailable")
	}
	if runtime.runPinned == nil || runtime.runKindCreate == nil || runtime.runCAPI == nil {
		return errors.New("CAPI bootstrap requires pinned Docker/Kind and isolated command runners")
	}
	lookPath := runtime.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	for _, executable := range []string{"docker", "kind", "kubectl", "clusterctl", "colima"} {
		if _, err := lookPath(executable); err != nil {
			return fmt.Errorf("required executable %s is unavailable; no state or infrastructure was changed", executable)
		}
	}
	kindVersion, err := runtime.run(ctx, "kind", "version")
	if err != nil || !localKindVersionSupported(string(kindVersion), localKindMinimumVersion) {
		return fmt.Errorf("Kind %s or newer is required; no state or infrastructure was changed", localKindMinimumVersion)
	}
	clusterctlVersion, err := runtime.run(ctx, "clusterctl", "version")
	if err != nil || !validateLocalCAPIClusterctlVersion(clusterctlVersion) {
		return fmt.Errorf("clusterctl %s is required; no state or infrastructure was changed", localCAPIVersion)
	}
	kubectlVersion, err := runtime.run(ctx, "kubectl", "version", "--client", "-o", "json", "--kubeconfig", os.DevNull)
	if err != nil || validateLocalCAPIKubectlVersion(kubectlVersion) != nil {
		return errors.New("kubectl client compatible with Kubernetes 1.35 is required; no state or infrastructure was changed")
	}
	if err := rejectUnexpectedLocalDockerEnvironment(runtime); err != nil {
		return fmt.Errorf("CAPI provider preflight rejected the environment: %s; no state or infrastructure was changed", err)
	}
	provider, err := observeLocalColimaDockerProvider(ctx, runtime, profile)
	if err != nil {
		return fmt.Errorf("CAPI provider discovery failed: %s; no state or infrastructure was changed", err)
	}
	if err := verifyLocalCAPIPrequisites(ctx, runtime, profile, provider); err != nil {
		return fmt.Errorf("CAPI preflight failed: %s; no state or infrastructure was changed", err.Error())
	}
	if err := verifyLocalCAPIDedicatedDaemon(ctx, runtime, provider); err != nil {
		return fmt.Errorf("selected Colima daemon is not empty and dedicated: %s; no state or infrastructure was changed", err)
	}
	newOwner := runtime.newOwnerID
	if newOwner == nil {
		newOwner = newLocalOwnerID
	}
	ownerID, err := newOwner()
	if err != nil {
		return errors.New("could not generate a fresh CAPI owner identifier")
	}
	kindName := localKindClusterName(name, ownerID)
	if !validLocalKindClusterName(kindName) {
		return errors.New("generated CAPI Kind name violates the hostname length contract")
	}
	clusters, err := runLocalPinned(ctx, runtime, provider, "kind", "get", "clusters")
	if err != nil {
		return errors.New("could not safely list Kind clusters; no state or infrastructure was changed")
	}
	clusterNames, err := parseLocalKindClusterNames(clusters)
	if err != nil {
		return errors.New("could not safely parse Kind cluster inventory; no state or infrastructure was changed")
	}
	for _, existing := range clusterNames {
		if existing == kindName {
			return errors.New("generated CAPI Kind name already exists; no state or infrastructure was changed")
		}
	}
	ownerContainers, err := runLocalPinned(ctx, runtime, provider, "docker", "ps", "-a", "--no-trunc", "--filter", "label="+localOwnerLabel+"="+ownerID, "--format", "{{.ID}}")
	if err != nil || len(strings.Fields(string(ownerContainers))) != 0 {
		return errors.New("generated CAPI owner identifier is already attached to Docker resources; no state or infrastructure was changed")
	}
	containers, err := observeLocalKindContainers(ctx, runtime, provider, kindName)
	if err != nil || len(containers) != 0 {
		return errors.New("generated CAPI Kind identity is occupied or could not be verified; no state or infrastructure was changed")
	}
	if err := verifyLocalCAPIStateRoot(runtime.stateRoot); err != nil {
		return fmt.Errorf("private CAPI state directory is unavailable: %w", err)
	}
	releaseOperation, err := acquireLocalLifecycleOperationLock(runtime.stateRoot, name)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseOperation(); err != nil {
			result = errors.Join(result, errors.New("local lifecycle lock could not be safely released; inspect it before another up"))
		}
	}() // A stale lock is fail-closed; it is never silently adopted.
	for _, path := range []string{filepath.Join(runtime.stateRoot, "clusters", name), localCAPIStateDirectory(runtime.stateRoot, name), localCAPIWorkloadDirectory(runtime.stateRoot, name)} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("existing local ownership material; CAPI mode will not overwrite, adopt, or retry it")
		}
	}

	dir := localCAPIStateDirectory(runtime.stateRoot, name)
	if err := createLocalCAPILifecycleDirectory(runtime.stateRoot, name); err != nil {
		return errors.New("cannot create a fresh private CAPI lifecycle directory; no infrastructure was changed")
	}
	kindConfig, err := renderLocalCAPIKindConfig(name, ownerID)
	if err != nil {
		return err
	}
	clusterctlConfig := []byte("cert-manager:\n  version: " + localCAPICertManagerVersion + "\n  timeout: 15m\n")
	kindPath := filepath.Join(dir, "kind.yaml")
	clusterctlPath := filepath.Join(dir, "clusterctl.yaml")
	kubeconfigPath := filepath.Join(dir, "bootstrap.kubeconfig")
	if err := writePrivateNewFile(kindPath, kindConfig); err != nil {
		return errors.New("could not write private CAPI Kind configuration")
	}
	if err := writePrivateNewFile(clusterctlPath, clusterctlConfig); err != nil {
		return errors.New("could not write private clusterctl configuration")
	}
	kindHash, clusterctlHash := sha256.Sum256(kindConfig), sha256.Sum256(clusterctlConfig)
	state := localCAPIState{
		Format: localCAPIStateFormat, Phase: localCAPIPhaseCreating, Name: name, OwnerID: ownerID, ColimaProfile: profile, Provider: provider,
		BootstrapKindName: kindName, BootstrapKubeconfig: kubeconfigPath, KindConfigPath: kindPath,
		KindConfigSHA256: hex.EncodeToString(kindHash[:]), ClusterctlConfigPath: clusterctlPath,
		ClusterctlConfigSHA256: hex.EncodeToString(clusterctlHash[:]), KubernetesVersion: localCAPIKubernetesVersion,
		NodeImage: localCAPINodeImage, ProviderVersions: localCAPIVersions(), BootstrapResourceState: localCAPIResourceUnknown,
	}
	if err := writeLocalCAPIState(runtime.stateRoot, state, false); err != nil {
		return errors.New("could not persist CREATING intent; no infrastructure mutation was attempted")
	}
	fail := func(stage, code string) error {
		state.Phase, state.FailureStage, state.FailureCode = localCAPIPhaseIncomplete, stage, code
		if err := writeLocalCAPIState(runtime.stateRoot, state, true); err != nil {
			return fmt.Errorf("CAPI bootstrap stopped at %s; durable INCOMPLETE update failed and original intent remains", stage)
		}
		return fmt.Errorf("CAPI bootstrap stopped at %s [%s]; INCOMPLETE state retained, resources preserved, no retry performed", stage, code)
	}
	// Rebind the just-persisted intent to the same provider and empty Kind name
	// immediately before the first infrastructure mutation.
	providerBeforeCreate, providerErr := observeLocalColimaDockerProvider(ctx, runtime, profile)
	if providerErr != nil || providerBeforeCreate != state.Provider {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if envErr := rejectUnexpectedLocalDockerEnvironment(runtime); envErr != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if err := verifyLocalCAPIPreflightProfile(ctx, runtime, profile, state.Provider); err != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if err := verifyLocalCAPIDedicatedDaemon(ctx, runtime, provider); err != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	clustersBeforeCreate, listErr := runLocalPinned(ctx, runtime, provider, "kind", "get", "clusters")
	if listErr != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	clusterNamesBeforeCreate, parseErr := parseLocalKindClusterNames(clustersBeforeCreate)
	if parseErr != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	for _, existing := range clusterNamesBeforeCreate {
		if existing == kindName {
			return fail("preflight", "PREFLIGHT_FAILED")
		}
	}
	ownerContainersBeforeCreate, ownerErr := runLocalPinned(ctx, runtime, provider, "docker", "ps", "-a", "--no-trunc", "--filter", "label="+localOwnerLabel+"="+ownerID, "--format", "{{.ID}}")
	if ownerErr != nil || len(strings.Fields(string(ownerContainersBeforeCreate))) != 0 {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if _, err := os.Lstat(kubeconfigPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if !localCAPIConfigMatches(kindPath, state.KindConfigSHA256) || !localCAPIConfigMatches(clusterctlPath, state.ClusterctlConfigSHA256) {
		return fail("preflight", "PREFLIGHT_FAILED")
	}
	if err := verifyLocalCAPIProviderStillPinned(ctx, runtime, state); err != nil {
		return fail("preflight", "PREFLIGHT_FAILED")
	}

	createArgs := []string{"create", "cluster", "--name", kindName, "--config", kindPath, "--kubeconfig", kubeconfigPath, "--image", localCAPINodeImage, "--wait", "180s"}
	if runtime.runKindCreate != nil {
		_, _, err = runtime.runKindCreate(ctx, provider, kubeconfigPath, createArgs...)
	} else {
		_, err = runLocalCAPIRaw(ctx, runtime, provider, kubeconfigPath, nil, "kind", createArgs...)
	}
	if err != nil {
		inspectLocalCAPIResidual(ctx, runtime, &state)
		return fail("kind-create", "KIND_CREATE_FAILED")
	}
	kubeconfigInfo, err := os.Lstat(kubeconfigPath)
	if err != nil || !kubeconfigInfo.Mode().IsRegular() || kubeconfigInfo.Mode()&os.ModeSymlink != 0 {
		inspectLocalCAPIResidual(ctx, runtime, &state)
		return fail("bootstrap-verify", "BOOTSTRAP_VERIFY_FAILED")
	}
	if err := os.Chmod(kubeconfigPath, 0o600); err != nil {
		inspectLocalCAPIResidual(ctx, runtime, &state)
		return fail("bootstrap-verify", "BOOTSTRAP_VERIFY_FAILED")
	}
	if err := verifyLocalCAPIProviderStillPinned(ctx, runtime, state); err != nil {
		inspectLocalCAPIResidual(ctx, runtime, &state)
		return fail("bootstrap-verify", "BOOTSTRAP_VERIFY_FAILED")
	}
	if err := captureLocalCAPIIdentity(ctx, runtime, &state); err != nil {
		inspectLocalCAPIResidual(ctx, runtime, &state)
		return fail("bootstrap-verify", "BOOTSTRAP_VERIFY_FAILED")
	}
	state.Phase = localCAPIPhaseBootstrapReady
	if err := writeLocalCAPIState(runtime.stateRoot, state, true); err != nil {
		return fail("state", "STATE_PERSIST_FAILED")
	}

	initArgs, err := buildLocalCAPIInitArgs(kindName, kubeconfigPath, clusterctlPath, localCAPIProviderWaitTimeout)
	if err != nil {
		return fail("capi-init", "CAPI_INIT_FAILED")
	}
	if !localCAPIConfigMatches(kindPath, state.KindConfigSHA256) || !localCAPIConfigMatches(clusterctlPath, state.ClusterctlConfigSHA256) {
		return fail("capi-init", "CAPI_INIT_FAILED")
	}
	state.Phase = localCAPIPhaseInitializing
	if err := writeLocalCAPIState(runtime.stateRoot, state, true); err != nil {
		return fail("state", "STATE_PERSIST_FAILED")
	}
	if err := verifyLocalCAPIProviderStillPinned(ctx, runtime, state); err != nil {
		return fail("capi-init", "PREFLIGHT_FAILED")
	}
	if _, err := runLocalCAPIRaw(ctx, runtime, provider, kubeconfigPath, map[string]string{"CLUSTER_TOPOLOGY": "true"}, "clusterctl", initArgs...); err != nil {
		state.InitEvidence = captureLocalCAPIInitEvidence(runtime, provider, state)
		failureCode := "CAPI_INIT_FAILED"
		if errors.Is(err, errLocalCAPIInitArgumentsRejected) {
			failureCode = "CAPI_INIT_ARGUMENTS_REJECTED"
		}
		return fail("capi-init", failureCode)
	}
	if err := waitLocalCAPIReadiness(ctx, runtime, provider, state); err != nil {
		return fail("capi-verify", "CAPI_VERIFY_FAILED")
	}
	if err := verifyLocalCAPIReady(ctx, runtime, provider, &state); err != nil {
		return fail("capi-verify", "CAPI_VERIFY_FAILED")
	}
	if err := installLocalCAPIDevelopmentTemplates(ctx, runtime, &state); err != nil {
		return fail("template-install", "CAPI_TEMPLATES_INSTALL_FAILED")
	}
	state.Phase, state.FailureStage, state.FailureCode = localCAPIPhaseCAPIReady, "", ""
	if err := writeLocalCAPIState(runtime.stateRoot, state, true); err != nil {
		return fail("state", "STATE_PERSIST_FAILED")
	}
	return nil
}

func validateLocalCAPIClusterctlVersion(raw []byte) bool {
	output := strings.TrimSpace(string(raw))
	if matches := localCAPIClusterctlSimpleVersionPattern.FindStringSubmatch(output); len(matches) == 2 {
		return matches[1] == localCAPIVersion
	}
	matches := localCAPIClusterctlInfoVersionPattern.FindStringSubmatch(output)
	if len(matches) != 4 || matches[3] != localCAPIVersion {
		return false
	}
	versionParts := strings.Split(strings.TrimPrefix(matches[3], "v"), ".")
	return len(versionParts) == 3 && matches[1] == versionParts[0] && matches[2] == versionParts[1]
}

// acquireLocalLifecycleOperationLock serializes the normal Console and
// experimental CAPI up paths by logical name. The directory is an atomic
// reservation; a process crash leaves it behind and requires explicit review.
func acquireLocalLifecycleOperationLock(root, name string) (func() error, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !localClusterNamePattern.MatchString(name) {
		return nil, errors.New("invalid local lifecycle operation lock path")
	}
	if err := ensureLocalCAPISafeParent(filepath.Dir(root)); err != nil {
		return nil, errors.New("local lifecycle state parent is unavailable or unsafe")
	}
	if err := ensureLocalCAPIDirectory(root, false); err != nil {
		return nil, errors.New("local lifecycle state root is unavailable or unsafe")
	}
	operations := filepath.Join(root, "operations")
	if err := ensureLocalCAPIDirectory(operations, false); err != nil {
		return nil, errors.New("local lifecycle operation directory is unavailable or unsafe")
	}
	lock := filepath.Join(operations, name)
	if err := os.Mkdir(lock, 0o700); err != nil {
		return nil, errors.New("another local lifecycle operation or an unreconciled operation lock exists for this name")
	}
	if err := syncLocalCAPIDirectory(operations); err != nil {
		_ = os.Remove(lock)
		_ = syncLocalCAPIDirectory(operations)
		return nil, errors.New("could not durably reserve the local lifecycle name")
	}
	return func() error {
		info, err := os.Lstat(lock)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("local lifecycle operation lock identity changed")
		}
		if err := os.Remove(lock); err != nil {
			return err
		}
		return syncLocalCAPIDirectory(operations)
	}, nil
}

func localCAPIVersions() map[string]string {
	return map[string]string{"cluster-api": localCAPIVersion, "kubeadm-bootstrap": localCAPIVersion,
		"kubeadm-control-plane": localCAPIVersion, "docker-infrastructure": localCAPIVersion,
		"cert-manager": localCAPICertManagerVersion}
}

func localCAPIHasDiskHeadroom(raw []byte, minimumKiB int64) bool {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		return false
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return false
	}
	available, err := strconv.ParseInt(fields[3], 10, 64)
	return err == nil && available >= minimumKiB
}

func localCAPIConfigMatches(path, expectedSHA256 string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == expectedSHA256
}

func waitLocalCAPIReadiness(ctx context.Context, runtime localRuntime, provider localProviderIdentity, state localCAPIState) error {
	contextName := "kind-" + state.BootstrapKindName
	if _, err := runLocalCAPIRaw(ctx, runtime, provider, state.BootstrapKubeconfig, nil, "kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", contextName, "wait", "--for=condition=Ready", "nodes", "--all", "--timeout=180s"); err != nil {
		return errors.New("bootstrap node readiness timed out")
	}
	for _, deployment := range [][2]string{
		{"capi-system", "capi-controller-manager"},
		{"capi-kubeadm-bootstrap-system", "capi-kubeadm-bootstrap-controller-manager"},
		{"capi-kubeadm-control-plane-system", "capi-kubeadm-control-plane-controller-manager"},
		{"capd-system", "capd-controller-manager"},
		{"cert-manager", "cert-manager"},
		{"cert-manager", "cert-manager-cainjector"},
		{"cert-manager", "cert-manager-webhook"},
	} {
		args := []string{"--kubeconfig", state.BootstrapKubeconfig, "--context", contextName, "-n", deployment[0], "wait", "--for=condition=Available", "deployment/" + deployment[1], "--timeout=900s"}
		if _, err := runLocalCAPIRaw(ctx, runtime, provider, state.BootstrapKubeconfig, nil, "kubectl", args...); err != nil {
			return errors.New("required CAPI or cert-manager controller readiness timed out")
		}
	}
	return nil
}

func validLocalColimaProfileName(profile string) bool {
	return profile != "default" && validLocalColimaProfileSyntax(profile)
}

func validLocalColimaProfileSyntax(profile string) bool {
	return (profile == "default" || regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(profile))
}

func localCAPIStateProfile(state localCAPIState) string {
	if state.ColimaProfile == "" {
		return "default" // v1 receipts created before profile selection were pinned to default.
	}
	return state.ColimaProfile
}

func validLocalDockerContextName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(name)
}

func localCAPIColimaEndpoint(endpoint, profile string) bool {
	if !validLocalColimaProfileSyntax(profile) || !strings.HasPrefix(endpoint, "unix://") || strings.ContainsAny(endpoint, "\\\r\n\x00") {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return false
	}
	path := strings.TrimPrefix(endpoint, "unix://")
	if filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return false
	}
	want := filepath.Join(home, ".colima", profile, "docker.sock")
	return path == want && !strings.Contains(path, string(filepath.Separator)+".."+string(filepath.Separator))
}

func localCAPIHostSocketExists(endpoint string) bool {
	path := strings.TrimPrefix(endpoint, "unix://")
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(home, path)
	if err != nil {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != 3 || parts[0] != ".colima" || parts[2] != "docker.sock" {
		return false
	}
	return localCAPIHostSocketSafeAt(home, parts[1], path)
}

func localCAPIHostSocketSafeAt(home, profile, path string) bool {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	homeInfo, err := os.Lstat(home)
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if !validLocalColimaProfileSyntax(profile) || path != filepath.Join(home, ".colima", profile, "docker.sock") {
		return false
	}
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	current := home
	parts := strings.Split(relative, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode()&os.ModeSocket != 0
		}
		if !info.IsDir() {
			return false
		}
	}
	return false
}

type localColimaInstance struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Runtime string `json:"runtime"`
}

type localColimaStatus struct {
	Runtime      string `json:"runtime"`
	DockerSocket string `json:"docker_socket"`
}

func rejectUnexpectedLocalDockerEnvironment(runtime localRuntime) error {
	environ := runtime.environ
	if environ == nil {
		environ = os.Environ
	}
	for _, item := range environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "DOCKER_") || key == "COLIMA_HOME" || key == "COLIMA_PROFILE" || key == "KIND_EXPERIMENTAL_PROVIDER" || key == "KUBECONFIG" || key == "LIMA_HOME" {
			return errors.New("Docker or Colima environment override is set")
		}
	}
	return nil
}

func observeLocalCAPIStateProvider(ctx context.Context, runtime localRuntime, state localCAPIState) (localProviderIdentity, error) {
	return observeLocalColimaDockerProvider(ctx, runtime, localCAPIStateProfile(state))
}

// observeLocalColimaDockerProvider derives the selected profile's socket from
// Colima status, finds the unique Docker context that references that exact
// endpoint, and obtains the daemon ID through the endpoint-pinned runner.
func observeLocalColimaDockerProvider(ctx context.Context, runtime localRuntime, profile string) (localProviderIdentity, error) {
	if !validLocalColimaProfileSyntax(profile) {
		return localProviderIdentity{}, errors.New("invalid Colima profile")
	}
	instancesRaw, err := runtime.run(ctx, "colima", "list", "--json")
	if err != nil {
		return localProviderIdentity{}, errors.New("cannot read the Colima profile inventory")
	}
	instances, err := parseLocalColimaInstances(instancesRaw)
	if err != nil {
		return localProviderIdentity{}, err
	}
	var selected *localColimaInstance
	for i := range instances {
		if instances[i].Name == profile {
			if selected != nil {
				return localProviderIdentity{}, errors.New("ambiguous Colima profile")
			}
			selected = &instances[i]
		}
	}
	if selected == nil || selected.Status != "Running" || (selected.Runtime != "docker" && selected.Runtime != "docker+k3s") {
		return localProviderIdentity{}, errors.New("selected Colima profile is missing, stopped, or not using the Docker runtime")
	}
	statusRaw, err := runtime.run(ctx, "colima", "status", profile, "--json")
	if err != nil {
		return localProviderIdentity{}, errors.New("cannot read status for the selected Colima profile")
	}
	var status localColimaStatus
	if err := json.Unmarshal(statusRaw, &status); err != nil || status.Runtime != "docker" || !localCAPIColimaEndpoint(status.DockerSocket, profile) {
		return localProviderIdentity{}, errors.New("Colima profile returned an invalid Docker endpoint")
	}
	verifySocket := runtime.verifySocket
	if verifySocket == nil {
		verifySocket = localCAPIHostSocketExists
	}
	if !verifySocket(status.DockerSocket) {
		return localProviderIdentity{}, errors.New("selected Colima Docker endpoint is not a safe profile-owned Unix socket")
	}
	contextsRaw, err := runtime.run(ctx, "docker", "context", "ls", "--format", "{{.Name}}")
	if err != nil {
		return localProviderIdentity{}, errors.New("cannot enumerate configured Docker contexts")
	}
	var matches []string
	for _, contextName := range strings.Fields(string(contextsRaw)) {
		if !validLocalDockerContextName(contextName) {
			return localProviderIdentity{}, errors.New("Docker returned an invalid context name")
		}
		endpointRaw, inspectErr := runtime.run(ctx, "docker", "context", "inspect", contextName, "--format", "{{.Endpoints.docker.Host}}")
		if inspectErr == nil && strings.TrimSpace(string(endpointRaw)) == status.DockerSocket {
			matches = append(matches, contextName)
		}
	}
	if len(matches) != 1 {
		return localProviderIdentity{}, errors.New("selected Colima socket must match exactly one Docker context; check for a missing or duplicate context")
	}
	provider := localProviderIdentity{Kind: "docker", Context: matches[0], Endpoint: status.DockerSocket}
	identityRaw, err := runLocalPinned(ctx, runtime, provider, "docker", "info", "--format", "{{.ID}}")
	if err != nil {
		return localProviderIdentity{}, errors.New("cannot query Docker through the selected Colima socket")
	}
	provider.DaemonID = strings.TrimSpace(string(identityRaw))
	if len(provider.DaemonID) < 3 || len(provider.DaemonID) > 128 || !regexp.MustCompile(`^[A-Za-z0-9._:-]+$`).MatchString(provider.DaemonID) {
		return localProviderIdentity{}, errors.New("selected Docker daemon identity is invalid")
	}
	return provider, nil
}

func parseLocalColimaInstances(raw []byte) ([]localColimaInstance, error) {
	var result []localColimaInstance
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item localColimaInstance
		if err := json.Unmarshal([]byte(line), &item); err != nil || item.Name == "" || item.Status == "" || item.Runtime == "" {
			return nil, errors.New("Colima profile inventory is malformed")
		}
		result = append(result, item)
		if len(result) > 128 {
			return nil, errors.New("Colima profile inventory exceeds the safe limit")
		}
	}
	return result, nil
}

func verifyLocalCAPIDedicatedDaemon(ctx context.Context, runtime localRuntime, provider localProviderIdentity) error {
	checks := [][]string{
		{"container", "ls", "-aq", "--no-trunc"},
		{"volume", "ls", "-q"},
		{"image", "ls", "-q", "--no-trunc"},
	}
	for _, args := range checks {
		output, err := runLocalPinned(ctx, runtime, provider, "docker", args...)
		if err != nil || len(strings.Fields(string(output))) != 0 {
			return errors.New("selected daemon contains existing containers, volumes, or images")
		}
	}
	usage, err := runLocalPinned(ctx, runtime, provider, "docker", "system", "df", "--format", "{{.Type}}|{{.TotalCount}}")
	if err != nil {
		return errors.New("could not verify selected daemon build-cache inventory")
	}
	seenUsage := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(usage)), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			return errors.New("selected daemon resource inventory is malformed")
		}
		count, parseErr := strconv.Atoi(parts[1])
		if parseErr != nil || count < 0 || seenUsage[parts[0]] {
			return errors.New("selected daemon resource inventory is malformed")
		}
		seenUsage[parts[0]] = true
		if count != 0 {
			return errors.New("selected daemon contains existing images, containers, volumes, or build cache")
		}
	}
	if len(seenUsage) != 4 || !seenUsage["Images"] || !seenUsage["Containers"] || !seenUsage["Local Volumes"] || !seenUsage["Build Cache"] {
		return errors.New("selected daemon resource inventory is incomplete")
	}
	networks, err := runLocalPinned(ctx, runtime, provider, "docker", "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		return errors.New("could not verify selected daemon networks")
	}
	for _, network := range strings.Fields(string(networks)) {
		if network != "bridge" && network != "host" && network != "none" {
			return errors.New("selected daemon contains a non-default network")
		}
	}
	kindClusters, err := runLocalPinned(ctx, runtime, provider, "kind", "get", "clusters")
	if err != nil {
		return errors.New("could not safely read selected daemon Kind cluster inventory")
	}
	kindClusterNames, parseErr := parseLocalKindClusterNames(kindClusters)
	if parseErr != nil {
		return errors.New("selected daemon Kind cluster inventory is malformed")
	}
	if len(kindClusterNames) != 0 {
		return errors.New("selected daemon contains existing Kind clusters")
	}
	return nil
}

func validateLocalCAPIKubectlVersion(raw []byte) error {
	var version localCAPIKubectlVersion
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	match := regexp.MustCompile(`^v1\.([0-9]+)\.[0-9]+`).FindStringSubmatch(version.ClientVersion.GitVersion)
	if len(match) != 2 {
		return errors.New("invalid kubectl version")
	}
	minor, _ := strconv.Atoi(match[1])
	if minor < 34 || minor > 36 {
		return errors.New("kubectl minor version outside supported skew")
	}
	return nil
}

func verifyLocalCAPIPreflightProfile(ctx context.Context, runtime localRuntime, profile string, provider localProviderIdentity) error {
	if err := rejectUnexpectedLocalDockerEnvironment(runtime); err != nil {
		return errors.New("unexpected Docker, Colima, Kind, or kubeconfig environment override is set")
	}
	observed, err := observeLocalColimaDockerProvider(ctx, runtime, profile)
	if err != nil {
		return fmt.Errorf("cannot revalidate selected Colima profile: %w", err)
	}
	if observed != provider {
		return errors.New("selected Colima profile context, socket, or Docker daemon identity changed")
	}
	if runtime.run == nil {
		return errors.New("Colima inspection command runner is unavailable")
	}
	if _, err := runtime.run(ctx, "colima", "ssh", "--profile", profile, "--", "sh", "-c", "test -S /var/run/docker.sock"); err != nil {
		return errors.New("Colima SSH could not verify the Docker socket in the selected VM; confirm that the named profile is running")
	}
	vmDaemon, err := runtime.run(ctx, "colima", "ssh", "--profile", profile, "--", "docker", "info", "--format", "{{.ID}}")
	if err != nil {
		return errors.New("Colima SSH could not query Docker through the selected VM socket")
	}
	if strings.TrimSpace(string(vmDaemon)) != provider.DaemonID {
		return errors.New("Docker daemon ID from the selected VM socket does not match the host Colima socket")
	}
	return nil
}

func verifyLocalCAPIProviderStillPinned(ctx context.Context, runtime localRuntime, state localCAPIState) error {
	if err := verifyLocalCAPIPreflightProfile(ctx, runtime, localCAPIStateProfile(state), state.Provider); err != nil {
		return errors.New("selected Colima Docker identity changed")
	}
	return nil
}

func verifyLocalCAPIPrequisites(ctx context.Context, runtime localRuntime, profile string, provider localProviderIdentity) error {
	if err := verifyLocalCAPIPreflightProfile(ctx, runtime, profile, provider); err != nil {
		return fmt.Errorf("selected Colima provider verification failed: %w", err)
	}
	sysctl, err := runtime.run(ctx, "colima", "ssh", "--profile", profile, "--", "sysctl", "-n", "fs.inotify.max_user_instances")
	if err != nil {
		return errors.New("cannot read the inotify limit from the selected Colima VM")
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(sysctl)))
	if err != nil || limit < 8192 {
		return errors.New("Colima fs.inotify.max_user_instances must be at least 8192; no automatic sysctl change is made")
	}
	info, err := runLocalPinned(ctx, runtime, provider, "docker", "info", "--format", `{"cpus":{{.NCPU}},"memory":{{.MemTotal}},"root":{{json .DockerRootDir}}}`)
	if err != nil {
		return errors.New("cannot verify Docker resources")
	}
	var resources localCAPIDockerInfo
	if json.Unmarshal(info, &resources) != nil || resources.CPUs < localCAPIMinCPUs || resources.Memory < localCAPIMinMemoryBytes || resources.Root == "" {
		return errors.New("Docker provider needs at least 2 CPUs and 6 GiB memory for the temporary CAPI bootstrap")
	}
	disk, err := runtime.run(ctx, "colima", "ssh", "--profile", profile, "--", "df", "-Pk", resources.Root)
	if err != nil || !localCAPIHasDiskHeadroom(disk, 15*1024*1024) {
		return errors.New("Colima Docker disk needs at least 15 GiB free for the temporary CAPI bootstrap")
	}
	return nil
}

func renderLocalCAPIKindConfig(name, ownerID string) ([]byte, error) {
	if !localClusterNamePattern.MatchString(name) || !localOwnerIDPattern.MatchString(ownerID) {
		return nil, errors.New("invalid CAPI cluster name or owner identifier")
	}
	kindName := localKindClusterName(name, ownerID)
	if !validLocalKindClusterName(kindName) {
		return nil, errors.New("generated CAPI Kind name violates the hostname length contract")
	}
	text := fmt.Sprintf("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nname: %s\nnetworking:\n  apiServerAddress: 127.0.0.1\nnodes:\n- role: control-plane\n  extraMounts:\n  - hostPath: /var/run/docker.sock\n    containerPath: /var/run/docker.sock\n  kubeadmConfigPatches:\n  - |\n    kind: InitConfiguration\n    nodeRegistration:\n      kubeletExtraArgs:\n        node-labels: %s=%s\n", kindName, localOwnerLabel, ownerID)
	return []byte(text), nil
}

func verifyLocalCAPIStateRoot(root string) error {
	if runtime.GOOS == "windows" {
		return errors.New("private CAPI state permissions are unsupported on this platform")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("state root is not a private non-symlink directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(root)
	info, err := os.Lstat(parent)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state root parent is unavailable or unsafe")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("state root parent is unavailable or unsafe")
	}
	grandparent, grandErr := os.Lstat(filepath.Dir(parent))
	if grandErr != nil || !grandparent.IsDir() || grandparent.Mode()&os.ModeSymlink != 0 {
		return errors.New("state root parent is unavailable or unsafe")
	}
	return nil
}

func ensureLocalCAPIDirectory(path string, exclusive bool) error {
	created := false
	if err := os.Mkdir(path, 0o700); err != nil && (!errors.Is(err, os.ErrExist) || exclusive) {
		return err
	} else if err == nil {
		created = true
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("CAPI lifecycle directories must be private non-symlink directories")
	}
	if created {
		return syncLocalCAPIDirectory(filepath.Dir(path))
	}
	return nil
}

func createLocalCAPILifecycleDirectory(root, name string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !localClusterNamePattern.MatchString(name) {
		return errors.New("invalid CAPI state path")
	}
	if err := ensureLocalCAPISafeParent(filepath.Dir(root)); err != nil {
		return err
	}
	if err := ensureLocalCAPIDirectory(root, false); err != nil {
		return err
	}
	if err := ensureLocalCAPIDirectory(filepath.Join(root, "capi"), false); err != nil {
		return err
	}
	if err := ensureLocalCAPIDirectory(filepath.Join(root, "capi", "clusters"), false); err != nil {
		return err
	}
	return ensureLocalCAPIDirectory(localCAPIStateDirectory(root, name), true)
}

func ensureLocalCAPISafeParent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		grandparent := filepath.Dir(path)
		grandInfo, grandErr := os.Lstat(grandparent)
		if grandErr != nil || !grandInfo.IsDir() || grandInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("CAPI state parent must be beneath an existing directory")
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := syncLocalCAPIDirectory(grandparent); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("CAPI state parent must be an existing non-symlink directory")
	}
	return nil
}

func syncLocalCAPIDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeLocalCAPIState(root string, state localCAPIState, replace bool) error {
	if err := validateLocalCAPIState(root, state); err != nil {
		return err
	}
	dir := localCAPIStateDirectory(root, state.Name)
	if err := verifyLocalCAPIDirectories(root, state.Name); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := localCAPIStateFilePath(root, state.Name)
	if !replace {
		if err := writePrivateNewFile(path, raw); err != nil {
			return err
		}
		return syncLocalCAPIDirectory(dir)
	}
	previous, err := readLocalCAPIState(root, state.Name)
	if err != nil || !sameLocalCAPIIntent(previous, state) || !validLocalCAPITransition(previous.Phase, state.Phase) || !validLocalCAPITemplateEvidenceTransition(previous, state) {
		return errors.New("existing CAPI receipt is invalid, belongs to another intent, or has an invalid phase transition")
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("existing CAPI state is missing, non-regular, symlinked, or not private")
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validLocalCAPITemplateEvidenceTransition(previous, next localCAPIState) bool {
	if (previous.DevelopmentTemplatesAttempted && !next.DevelopmentTemplatesAttempted) ||
		(previous.DevelopmentTemplatesComplete && !next.DevelopmentTemplatesComplete) ||
		(previous.DevelopmentTemplatesSHA256 != "" && previous.DevelopmentTemplatesSHA256 != next.DevelopmentTemplatesSHA256) ||
		len(previous.DevelopmentTemplates) > len(next.DevelopmentTemplates) {
		return false
	}
	if next.DevelopmentTemplatesComplete && !localCAPITemplateInventoryComplete(next.DevelopmentTemplates) {
		return false
	}
	nextByIdentity := map[string]localCAPITemplateEvidence{}
	for _, evidence := range next.DevelopmentTemplates {
		nextByIdentity[evidence.APIVersion+"/"+evidence.Kind+"/"+evidence.Name] = evidence
	}
	for _, evidence := range previous.DevelopmentTemplates {
		if nextByIdentity[evidence.APIVersion+"/"+evidence.Kind+"/"+evidence.Name] != evidence {
			return false
		}
	}
	return true
}

func sameLocalCAPIIntent(previous, next localCAPIState) bool {
	return previous.Format == next.Format && previous.Name == next.Name && previous.OwnerID == next.OwnerID && previous.Provider == next.Provider &&
		previous.BootstrapKindName == next.BootstrapKindName && previous.BootstrapKubeconfig == next.BootstrapKubeconfig &&
		previous.KindConfigPath == next.KindConfigPath && previous.KindConfigSHA256 == next.KindConfigSHA256 &&
		previous.ClusterctlConfigPath == next.ClusterctlConfigPath && previous.ClusterctlConfigSHA256 == next.ClusterctlConfigSHA256 &&
		previous.KubernetesVersion == next.KubernetesVersion && previous.NodeImage == next.NodeImage && mapsEqual(previous.ProviderVersions, next.ProviderVersions)
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validLocalCAPITransition(previous, next localCAPIPhase) bool {
	switch previous {
	case localCAPIPhaseCreating:
		return next == localCAPIPhaseBootstrapReady || next == localCAPIPhaseIncomplete
	case localCAPIPhaseBootstrapReady:
		return next == localCAPIPhaseInitializing || next == localCAPIPhaseIncomplete
	case localCAPIPhaseInitializing:
		return next == localCAPIPhaseInitializing || next == localCAPIPhaseCAPIReady || next == localCAPIPhaseIncomplete
	default:
		return false
	}
}

func readLocalCAPIState(root, name string) (localCAPIState, error) {
	if !localClusterNamePattern.MatchString(name) {
		return localCAPIState{}, errors.New("invalid CAPI logical name")
	}
	if err := verifyLocalCAPIDirectories(root, name); err != nil {
		return localCAPIState{}, err
	}
	path := localCAPIStateFilePath(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return localCAPIState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return localCAPIState{}, errors.New("CAPI state file is not a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return localCAPIState{}, err
	}
	var state localCAPIState
	if err := jsonstrict.Decode(raw, &state); err != nil {
		return localCAPIState{}, errors.New("CAPI state file is malformed or contains unsupported fields")
	}
	if err := validateLocalCAPIState(root, state); err != nil {
		return localCAPIState{}, err
	}
	return state, nil
}

func verifyLocalCAPIDirectories(root, name string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !localClusterNamePattern.MatchString(name) {
		return errors.New("invalid CAPI state directory")
	}
	for _, path := range []string{root, filepath.Join(root, "capi"), filepath.Join(root, "capi", "clusters"), localCAPIStateDirectory(root, name)} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("CAPI lifecycle directories must be private non-symlink directories")
		}
	}
	return nil
}

func runLocalCAPIRaw(ctx context.Context, runtime localRuntime, provider localProviderIdentity, kubeconfig string, extraEnv map[string]string, executable string, args ...string) ([]byte, error) {
	runner := runtime.runCAPI
	if runner == nil {
		runner = runLocalCAPICommand
	}
	return runner(ctx, provider, kubeconfig, extraEnv, executable, args...)
}

func buildLocalCAPIInitArgs(kindName, kubeconfig, clusterctlConfig string, providerWait time.Duration) ([]string, error) {
	if providerWait <= 0 {
		return nil, errors.New("provider wait timeout must be positive")
	}
	// clusterctl's --wait-provider-timeout is an integer number of seconds.
	// Round fractional seconds up so conversion never shortens the requested wait.
	seconds := int64(1 + (providerWait-1)/time.Second)
	return []string{"init", "--core", "cluster-api:" + localCAPIVersion, "--bootstrap", "kubeadm:" + localCAPIVersion,
		"--control-plane", "kubeadm:" + localCAPIVersion, "--infrastructure", "docker:" + localCAPIVersion,
		"--kubeconfig", kubeconfig, "--kubeconfig-context", "kind-" + kindName,
		"--config", clusterctlConfig, "--wait-providers", "--wait-provider-timeout", strconv.FormatInt(seconds, 10)}, nil
}

func isLocalCAPIArgumentUsageFailure(output []byte) bool {
	if len(output) > 128<<10 {
		output = output[:128<<10]
	}
	text := strings.ToLower(string(output))
	for _, marker := range []string{"unknown flag", "unknown shorthand flag", "flag provided but not defined", "flag needs an argument", "unknown command", "invalid argument", "usage:"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func runLocalCAPICommand(ctx context.Context, provider localProviderIdentity, kubeconfig string, extraEnv map[string]string, executable string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	env := make([]string, 0, len(os.Environ())+5+len(extraEnv))
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		if key == "DOCKER_CONTEXT" || key == "DOCKER_HOST" || key == "DOCKER_TLS_VERIFY" || key == "DOCKER_CERT_PATH" || key == "KIND_EXPERIMENTAL_PROVIDER" || key == "KUBECONFIG" || key == "CLUSTER_TOPOLOGY" {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "DOCKER_HOST="+provider.Endpoint, "KIND_EXPERIMENTAL_PROVIDER=docker", "KUBECONFIG="+kubeconfig)
	for key, value := range extraEnv {
		if key != "CLUSTER_TOPOLOGY" || value != "true" {
			return nil, errors.New("CAPI command received an unsupported environment override")
		}
		env = append(env, key+"="+value)
	}
	command.Env = env
	stdout := &boundedDiagnosticOutput{limit: localCAPIMaxOutput}
	var stderr boundedDiagnosticOutput
	stderr.limit = 64 * 1024
	command.Stdout, command.Stderr = stdout, &stderr
	if err := command.Run(); err != nil {
		if filepath.Base(executable) == "clusterctl" && len(args) > 0 && args[0] == "init" && !stdout.truncated && !stderr.truncated &&
			isLocalCAPIArgumentUsageFailure(append(stdout.Bytes(), stderr.Bytes()...)) {
			return nil, errLocalCAPIInitArgumentsRejected
		}
		return nil, errors.New("CAPI command failed; command output suppressed")
	}
	if stdout.truncated {
		return nil, errors.New("CAPI command output exceeded the safe processing limit")
	}
	return stdout.Bytes(), nil
}

func captureLocalCAPIIdentity(ctx context.Context, runtime localRuntime, state *localCAPIState) error {
	observed, err := observeLocalCAPIStateProvider(ctx, runtime, *state)
	if err != nil || observed != state.Provider {
		return errors.New("pinned Docker provider identity changed")
	}
	containers, err := observeLocalKindContainers(ctx, runtime, state.Provider, state.BootstrapKindName)
	if err != nil || len(containers) != 1 || containers[0].Name != state.BootstrapKindName+"-control-plane" || containers[0].Role != "control-plane" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(containers[0].ID) {
		return errors.New("bootstrap Kind container identity is not unique and owner-bound")
	}
	state.Containers = []localCAPIContainerEvidence{{ID: containers[0].ID, Name: containers[0].Name, Role: containers[0].Role, KindClusterName: state.BootstrapKindName}}
	state.BootstrapResourceState = localCAPIResourcePresentUnverified
	if info, err := os.Lstat(state.BootstrapKubeconfig); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		state.BootstrapKubeconfigSeen = true
	}
	kindConfig, err := runLocalPinned(ctx, runtime, state.Provider, "kind", "get", "kubeconfig", "--name", state.BootstrapKindName)
	if err != nil {
		return errors.New("cannot retrieve bootstrap kubeconfig identity")
	}
	private, err := os.ReadFile(state.BootstrapKubeconfig)
	if err != nil || compareKindKubeconfig(kindConfig, private, "kind-"+state.BootstrapKindName) != nil {
		return errors.New("private kubeconfig does not match the owner-bound bootstrap cluster")
	}
	nodesRaw, err := runLocalCAPIRaw(ctx, runtime, state.Provider, state.BootstrapKubeconfig, nil, "kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName, "get", "nodes", "-o", "json")
	if err != nil {
		return errors.New("cannot verify bootstrap Kubernetes nodes")
	}
	var nodes struct {
		Items []struct {
			Metadata struct {
				Name, UID string
				Labels    map[string]string
			} `json:"metadata"`
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(nodesRaw, &nodes) != nil || len(nodes.Items) != 1 {
		return errors.New("bootstrap Kubernetes node inventory is invalid")
	}
	node := nodes.Items[0]
	ready := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			ready = true
		}
	}
	if node.Metadata.Name != containers[0].Name || node.Metadata.UID == "" || node.Metadata.Labels[localOwnerLabel] != state.OwnerID {
		return errors.New("bootstrap node owner identity does not match")
	}
	if !ready {
		return errors.New("bootstrap node is not Ready")
	}
	namespaceRaw, err := runLocalCAPIRaw(ctx, runtime, state.Provider, state.BootstrapKubeconfig, nil, "kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return errors.New("cannot verify bootstrap kube-system identity")
	}
	var namespace struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(namespaceRaw, &namespace) != nil || namespace.Metadata.UID == "" {
		return errors.New("bootstrap kube-system identity is invalid")
	}
	state.Node = &localNodeIdentity{Name: node.Metadata.Name, UID: node.Metadata.UID}
	state.NodeOwnerID = node.Metadata.Labels[localOwnerLabel]
	state.BootstrapResourceState = localCAPIResourceVerified
	state.BootstrapKubeconfigSeen = true
	state.KubeSystemUID = namespace.Metadata.UID
	return nil
}

// inspectLocalCAPIResidual records only bounded read-only identity observations
// after a failed Kind create. It does not call kubeadm, adopt, repair, or delete.
func inspectLocalCAPIResidual(ctx context.Context, runtime localRuntime, state *localCAPIState) {
	state.BootstrapResourceState = localCAPIResourceUnknown
	provider, err := observeLocalCAPIStateProvider(ctx, runtime, *state)
	if err != nil || provider != state.Provider {
		return
	}
	clusters, err := runLocalPinned(ctx, runtime, provider, "kind", "get", "clusters")
	if err != nil {
		return
	}
	clusterNames, err := parseLocalKindClusterNames(clusters)
	if err != nil {
		return
	}
	clusterFound := false
	for _, name := range clusterNames {
		if name == state.BootstrapKindName {
			clusterFound = true
		}
	}
	containers, err := observeLocalKindContainers(ctx, runtime, provider, state.BootstrapKindName)
	if err != nil {
		return
	}
	if !clusterFound && len(containers) == 0 {
		state.BootstrapResourceState = localCAPIResourceAbsent
		return
	}
	if clusterFound && len(containers) == 1 && containers[0].Name == state.BootstrapKindName+"-control-plane" && containers[0].Role == "control-plane" && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(containers[0].ID) {
		state.Containers = []localCAPIContainerEvidence{{ID: containers[0].ID, Name: containers[0].Name, Role: containers[0].Role, KindClusterName: state.BootstrapKindName}}
		state.BootstrapResourceState = localCAPIResourcePresentUnverified
	} else {
		state.BootstrapResourceState = localCAPIResourceAmbiguous
	}
	if info, err := os.Lstat(state.BootstrapKubeconfig); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		state.BootstrapKubeconfigSeen = true
	}
}

// captureLocalCAPIInitEvidence makes only read-only, bounded requests against
// the owner-bound bootstrap kubeconfig. It intentionally omits pod specs,
// environment variables, Secret objects, events, and command output.
func captureLocalCAPIInitEvidence(runtime localRuntime, provider localProviderIdentity, state localCAPIState) *localCAPIInitEvidence {
	// The init command may have consumed the caller's deadline. Give the
	// read-only inventory a small independent window so timeout failures still
	// have a chance to record what was installed.
	inspectCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	evidence := &localCAPIInitEvidence{}
	contextName := "kind-" + state.BootstrapKindName
	if raw, err := runLocalCAPIRaw(inspectCtx, runtime, provider, state.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", contextName,
		"get", "providers.clusterctl.cluster.x-k8s.io", "-A", "-o", "json"); err == nil {
		if providers, parseErr := parseLocalCAPIProviderInventory(raw, true); parseErr == nil {
			evidence.ProvidersObserved = true
			evidence.Providers = providers
		}
	}
	if raw, err := runLocalCAPIRaw(inspectCtx, runtime, provider, state.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", contextName, "get", "deployments", "-A", "-o", "json"); err == nil {
		var inventory struct {
			Items []struct {
				Metadata struct {
					Namespace  string `json:"namespace"`
					Name       string `json:"name"`
					UID        string `json:"uid"`
					Generation int64  `json:"generation"`
				} `json:"metadata"`
				Spec struct {
					Replicas *int32 `json:"replicas"`
				} `json:"spec"`
				Status struct {
					ObservedGeneration int64 `json:"observedGeneration"`
					AvailableReplicas  int32 `json:"availableReplicas"`
				} `json:"status"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &inventory) == nil && len(inventory.Items) <= 4096 {
			evidence.DeploymentsObserved = true
			for _, item := range inventory.Items {
				if !expectedLocalCAPIDeployment(item.Metadata.Namespace, item.Metadata.Name) {
					continue
				}
				if item.Metadata.UID == "" || strings.ContainsAny(item.Metadata.UID, "\r\n\x00") || item.Metadata.Generation < 0 || item.Status.ObservedGeneration < 0 || item.Status.AvailableReplicas < 0 ||
					(item.Spec.Replicas != nil && *item.Spec.Replicas < 0) {
					evidence.DeploymentsObserved = false
					evidence.Deployments = nil
					break
				}
				replicas := int32(0)
				if item.Spec.Replicas != nil {
					replicas = *item.Spec.Replicas
				}
				evidence.Deployments = append(evidence.Deployments, localCAPIWorkloadEvidence{
					Namespace: item.Metadata.Namespace, Name: item.Metadata.Name, UID: item.Metadata.UID,
					Generation: item.Metadata.Generation, ObservedGeneration: item.Status.ObservedGeneration,
					Replicas: replicas, AvailableReplicas: item.Status.AvailableReplicas,
				})
			}
		}
	}
	if raw, err := runLocalCAPIRaw(inspectCtx, runtime, provider, state.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", contextName, "get", "crds", "-o", "json"); err == nil {
		var inventory struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &inventory) == nil && len(inventory.Items) <= 4096 {
			evidence.CRDsObserved = true
			for _, item := range inventory.Items {
				if strings.HasSuffix(item.Metadata.Name, ".cluster.x-k8s.io") || strings.HasSuffix(item.Metadata.Name, ".cert-manager.io") {
					evidence.CRDs = append(evidence.CRDs, item.Metadata.Name)
				}
			}
			sort.Strings(evidence.CRDs)
			if len(evidence.CRDs) > 128 {
				evidence.CRDsObserved = false
				evidence.CRDs = nil
			}
		}
	}
	return evidence
}

func expectedLocalCAPIDeployment(namespace, name string) bool {
	switch namespace + "/" + name {
	case "capi-system/capi-controller-manager",
		"capi-kubeadm-bootstrap-system/capi-kubeadm-bootstrap-controller-manager",
		"capi-kubeadm-control-plane-system/capi-kubeadm-control-plane-controller-manager",
		"capd-system/capd-controller-manager",
		"cert-manager/cert-manager", "cert-manager/cert-manager-cainjector", "cert-manager/cert-manager-webhook":
		return true
	default:
		return false
	}
}

type localCAPIExpectedProvider struct {
	ObjectName string
	Namespace  string
	Version    string
}

func expectedLocalCAPIProviders() map[string]localCAPIExpectedProvider {
	return map[string]localCAPIExpectedProvider{
		"CoreProvider/cluster-api":      {ObjectName: "cluster-api", Namespace: "capi-system", Version: localCAPIVersion},
		"BootstrapProvider/kubeadm":     {ObjectName: "bootstrap-kubeadm", Namespace: "capi-kubeadm-bootstrap-system", Version: localCAPIVersion},
		"ControlPlaneProvider/kubeadm":  {ObjectName: "control-plane-kubeadm", Namespace: "capi-kubeadm-control-plane-system", Version: localCAPIVersion},
		"InfrastructureProvider/docker": {ObjectName: "infrastructure-docker", Namespace: "capd-system", Version: localCAPIVersion},
	}
}

// parseLocalCAPIProviderInventory reads the Kubernetes ProviderList returned by
// kubectl. Missing entries are allowed only for partial-init evidence; every
// observed entry must match the exact type, name, version, and namespace.
func parseLocalCAPIProviderInventory(raw []byte, allowPartial bool) ([]localCAPIProviderEvidence, error) {
	var list localCAPIProviderList
	// kubectl get ... -o json wraps custom resources in the generic core/v1
	// List envelope; it does not return clusterctl's ProviderList type.
	if err := json.Unmarshal(raw, &list); err != nil || list.APIVersion != "v1" || list.Kind != "List" || list.Items == nil || len(list.Items) > 8 {
		return nil, errors.New("Kubernetes provider inventory List is malformed or unsupported")
	}
	want := expectedLocalCAPIProviders()
	seen := make(map[string]bool, len(want))
	providers := make([]localCAPIProviderEvidence, 0, len(list.Items))
	for _, item := range list.Items {
		if item.APIVersion != "clusterctl.cluster.x-k8s.io/v1alpha3" || item.Kind != "Provider" {
			return nil, errors.New("Kubernetes provider inventory contains an unexpected resource type")
		}
		provider := localCAPIProviderEvidence{
			Namespace: item.Metadata.Namespace,
			Type:      item.Type,
			Name:      item.ProviderName,
			Version:   item.Version,
		}
		key := provider.Type + "/" + provider.Name
		expected, ok := want[key]
		if !ok || item.Metadata.Name != expected.ObjectName || provider.Namespace != expected.Namespace || provider.Version != expected.Version || seen[key] {
			return nil, errors.New("Kubernetes provider inventory contains an unexpected or conflicting provider")
		}
		seen[key] = true
		providers = append(providers, provider)
	}
	if !allowPartial && len(providers) != len(want) {
		return nil, errors.New("Kubernetes provider inventory is missing required providers")
	}
	return providers, nil
}

func verifyLocalCAPIReady(ctx context.Context, runtime localRuntime, provider localProviderIdentity, state *localCAPIState) error {
	if err := captureLocalCAPIIdentity(ctx, runtime, state); err != nil {
		return err
	}
	deployRaw, err := runLocalCAPIRaw(ctx, runtime, provider, state.BootstrapKubeconfig, nil, "kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName, "get", "deployments", "-A", "-o", "json")
	if err != nil {
		return errors.New("cannot read CAPI and cert-manager deployment status")
	}
	var deploymentList struct {
		Items []localCAPIDeploymentObservation `json:"items"`
	}
	if json.Unmarshal(deployRaw, &deploymentList) != nil {
		return errors.New("CAPI deployment status is malformed")
	}
	expected := []struct {
		namespace, name string
		capiController  bool
		topology        bool
	}{
		{"capi-system", "capi-controller-manager", true, true},
		{"capi-kubeadm-bootstrap-system", "capi-kubeadm-bootstrap-controller-manager", true, false},
		{"capi-kubeadm-control-plane-system", "capi-kubeadm-control-plane-controller-manager", true, true},
		{"capd-system", "capd-controller-manager", true, true},
		{"cert-manager", "cert-manager", false, false}, {"cert-manager", "cert-manager-cainjector", false, false}, {"cert-manager", "cert-manager-webhook", false, false},
	}
	state.Deployments = nil
	for _, want := range expected {
		var found *localCAPIDeploymentObservation
		for i := range deploymentList.Items {
			item := &deploymentList.Items[i]
			if item.Metadata.Namespace == want.namespace && item.Metadata.Name == want.name {
				found = item
				break
			}
		}
		if found == nil || found.Metadata.UID == "" || found.Spec.Replicas == nil || *found.Spec.Replicas < 1 || found.Status.ObservedGeneration < found.Metadata.Generation || found.Status.AvailableReplicas != *found.Spec.Replicas {
			return errors.New("required CAPI or cert-manager deployment is not fully Available")
		}
		evidence := localCAPIDeploymentEvidence{Namespace: want.namespace, Name: want.name, UID: found.Metadata.UID, Replicas: *found.Spec.Replicas, AvailableReplicas: found.Status.AvailableReplicas}
		managerFound := false
		managerSocketVolume := ""
		managerImage := ""
		for _, container := range found.Spec.Template.Spec.Containers {
			evidence.Images = append(evidence.Images, container.Image)
			if container.Name == "manager" {
				managerImage = container.Image
				evidence.ManagerImage = container.Image
			}
			if want.capiController && container.Name == "manager" {
				managerFound = true
			}
			if want.topology && container.Name == "manager" {
				gate := false
				for _, arg := range container.Args {
					for _, setting := range strings.Split(strings.TrimPrefix(arg, "--feature-gates="), ",") {
						if setting == "ClusterTopology=true" {
							gate = true
						}
					}
				}
				evidence.ClusterTopology = evidence.ClusterTopology || gate
			}
			if want.namespace == "capd-system" && container.Name == "manager" {
				for _, mount := range container.VolumeMounts {
					if mount.Name != "" && mount.MountPath == "/var/run/docker.sock" {
						managerSocketVolume = mount.Name
					}
				}
			}
		}
		if want.namespace == "capd-system" {
			for _, volume := range found.Spec.Template.Spec.Volumes {
				if volume.Name == managerSocketVolume && volume.HostPath != nil && volume.HostPath.Path == "/var/run/docker.sock" {
					evidence.DockerSocketMounted = true
				}
			}
		}
		if len(evidence.Images) == 0 || (want.capiController && (!managerFound || !strings.HasSuffix(managerImage, ":"+localCAPIVersion))) || (want.topology && !evidence.ClusterTopology) {
			return errors.New("required controller image or ClusterTopology feature gate evidence is missing")
		}
		if want.namespace == "capd-system" && !evidence.DockerSocketMounted {
			return errors.New("CAPD manager does not mount the verified Docker socket path")
		}
		if want.namespace == "cert-manager" {
			for _, image := range evidence.Images {
				if !strings.HasSuffix(image, ":"+localCAPICertManagerVersion) {
					return errors.New("cert-manager image version does not match the pinned receipt")
				}
			}
		}
		state.Deployments = append(state.Deployments, evidence)
	}
	providersRaw, err := runLocalCAPIRaw(ctx, runtime, provider, state.BootstrapKubeconfig, nil,
		"kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName,
		"get", "providers.clusterctl.cluster.x-k8s.io", "-A", "-o", "json")
	if err != nil {
		return errors.New("cannot verify installed CAPI provider versions")
	}
	providers, err := parseLocalCAPIProviderInventory(providersRaw, false)
	if err != nil || len(providers) != len(expectedLocalCAPIProviders()) {
		return errors.New("installed CAPI provider inventory does not exactly match the pinned set")
	}
	state.InstalledProviderVersions = map[string]string{"cluster-api": localCAPIVersion, "kubeadm-bootstrap": localCAPIVersion,
		"kubeadm-control-plane": localCAPIVersion, "docker-infrastructure": localCAPIVersion}
	state.InstalledProviderVersions["cert-manager"] = localCAPICertManagerVersion // independently matched against all three pinned deployment images above
	crdRaw, err := runLocalCAPIRaw(ctx, runtime, provider, state.BootstrapKubeconfig, nil, "kubectl", "--kubeconfig", state.BootstrapKubeconfig, "--context", "kind-"+state.BootstrapKindName, "get", "crds", "-o", "json")
	if err != nil {
		return errors.New("cannot verify required CAPI CRDs")
	}
	var crds struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal(crdRaw, &crds) != nil {
		return errors.New("CAPI CRD inventory is malformed")
	}
	available := map[string]bool{}
	for _, crd := range crds.Items {
		available[crd.Metadata.Name] = true
	}
	for _, required := range []string{"clusters.cluster.x-k8s.io", "kubeadmconfigs.bootstrap.cluster.x-k8s.io", "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io", "dockerclusters.infrastructure.cluster.x-k8s.io"} {
		if !available[required] {
			return errors.New("required CAPI CRD is missing")
		}
		state.CRDs = append(state.CRDs, required)
	}
	sort.Strings(state.CRDs)
	observed, err := observeLocalCAPIStateProvider(ctx, runtime, *state)
	if err != nil || observed != state.Provider {
		return errors.New("Docker provider identity changed during CAPI initialization")
	}
	return nil
}

func localCAPIDeploymentIsCAPIController(namespace string) bool {
	return namespace == "capi-system" || strings.HasPrefix(namespace, "capi-kubeadm-") || namespace == "capd-system"
}

func localCAPIControllerRequiresClusterTopology(namespace, name string) bool {
	switch namespace + "/" + name {
	case "capi-system/capi-controller-manager",
		"capi-kubeadm-control-plane-system/capi-kubeadm-control-plane-controller-manager",
		"capd-system/capd-controller-manager":
		return true
	default:
		return false
	}
}
