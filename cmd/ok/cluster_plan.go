package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

const (
	clusterRequestAPIVersion = "cli.openkubes.io/v1alpha1"
	clusterRequestKind       = "ClusterRequest"
	clusterRequestProfile    = "talos-kubevirt-reference"
	clusterRequestSchematic  = "ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515"
)

var clusterRequestVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

// clusterRequest is a small, versioned user request for the trusted Make
// Talos/KubeVirt workflow. Its distinct kind is intentional: the existing
// cli.openkubes.io/v1alpha1 Cluster kind is a Contract/Runner intent with
// different fields and validation semantics, which this preview must not alter.
type clusterRequest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Profile      string `yaml:"profile"`
		ControlPlane struct {
			Replicas *int `yaml:"replicas"`
		} `yaml:"controlPlane"`
		Workers struct {
			Replicas *int `yaml:"replicas"`
		} `yaml:"workers"`
		Versions struct {
			Kubernetes string `yaml:"kubernetes"`
			Talos      string `yaml:"talos"`
		} `yaml:"versions"`
		Network struct {
			Endpoint    string `yaml:"endpoint"`
			PodCIDR     string `yaml:"podCIDR"`
			ServiceCIDR string `yaml:"serviceCIDR"`
		} `yaml:"network"`
	} `yaml:"spec"`
}

type clusterPlanValues struct {
	Name, Profile, Kubernetes, Talos string
	Endpoint, PodCIDR, ServiceCIDR   string
	ControlPlaneReplicas, Workers    int
	SchematicID                      string
}

const clusterPlanText = `OpenKubes Cluster Plan (read-only)

Request: {{.Name}}
Profile: {{.Profile}}
Backend: trusted administrator Make workflow (Talos on KubeVirt)

Required request fields: metadata.name and spec.profile.
Defaults: control plane=1; workers=1; Kubernetes=v1.34.1; Talos=v1.9.6;
network values=auto; CPU/memory/disk and ok-infra scheduling are fixed by this profile.

Resolved inputs
  Control plane: {{.ControlPlaneReplicas}} replica(s), 2 CPU, 4Gi memory, 20Gi disk
  Workers:       {{.Workers}} replica(s), 2 CPU, 4Gi memory, 15Gi disk per worker
  Kubernetes:    {{.Kubernetes}}
  Talos:         {{.Talos}}
  Scheduling:    ok-infra (fixed reference profile)
  OS profile:    ok-linux/kubevirt
  OS schematic:  {{.SchematicID}}
  CNI:           Cilium v1.19.6 (local digest-verified chart required)
  Endpoint:      {{.Endpoint}}
  Pod CIDR:      {{.PodCIDR}}
  Service CIDR:  {{.ServiceCIDR}}

Existing Make steps (not executed)
  1. make new CLUSTER={{.Name}} TYPE=talos SCHEDULING_PROFILE=ok-infra WORKERS={{.Workers}} K8S_VERSION={{.Kubernetes}} TALOS_VERSION={{.Talos}}
     Scaffolds cluster configuration and renders the Talos/KubeVirt manifests.
  2. make bootstrap CLUSTER={{.Name}}
     Runs the existing preflight, applies the management-side Cluster resource,
     waits for API access, installs pinned Cilium, and checks expected Nodes.
     Requires the repository's digest-verified Cilium chart cache and Make access
     to the management cluster; neither is checked by this offline plan.

This plan is informational only. It does not authorize or execute operations,
reserve the name or network values, contact Kubernetes, or attest outcomes.
`

func readClusterRequest(path string) (clusterRequest, error) {
	var request clusterRequest
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return request, errors.New("cluster request must be a regular non-symlink file, at most 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return request, errors.New("cannot open cluster request")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return request, errors.New("cluster request changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return request, errors.New("cannot read bounded cluster request")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return request, errors.New("invalid cluster request YAML")
	}
	if err := validateClusterRequestYAMLNode(&document); err != nil {
		return request, err
	}
	decoder = yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("cluster request contains an unknown field or invalid structure")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return request, errors.New("exactly one cluster request YAML document is required")
	}
	if err := validateClusterRequest(request); err != nil {
		return request, err
	}
	return request, nil
}

func validateClusterRequestYAMLNode(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag != "!!str" && node.Tag != "!!int" {
		return errors.New("cluster request scalars must be strings or integers")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("cluster request YAML aliases and anchors are not supported")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return errors.New("cluster request requires unique string keys; merge keys are not supported")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateClusterRequestYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}

func validateClusterRequest(request clusterRequest) error {
	if request.APIVersion != clusterRequestAPIVersion || request.Kind != clusterRequestKind {
		return fmt.Errorf("expected %s %s", clusterRequestAPIVersion, clusterRequestKind)
	}
	name := request.Metadata.Name
	if !clusterCreateNamePattern.MatchString(name) || len(name) > 63 || name == "default" || strings.HasPrefix(name, "kube-") {
		return errors.New("metadata.name must be a non-reserved DNS label of at most 63 characters")
	}
	if request.Spec.Profile != clusterRequestProfile {
		return fmt.Errorf("unsupported profile %q; only %q is supported", request.Spec.Profile, clusterRequestProfile)
	}
	cp := 1
	if request.Spec.ControlPlane.Replicas != nil {
		cp = *request.Spec.ControlPlane.Replicas
	}
	workers := 1
	if request.Spec.Workers.Replicas != nil {
		workers = *request.Spec.Workers.Replicas
	}
	if cp != 1 || workers < 1 || workers > 10 {
		return errors.New("reference profile requires exactly one control-plane replica and 1 to 10 worker replicas")
	}
	if request.Spec.Versions.Kubernetes != "" && !clusterRequestVersionPattern.MatchString(request.Spec.Versions.Kubernetes) {
		return errors.New("spec.versions.kubernetes must be a pinned v-prefixed version")
	}
	if request.Spec.Versions.Talos != "" && !clusterRequestVersionPattern.MatchString(request.Spec.Versions.Talos) {
		return errors.New("spec.versions.talos must be a pinned v-prefixed version")
	}
	return validateClusterRequestNetwork(request.Spec.Network)
}

func validateClusterRequestNetwork(network struct {
	Endpoint    string `yaml:"endpoint"`
	PodCIDR     string `yaml:"podCIDR"`
	ServiceCIDR string `yaml:"serviceCIDR"`
}) error {
	for _, input := range []struct{ field, value string }{
		{"endpoint", network.Endpoint}, {"podCIDR", network.PodCIDR}, {"serviceCIDR", network.ServiceCIDR},
	} {
		field, value := input.field, input.value
		if value != "" && value != "auto" {
			return fmt.Errorf("spec.network.%s must be omitted or auto for this Make profile; explicit allocation is not supported by the scaffold contract", field)
		}
	}
	return nil
}

func runClusterPlan(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var input clusterPlanInputFlag
	flags.Var(&input, "file", "ClusterRequest YAML file")
	flags.Var(&input, "f", "ClusterRequest YAML file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || input.value == "" {
		return errors.New("ok cluster plan requires -f <cluster.yaml>")
	}
	request, err := readClusterRequest(input.value)
	if err != nil {
		return err
	}
	values := clusterPlanValues{
		Name: request.Metadata.Name, Profile: request.Spec.Profile,
		Kubernetes: request.Spec.Versions.Kubernetes, Talos: request.Spec.Versions.Talos,
		Endpoint: request.Spec.Network.Endpoint, PodCIDR: request.Spec.Network.PodCIDR, ServiceCIDR: request.Spec.Network.ServiceCIDR,
		ControlPlaneReplicas: 1, Workers: 1, SchematicID: clusterRequestSchematic,
	}
	if values.Kubernetes == "" {
		values.Kubernetes = "v1.34.1"
	}
	if values.Talos == "" {
		values.Talos = "v1.9.6"
	}
	if request.Spec.ControlPlane.Replicas != nil {
		values.ControlPlaneReplicas = *request.Spec.ControlPlane.Replicas
	}
	if request.Spec.Workers.Replicas != nil {
		values.Workers = *request.Spec.Workers.Replicas
	}
	if values.Endpoint == "" {
		values.Endpoint = "auto (unresolved; Make allocates during scaffold/render)"
	} else {
		values.Endpoint += " (unresolved; Make allocates during scaffold/render)"
	}
	if values.PodCIDR == "" {
		values.PodCIDR = "auto (unresolved; Make allocates during render)"
	} else {
		values.PodCIDR += " (unresolved; Make allocates during render)"
	}
	if values.ServiceCIDR == "" {
		values.ServiceCIDR = "auto (unresolved; Make allocates during render)"
	} else {
		values.ServiceCIDR += " (unresolved; Make allocates during render)"
	}
	template, err := template.New("cluster-plan").Parse(clusterPlanText)
	if err != nil {
		return errors.New("internal plan template is invalid")
	}
	return template.Execute(stdout, values)
}

type clusterPlanInputFlag struct {
	value string
	set   bool
}

func (input *clusterPlanInputFlag) String() string { return input.value }

func (input *clusterPlanInputFlag) Set(value string) error {
	if input.set {
		return errors.New("specify exactly one of -f or --file")
	}
	input.value, input.set = value, true
	return nil
}
