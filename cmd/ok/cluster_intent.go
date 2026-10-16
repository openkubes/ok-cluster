package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const clusterIntentAPIVersion = "cli.openkubes.io/v1alpha1"

// An intent is not a Contract, execution manifest, reservation or authority.
type clusterIntent struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`
	Metadata   struct {
		Name string `yaml:"name" json:"name"`
	} `yaml:"metadata" json:"metadata"`
	Spec struct {
		Profile string `yaml:"profile" json:"profile"`
		Network struct {
			Endpoint    string `yaml:"endpoint" json:"endpoint"`
			PodCIDR     string `yaml:"podCIDR" json:"podCIDR"`
			ServiceCIDR string `yaml:"serviceCIDR" json:"serviceCIDR"`
		} `yaml:"network" json:"network"`
	} `yaml:"spec" json:"spec"`
}

func readClusterIntent(path string) (clusterIntent, error) {
	var intent clusterIntent
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return intent, errors.New("cluster YAML must be a regular non-symlink file, at most 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return intent, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return intent, errors.New("cluster YAML changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return intent, errors.New("cannot read bounded cluster YAML")
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil {
		return intent, errors.New("invalid cluster YAML")
	}
	var inspect func(*yaml.Node) error
	inspect = func(node *yaml.Node) error {
		if node.Kind == yaml.ScalarNode && node.Tag != "!!str" {
			return errors.New("cluster YAML fields must be strings")
		}
		if node.Kind == yaml.AliasNode || node.Anchor != "" {
			return errors.New("cluster YAML aliases and anchors are not supported")
		}
		if node.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
					return errors.New("cluster YAML requires unique string keys; merge keys are not supported")
				}
				seen[key.Value] = true
			}
		}
		for _, child := range node.Content {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(&document); err != nil {
		return intent, err
	}
	decoder = yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&intent); err != nil {
		return intent, errors.New("cluster YAML contains an unknown field or invalid structure")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return intent, errors.New("exactly one cluster YAML document is required")
	}
	name := intent.Metadata.Name
	if intent.APIVersion != clusterIntentAPIVersion || intent.Kind != "Cluster" || intent.Spec.Profile != "talos-kubevirt-mvp" {
		return intent, errors.New("expected cli.openkubes.io/v1alpha1 Cluster with profile talos-kubevirt-mvp")
	}
	if !clusterCreateNamePattern.MatchString(name) || len(name) > 63 || name == "default" || strings.HasPrefix(name, "kube-") {
		return intent, errors.New("cluster YAML name must be a non-reserved DNS label of at most 63 characters")
	}
	network := intent.Spec.Network
	ip, err := netip.ParseAddr(network.Endpoint)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return intent, errors.New("network.endpoint must be an explicit unicast IPv4 address, not auto")
	}
	pod, podErr := netip.ParsePrefix(network.PodCIDR)
	service, serviceErr := netip.ParsePrefix(network.ServiceCIDR)
	if podErr != nil || serviceErr != nil || !pod.Addr().Is4() || !service.Addr().Is4() || pod != pod.Masked() || service != service.Masked() || pod.Overlaps(service) || pod.Contains(ip) || service.Contains(ip) {
		return intent, errors.New("podCIDR and serviceCIDR must be canonical, disjoint IPv4 networks excluding the endpoint")
	}
	return intent, nil
}

func isClusterYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return true
	}
	// Technical JSON manifests have always been independent of filename suffix.
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()
	raw, _ := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	return !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{"))
}

func writeClusterIntentTemplate(stdout io.Writer) error {
	_, err := fmt.Fprint(stdout, `# Local intent only. Addresses below are examples, not verified allocations.
apiVersion: cli.openkubes.io/v1alpha1
kind: Cluster
metadata:
  name: my-cluster
spec:
  profile: talos-kubevirt-mvp
  network:
    endpoint: 192.0.2.10
    podCIDR: 10.42.0.0/16
    serviceCIDR: 10.96.0.0/20
`)
	return err
}

func validateClusterYAMLWorkflow(path string, dryRun bool, stdout io.Writer) error {
	intent, err := readClusterIntent(path)
	if err != nil {
		return err
	}
	if !dryRun {
		return errors.New("cluster YAML is NO-GO: full runner binding is not implemented; use ok up render for local artifacts only; --prepare/--live require a separately bound technical JSON manifest")
	}
	return json.NewEncoder(stdout).Encode(struct {
		Format                string `json:"format"`
		State                 string `json:"state"`
		Name                  string `json:"name"`
		APIContacted          bool   `json:"apiContacted"`
		AuthorizationConsumed bool   `json:"authorizationConsumed"`
		MutationAllowed       bool   `json:"mutationAllowed"`
		RunnerReady           bool   `json:"runnerReady"`
		CollisionChecked      bool   `json:"collisionChecked"`
		NextAction            string `json:"nextAction"`
	}{"ok-cli-cluster-intent-validation/v1", "INTENT_VALIDATED_NO_GO", intent.Metadata.Name, false, false, false, false, false,
		"ok up render --file <cluster.yaml> --output <new-private-directory>; local validation is not full-run preparation, a reservation or live approval"})
}

func runClusterIntentRender(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster create render", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("file", "", "Friendly cluster YAML")
	output := flags.String("output", "", "New private render directory; never reused or overwritten")
	root := flags.String("lifecycle-root", "", "Trusted lifecycle checkout (or saved local path)")
	profiles := flags.String("ok-linux-path", "", "Reviewed ok-linux profiles (or saved local path)")
	configFile := flags.String("config", "", "Explicit local path configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("render requires --file and a new --output directory; see ok up render --help")
	}
	explicitEmpty := false
	flags.Visit(func(f *flag.Flag) {
		if f.Value.String() == "" {
			explicitEmpty = true
		}
	})
	if explicitEmpty {
		return errors.New("explicit render path flags must not be empty")
	}
	intent, err := readClusterIntent(*input)
	if err != nil {
		return err
	}
	if *root == "" || *profiles == "" || *configFile != "" {
		path, err := localConfigPath(*configFile)
		if err != nil {
			return err
		}
		config, err := loadLocalConfig(path)
		if err != nil {
			return fmt.Errorf("render requires explicit lifecycle/profile paths or ok config init: %w", err)
		}
		if *root == "" {
			*root = config.LifecycleRoot
		}
		if *profiles == "" {
			*profiles = config.OKLinuxPath
		}
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	profilePath, err := filepath.Abs(*profiles)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		return errors.New("render output must not exist; no overwrite or resume is allowed")
	}
	script := filepath.Join(rootPath, "scripts", "render_cluster_intent.py")
	if err := destroyRegularFile(script); err != nil {
		return errors.New("trusted lifecycle checkout does not contain the YAML intent renderer; update it first")
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "python3", "-B", script, "--output", outputPath, "--ok-linux-path", profilePath)
	command.Dir = rootPath
	command.Stdin = bytes.NewReader(raw)
	command.Stdout, command.Stderr = stdout, stderr
	return command.Run()
}

func writeClusterIntentRenderHelp(stdout io.Writer) {
	fmt.Fprint(stdout, `Render a friendly cluster YAML locally; not a runner-ready preparation

Usage:
  ok up cluster-template
  ok up --file cluster.yaml --dry-run
  ok up render --file cluster.yaml --output <new-private-directory> [paths]

Paths: --lifecycle-root <trusted-checkout> --ok-linux-path <profile-checkout>
or saved local paths from ok config init; --config selects an explicit file.
Only those two saved paths are used: kubeconfigs and credential contents are not read.

Profile talos-kubevirt-mvp fixes one control plane and one worker, each with
2 cores / 4Gi memory / 20Gi disk and Kubernetes v1.34.1. Talos, Golden image,
provider settings and storage semantics come from the existing owning resolver.
Explicit endpoint/podCIDR/serviceCIDR are required; no auto allocation or collision
check is performed. The output is create-only, private and remains RENDERED_NO_GO.
Generated shell helpers are not executable and are never run.

Full Contract/Plan/fixture/authority/credential binding is still required and is
not implemented by this YAML step. YAML --prepare and --live fail closed.
No API client, credential issuance, authority rebinding or live stage is opened.
Existing technical JSON manifests keep their original workflow and receipts.
`)
}
