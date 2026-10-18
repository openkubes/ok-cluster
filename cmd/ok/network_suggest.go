package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func runNetworkSuggest(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok up network-suggest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("file", "", "Existing friendly YAML; proposed network replaces its example values")
	output := flags.String("output", "", "Optional NEW YAML file; never overwrite the input or existing files")
	root := flags.String("lifecycle-root", "", "Trusted renderer checkout (or saved path)")
	inventory := flags.String("clusters-dir", "", "Existing local cluster inventory (or saved clustersDir)")
	configPath := flags.String("config", "", "Local path configuration")
	online := flags.Bool("online", false, "Explicit read-only queries of both YAML-selected APIs and infra MetalLB pools")
	pool := flags.String("pool", "", "Online: MetalLB pool namespace/name; required if ambiguous")
	rangeValue := flags.String("endpoint-pool", "", "Offline: explicitly approved IPv4 range start-end or CIDR; no hidden site default")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: ok up network-suggest --file cluster.yaml [--online [--pool namespace/name] | --endpoint-pool start-end] [--output cluster.proposed.yaml]")
		flags.PrintDefaults()
		fmt.Fprintln(stderr, "Proposal only, not a reservation, authorization, runner preparation or convergence evidence. Offline never reads kubeconfigs or opens an API; online errors never fall back. No credentials are issued or renewed. JSON reports before/after and evidence scope. Review the new YAML before ok up; allocations must be rechecked before separately authorized live execution.")
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || (*online && *rangeValue != "") || (!*online && (*rangeValue == "" || *pool != "")) {
		return errors.New("network-suggest requires --file and either --online or an explicit offline --endpoint-pool; see --help")
	}
	emptyFlag := false
	flags.Visit(func(f *flag.Flag) {
		if f.Value.String() == "" {
			emptyFlag = true
		}
	})
	if emptyFlag {
		return errors.New("explicit proposal flags must not be empty")
	}
	intent, err := readClusterIntent(*input)
	if err != nil {
		return err
	}
	if *output != "" {
		if _, err := os.Lstat(*output); !os.IsNotExist(err) {
			return errors.New("proposal output must not exist")
		}
	}
	if *root == "" || *inventory == "" || *configPath != "" {
		path, err := localConfigPath(*configPath)
		if err != nil {
			return err
		}
		config, err := loadLocalConfig(path)
		if err != nil {
			return fmt.Errorf("network proposal requires source/inventory paths or ok config init: %w", err)
		}
		if *root == "" {
			*root = config.LifecycleRoot
		}
		if *inventory == "" {
			*inventory = config.ClustersDir
		}
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	inventoryPath, err := filepath.Abs(*inventory)
	if err != nil {
		return err
	}
	payload := map[string]any{"intent": intent, "inventory": inventoryPath, "online": *online, "pool": *pool, "endpointPool": *rangeValue}
	var selectedTargets *clusterIntentTargets
	if *online {
		targets, err := readClusterIntentTargets(*input, intent)
		if err != nil {
			return err
		}
		if targets == nil {
			return errors.New("--online requires both management and infrastructure kubeconfig references in YAML")
		}
		// Normalize relative paths in the copied intent, never use current-context.
		for _, ref := range []*clusterKubeconfigReference{intent.Spec.Management, intent.Spec.Infrastructure} {
			path, err := networkReferencePath(*input, ref.Kubeconfig)
			if err != nil {
				return err
			}
			ref.Kubeconfig = path
		}
		intent.Spec.Management.Context = targets.Management.Context
		intent.Spec.Infrastructure.Context = targets.Infrastructure.Context
		payload["intent"] = intent
		payload["targets"] = targets
		selectedTargets = targets
	}
	if userConfig, err := os.UserConfigDir(); err == nil && filepath.IsAbs(userConfig) {
		payload["managedRuns"] = filepath.Join(userConfig, "ok", "runs")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", filepath.Join(rootPath, "scripts", "suggest_cluster_network.py"))
	command.Stdin = bytes.NewReader(raw)
	var result bytes.Buffer
	command.Stdout = &result
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return errors.New("network proposal stopped; no allocation, authorization or runner execution")
	}
	if selectedTargets != nil {
		current, err := readClusterIntentTargets(*input, intent)
		if err != nil || current == nil || *current != *selectedTargets {
			return errors.New("selected kubeconfig targets changed during proposal; no output YAML")
		}
	}
	var receipt struct {
		Format                          string `json:"format"`
		State                           string `json:"state"`
		Name                            string `json:"name"`
		APIContacted                    *bool  `json:"apiContacted"`
		ObservedCollisionCheckCompleted *bool  `json:"observedCollisionCheckCompleted"`
		GlobalAvailabilityProven        *bool  `json:"globalAvailabilityProven"`
		ReservationCreated              *bool  `json:"reservationCreated"`
		AuthorizationConsumed           *bool  `json:"authorizationConsumed"`
		MutationAllowed                 *bool  `json:"mutationAllowed"`
		RunnerReady                     *bool  `json:"runnerReady"`
		Network                         struct {
			Endpoint    string `json:"endpoint"`
			PodCIDR     string `json:"podCIDR"`
			ServiceCIDR string `json:"serviceCIDR"`
		} `json:"proposedNetwork"`
	}
	if err := json.Unmarshal(result.Bytes(), &receipt); err != nil || receipt.Format != "ok-cli-network-proposal/v1" || receipt.State != "PROPOSED_NOT_RESERVED" || receipt.Name != intent.Metadata.Name {
		return errors.New("invalid owning network proposal")
	}
	if receipt.APIContacted == nil || *receipt.APIContacted != *online || receipt.ObservedCollisionCheckCompleted == nil || *receipt.ObservedCollisionCheckCompleted != *online {
		return errors.New("network proposal contact evidence differs from requested mode")
	}
	for _, value := range []*bool{receipt.GlobalAvailabilityProven, receipt.ReservationCreated, receipt.AuthorizationConsumed, receipt.MutationAllowed, receipt.RunnerReady} {
		if value == nil || *value {
			return errors.New("network proposal crossed its non-authorizing boundary")
		}
	}
	intent.Spec.Network.Endpoint = receipt.Network.Endpoint
	intent.Spec.Network.PodCIDR = receipt.Network.PodCIDR
	intent.Spec.Network.ServiceCIDR = receipt.Network.ServiceCIDR
	if err := validateClusterIntentNetwork(intent); err != nil {
		return fmt.Errorf("owning proposal returned invalid network: %w", err)
	}
	if *output != "" {
		// Relative references must retain their meaning in a different directory.
		for _, ref := range []*clusterKubeconfigReference{intent.Spec.Management, intent.Spec.Infrastructure} {
			if ref != nil {
				path, err := networkReferencePath(*input, ref.Kubeconfig)
				if err != nil {
					return err
				}
				ref.Kubeconfig = path
			}
		}
		raw, err := yaml.Marshal(intent)
		if err != nil {
			return err
		}
		if err := writeStaticBindingFile(*output, raw); err != nil {
			return err
		}
		fmt.Fprintln(stderr, "Proposed YAML written create-only; review it before ok up. No reservation or live approval.")
	}
	_, err = stdout.Write(result.Bytes())
	return err
}

func networkReferencePath(input, path string) (string, error) {
	if len(path) > 0 && path[0] == '~' && !(len(path) >= 2 && path[:2] == "~/") {
		return "", errors.New("only ~/ home expansion is supported")
	}
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(input)
		if err != nil {
			return "", err
		}
		path = filepath.Join(filepath.Dir(absolute), path)
	}
	return filepath.Clean(path), nil
}
