package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
	"github.com/openkubes/ok-cluster/internal/runner"
)

type clusterKubeconfigReference struct {
	Kubeconfig string `yaml:"kubeconfig" json:"kubeconfig"`
	Context    string `yaml:"context,omitempty" json:"context,omitempty"`
}

type clusterIntentTargets struct {
	Management     kubeconfigtarget.Target `json:"management"`
	Infrastructure kubeconfigtarget.Target `json:"infrastructure"`
}

func validateClusterKubeconfigReferences(intent clusterIntent) error {
	if (intent.Spec.Management == nil) != (intent.Spec.Infrastructure == nil) {
		return errors.New("spec.management and spec.infrastructure kubeconfig references must be supplied together")
	}
	for _, ref := range []*clusterKubeconfigReference{intent.Spec.Management, intent.Spec.Infrastructure} {
		if ref == nil {
			continue
		}
		if ref.Kubeconfig == "" || strings.TrimSpace(ref.Kubeconfig) != ref.Kubeconfig || strings.IndexFunc(ref.Kubeconfig, unicode.IsControl) >= 0 || strings.TrimSpace(ref.Context) != ref.Context || strings.IndexFunc(ref.Context, unicode.IsControl) >= 0 {
			return errors.New("kubeconfig references require a literal non-empty path and optional literal context")
		}
	}
	return nil
}

func readClusterIntentTargets(intentPath string, intent clusterIntent) (*clusterIntentTargets, error) {
	if err := validateClusterKubeconfigReferences(intent); err != nil {
		return nil, err
	}
	if intent.Spec.Management == nil {
		return nil, nil
	}
	selected := &clusterIntentTargets{}
	for _, field := range []struct {
		role   string
		ref    *clusterKubeconfigReference
		target *kubeconfigtarget.Target
	}{
		{"management", intent.Spec.Management, &selected.Management}, {"infrastructure", intent.Spec.Infrastructure, &selected.Infrastructure},
	} {
		path := field.ref.Kubeconfig
		if path == "~" || strings.HasPrefix(path, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			if path == "~" {
				path = home
			} else {
				path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
			}
		}
		if strings.HasPrefix(path, "~") {
			return nil, errors.New("only ~/ home expansion is supported in kubeconfig paths")
		}
		if !filepath.IsAbs(path) {
			base, err := filepath.Abs(intentPath)
			if err != nil {
				return nil, err
			}
			path = filepath.Join(filepath.Dir(base), path)
		}
		target, err := kubeconfigtarget.Read(filepath.Clean(path), field.ref.Context)
		if err != nil {
			return nil, fmt.Errorf("%s kubeconfig target: %w", field.role, err)
		}
		*field.target = target
	}
	return selected, nil
}

func verifyClusterIntentTargets(intentPath string, binding clusterIntentBindingReceipt, manifestPath, manifestDigest string) error {
	if binding.Targets == nil {
		return nil
	}
	intent, err := readClusterIntent(intentPath)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(intent)
	if digest.SHA256(raw) != binding.NormalizedIntentDigest {
		return errors.New("YAML changed since target selection; no execution")
	}
	current, err := readClusterIntentTargets(intentPath, intent)
	if err != nil {
		return err
	}
	if current == nil || *current != *binding.Targets {
		return errors.New("selected kubeconfig target changed since preparation; no execution")
	}
	return runner.VerifyFullRunManifestPlaneTargets(manifestPath, manifestDigest, current.Management, current.Infrastructure)
}
