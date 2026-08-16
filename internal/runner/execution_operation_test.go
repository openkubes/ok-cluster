package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestOpenKubernetesExecutionOperationComposesBoundedRuntime(t *testing.T) {
	config := executionOperationFixture(t)
	operation, err := OpenKubernetesExecutionOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Ledger == nil || operation.Submitter == nil || operation.Observer == nil || operation.Clock == nil {
		t.Fatalf("execution operation is incomplete: %#v", operation)
	}
	if _, ok := operation.Observer.(*BoundedPollingObserver); !ok {
		t.Fatalf("execution observer is not bounded polling: %T", operation.Observer)
	}
}

func TestOpenKubernetesExecutionOperationRejectsAuthorityAliasing(t *testing.T) {
	for name, mutate := range map[string]func(*KubernetesExecutionOperationConfig){
		"same endpoint": func(config *KubernetesExecutionOperationConfig) {
			config.Infrastructure.Endpoint = config.Management.Endpoint
		},
		"same identity": func(config *KubernetesExecutionOperationConfig) {
			config.Infrastructure.AuthorityIdentity = config.Management.AuthorityIdentity
		},
		"same credential": func(config *KubernetesExecutionOperationConfig) {
			config.Infrastructure.TokenFile = config.Management.TokenFile
		},
		"different observation authority": func(config *KubernetesExecutionOperationConfig) {
			config.Observer.ExpectedManagementAuthority = "other-management"
		},
		"unbound GitOps authority": func(config *KubernetesExecutionOperationConfig) {
			config.Observer.ExpectedArgoAuthority = "other-gitops"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := executionOperationFixture(t)
			mutate(&config)
			if _, err := OpenKubernetesExecutionOperation(config); err == nil {
				t.Fatal("unsafe authority composition accepted")
			}
		})
	}
}

func TestOpenKubernetesExecutionOperationRedactsCredentialFailures(t *testing.T) {
	config := executionOperationFixture(t)
	secretPath := filepath.Join(t.TempDir(), "private-infrastructure-token")
	config.Infrastructure.TokenFile = secretPath
	_, err := OpenKubernetesExecutionOperation(config)
	if err == nil || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("credential failure was accepted or disclosed a path: %v", err)
	}
}

func TestOpenKubernetesExecutionOperationRejectsUnboundedPolling(t *testing.T) {
	config := executionOperationFixture(t)
	config.PollTimeout = 7 * time.Hour
	if _, err := OpenKubernetesExecutionOperation(config); err == nil {
		t.Fatal("unbounded polling accepted")
	}
}

func executionOperationFixture(t *testing.T) KubernetesExecutionOperationConfig {
	t.Helper()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	authority := func(name, endpoint, token string) KubernetesAuthorityConfig {
		path := filepath.Join(root, token)
		if err := os.WriteFile(path, []byte("short-lived-"+token), 0o600); err != nil {
			t.Fatal(err)
		}
		return KubernetesAuthorityConfig{Endpoint: endpoint, AuthorityIdentity: name, TokenFile: path, CAFile: caPath}
	}
	ledgerToken := filepath.Join(root, "ledger-token")
	if err := os.WriteFile(ledgerToken, []byte("short-lived-ledger-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, observer := aggregateRunnerFixture()
	management := authority("ok-mgmt", "https://10.0.0.2:443", "management-token")
	observer.Management = management
	observer.ExpectedManagementAuthority = management.AuthorityIdentity
	observer.Argo = authority("ok-shared", "https://10.0.0.3:443", "gitops-token")
	observer.ExpectedArgoAuthority = observer.Argo.AuthorityIdentity
	observer.WorkloadAuthority = WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
		return KubernetesAuthorityConfig{}, nil
	})
	observer.PlatformCapability = PlatformCapabilityResolverFunc(func(context.Context, observation.Policy, observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
		return inertPlatformCapabilitySource{}, nil
	})
	clock := func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }
	return KubernetesExecutionOperationConfig{
		Ledger:         KubernetesLedgerConfig{Endpoint: "https://10.0.0.3:443", Namespace: "openkubes-execution-system", TokenFile: ledgerToken, CAFile: caPath},
		Infrastructure: authority("ok-infra", "https://10.0.0.1:443", "infrastructure-token"),
		Management:     management, Observer: observer, PollInterval: 15 * time.Second,
		PollTimeout: 2 * time.Hour, Clock: clock,
		Wait: func(context.Context, time.Duration) error { return nil },
	}
}
