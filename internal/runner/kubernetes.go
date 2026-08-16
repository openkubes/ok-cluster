// Package runner contains execution-environment adapters for the bounded
// Contract Executor. It does not own contract projection or lifecycle state.
package runner

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	maximumTokenBytes = 64 * 1024
	maximumCABytes    = 1024 * 1024
)

// KubernetesLedgerConfig binds the only credential and API inputs used by the
// Job preflight. Source paths never appear in receipts or returned errors.
type KubernetesLedgerConfig struct {
	Endpoint  string
	Namespace string
	TokenFile string
	CAFile    string
}

// KubernetesAuthorityConfig binds one short-lived credential to exactly one
// authority plane. A caller must use separate instances for ok-infra and
// ok-mgmt; no reusable multi-cluster administrator client is constructed.
type KubernetesAuthorityConfig struct {
	Endpoint          string
	AuthorityIdentity string
	TokenFile         string
	CAFile            string
}

// KubernetesNetworkObserverConfig binds distinct management and workload
// credentials to one runtime Cluster UID. Pod exec remains a separately
// supplied, fixed-command transport rather than an arbitrary shell surface.
type KubernetesNetworkObserverConfig struct {
	Management                  KubernetesAuthorityConfig
	Workload                    KubernetesAuthorityConfig
	ExpectedManagementAuthority string
	TargetClusterUID            string
	Namespace                   string
	Name                        string
	HCPName                     string
	Clock                       func() time.Time
	PodExecutor                 observation.CiliumProbePodExecutor
}

// InspectKubernetesLedger performs a read-only restart decision. It does not
// claim the grant and therefore cannot authorize a later mutation by itself.
func InspectKubernetesLedger(ctx context.Context, grant authorization.VerifiedGrant, config KubernetesLedgerConfig) (ledger.Inspection, error) {
	store, err := OpenKubernetesLedger(config)
	if err != nil {
		return ledger.Inspection{}, err
	}
	return store.Inspect(ctx, grant)
}

// OpenKubernetesLedger materializes a TLS-only, redirect-denying client from
// bounded projected files. The caller is responsible for using a short-lived
// token with the dedicated ledger ServiceAccount.
func OpenKubernetesLedger(config KubernetesLedgerConfig) (*ledger.Ledger, error) {
	if config.Endpoint == "" || config.Namespace == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, errors.New("Kubernetes ledger endpoint, namespace, token file, and CA file are required")
	}
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, err
	}
	backend, err := ledger.NewKubernetesStore(ledger.KubernetesStoreConfig{
		Endpoint: config.Endpoint, Namespace: config.Namespace, BearerToken: token, Client: client,
	})
	if err != nil {
		return nil, err
	}
	return ledger.New(backend)
}

// OpenKubernetesSubmissionClient materializes a redirect-denying TLS client
// for one exact authority plane. Paths and credential contents are never
// returned in errors or receipts.
func OpenKubernetesSubmissionClient(config KubernetesAuthorityConfig) (*submission.KubernetesClient, error) {
	if config.Endpoint == "" || config.AuthorityIdentity == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, errors.New("Kubernetes authority endpoint, identity, token file, and CA file are required")
	}
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, err
	}
	return submission.NewKubernetesClient(submission.KubernetesClientConfig{
		Endpoint: config.Endpoint, AuthorityIdentity: config.AuthorityIdentity, BearerToken: token, Client: client,
	})
}

// OpenKubernetesCAPILifecycleObserver materializes a bounded management-plane
// observer for one exact CAPI Cluster. The independently supplied expected
// authority must match the credential identity bound by the projection plan.
func OpenKubernetesCAPILifecycleObserver(config KubernetesAuthorityConfig, expectedAuthority, namespace, name string) (*observation.CAPILifecycleObserver, error) {
	if config.Endpoint == "" || config.AuthorityIdentity == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, errors.New("Kubernetes CAPI observer endpoint, identity, token file, and CA file are required")
	}
	if expectedAuthority == "" || config.AuthorityIdentity != expectedAuthority {
		return nil, errors.New("Kubernetes CAPI observer authority differs from the verified management plane")
	}
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, err
	}
	return observation.NewCAPILifecycleObserver(observation.CAPILifecycleObserverConfig{
		Endpoint: config.Endpoint, BearerToken: token, Namespace: namespace, Name: name, Client: client,
	})
}

// OpenKubernetesNetworkSourceCollector materializes two isolated TLS clients:
// one for HCP/HRP reads on the management authority and one for runtime reads
// on the immutable workload Cluster UID. It performs no API request itself.
func OpenKubernetesNetworkSourceCollector(config KubernetesNetworkObserverConfig) (*observation.NetworkSourceCollector, error) {
	if config.ExpectedManagementAuthority == "" || config.Management.AuthorityIdentity != config.ExpectedManagementAuthority {
		return nil, errors.New("network observer management authority differs from the verified management plane")
	}
	if config.TargetClusterUID == "" || config.Workload.AuthorityIdentity != config.TargetClusterUID {
		return nil, errors.New("network observer workload authority differs from the runtime-bound target Cluster")
	}
	if config.Management.Endpoint == config.Workload.Endpoint {
		return nil, errors.New("network observer management and workload endpoints must be distinct")
	}
	managementToken, managementClient, err := openBoundedKubernetesHTTP(config.Management.TokenFile, config.Management.CAFile)
	if err != nil {
		return nil, errors.New("open bounded management network credential")
	}
	workloadToken, workloadClient, err := openBoundedKubernetesHTTP(config.Workload.TokenFile, config.Workload.CAFile)
	if err != nil {
		return nil, errors.New("open bounded workload network credential")
	}
	if len(managementToken) == len(workloadToken) && subtle.ConstantTimeCompare([]byte(managementToken), []byte(workloadToken)) == 1 {
		return nil, errors.New("network observer management and workload credentials must be distinct")
	}
	management, err := observation.NewKubernetesManagementNetworkReader(observation.KubernetesNetworkReaderConfig{
		Endpoint: config.Management.Endpoint, BearerToken: managementToken, Client: managementClient,
	}, config.Namespace, config.Name, config.HCPName)
	if err != nil {
		return nil, err
	}
	workload, err := observation.NewKubernetesWorkloadNetworkReader(observation.KubernetesNetworkReaderConfig{
		Endpoint: config.Workload.Endpoint, BearerToken: workloadToken, Client: workloadClient,
	})
	if err != nil {
		return nil, err
	}
	probe, err := observation.NewKubernetesFixedCiliumProbe(config.PodExecutor)
	if err != nil {
		return nil, err
	}
	return observation.NewNetworkSourceCollector(management, workload, probe, observation.NetworkCollectorConfig{
		Namespace: config.Namespace, Name: config.Name, HCPName: config.HCPName,
		TargetClusterUID: config.TargetClusterUID, Clock: config.Clock,
	})
}

func openBoundedKubernetesHTTP(tokenFile, caFile string) (string, *http.Client, error) {
	tokenRaw, err := readBoundedRegular(tokenFile, maximumTokenBytes)
	if err != nil {
		return "", nil, errors.New("read projected Kubernetes token")
	}
	token := string(tokenRaw)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return "", nil, errors.New("projected Kubernetes token is invalid")
	}
	caRaw, err := readBoundedRegular(caFile, maximumCABytes)
	if err != nil {
		return "", nil, errors.New("read projected Kubernetes API CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return "", nil, errors.New("projected Kubernetes API CA contains no certificate")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:              nil,
			DisableCompression: true,
			ForceAttemptHTTP2:  true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
			},
		},
	}
	return token, client, nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("projected file metadata is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("projected file exceeds size limit")
	}
	return raw, nil
}
