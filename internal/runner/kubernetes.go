// Package runner contains execution-environment adapters for the bounded
// Contract Executor. It does not own contract projection or lifecycle state.
package runner

import (
	"bytes"
	"context"
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
	"github.com/openkubes/ok-cluster/internal/digest"
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
	KubeconfigFile    string
	CAFile            string
	CABundleDigest    string
}

type boundedKubernetesTransport struct {
	bearerToken        string
	clientCertificate  bool
	caData             []byte
	certificateData    []byte
	keyData            []byte
	credentialIdentity string
	client             *http.Client
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
}

// KubernetesPlatformObserverConfig binds the GitOps control-plane authority,
// an immutable Platform profile and an independently verified capability
// source. The Argo adapter itself cannot execute capability code.
type KubernetesPlatformObserverConfig struct {
	Argo                  KubernetesAuthorityConfig
	ExpectedArgoAuthority string
	Profile               observation.PlatformProfile
	Capability            observation.PlatformCapabilitySource
	TargetClusterUID      string
	Clock                 func() time.Time
}

type KubernetesObservabilityTransportConfig struct {
	Workload KubernetesAuthorityConfig
	Run      ObservabilityCapabilityRun
	Fixture  ObservabilitySyntheticFixtureConfig
	Checks   ObservabilityCapabilityChecks
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
	store, _, err := openKubernetesLedger(config)
	return store, err
}

func openKubernetesLedger(config KubernetesLedgerConfig) (*ledger.Ledger, string, error) {
	if config.Endpoint == "" || config.Namespace == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, "", errors.New("Kubernetes ledger endpoint, namespace, token file, and CA file are required")
	}
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, "", err
	}
	backend, err := ledger.NewKubernetesStore(ledger.KubernetesStoreConfig{
		Endpoint: config.Endpoint, Namespace: config.Namespace, BearerToken: token, Client: client,
	})
	if err != nil {
		return nil, "", err
	}
	store, err := ledger.New(backend)
	if err != nil {
		return nil, "", err
	}
	return store, token, nil
}

// OpenKubernetesSubmissionClient materializes a redirect-denying TLS client
// for one exact authority plane. Paths and credential contents are never
// returned in errors or receipts.
func OpenKubernetesSubmissionClient(config KubernetesAuthorityConfig) (*submission.KubernetesClient, error) {
	client, _, err := openKubernetesSubmissionClient(config)
	return client, err
}

// openKubernetesSubmissionClient also returns a private credential identity so
// operation composition can prove that two write authorities do not share one
// credential. It never enters an error or receipt.
func openKubernetesSubmissionClient(config KubernetesAuthorityConfig) (*submission.KubernetesClient, string, error) {
	if err := rejectKubernetesClientCertificate(config); err != nil {
		return nil, "", err
	}
	if config.Endpoint == "" || config.AuthorityIdentity == "" || config.CAFile == "" {
		return nil, "", errors.New("Kubernetes authority endpoint, identity, credential, and CA file are required")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(config)
	if err != nil {
		return nil, "", err
	}
	submitter, err := submission.NewKubernetesClient(submission.KubernetesClientConfig{
		Endpoint: config.Endpoint, AuthorityIdentity: config.AuthorityIdentity, BearerToken: transport.bearerToken,
		ClientCertificate: transport.clientCertificate, Client: transport.client,
	})
	if err != nil {
		return nil, "", err
	}
	return submitter, transport.credentialIdentity, nil
}

func openBoundedKubernetesAuthorityTransport(config KubernetesAuthorityConfig) (boundedKubernetesTransport, error) {
	if err := rejectKubernetesClientCertificate(config); err != nil {
		return boundedKubernetesTransport{}, err
	}
	tokenMode := config.TokenFile != ""
	kubeconfigMode := config.KubeconfigFile != ""
	if config.Endpoint == "" || config.CAFile == "" || tokenMode == kubeconfigMode {
		return boundedKubernetesTransport{}, errors.New("Kubernetes authority requires exactly one transport credential")
	}
	if tokenMode {
		token, ca, client, err := openBoundedKubernetesMaterial(config.TokenFile, config.CAFile)
		if err != nil {
			return boundedKubernetesTransport{}, err
		}
		return boundedKubernetesTransport{
			bearerToken: token, caData: ca, credentialIdentity: token, client: client,
		}, nil
	}
	return openBoundedKubernetesKubeconfigTransport(config.KubeconfigFile, config.Endpoint, config.CAFile)
}

// No bounded certificate issuer/subject/group/lifetime policy is approved.
// CA-signed CAPI admin certificates must never become executor credentials.
var ErrClientCertificateDisabled = errors.New("client-certificate execution is disabled pending a bounded credential bootstrap policy")

func rejectKubernetesClientCertificate(config KubernetesAuthorityConfig) error {
	if config.KubeconfigFile != "" {
		return ErrClientCertificateDisabled
	}
	return nil
}

func openBoundedKubernetesKubeconfigTransport(kubeconfigFile, expectedEndpoint, caFile string) (boundedKubernetesTransport, error) {
	// Reject before reading credential files or constructing an HTTP client.
	return boundedKubernetesTransport{}, ErrClientCertificateDisabled
}

func parseBoundedKubernetesKubeconfig(raw []byte, expectedEndpoint string, boundCA []byte) (boundedKubernetesTransport, error) {
	return boundedKubernetesTransport{}, ErrClientCertificateDisabled
}

// OpenKubernetesCAPILifecycleObserver materializes a bounded management-plane
// observer for one exact CAPI Cluster. The independently supplied expected
// authority must match the credential identity bound by the projection plan.
func OpenKubernetesCAPILifecycleObserver(config KubernetesAuthorityConfig, expectedAuthority, namespace, name string) (*observation.CAPILifecycleObserver, error) {
	observer, _, err := openKubernetesCAPILifecycleObserver(config, expectedAuthority, namespace, name)
	return observer, err
}

// openKubernetesCAPILifecycleObserver also returns the bounded token so a
// stage-level composition can prove that observation and ledger writes use
// distinct credentials. The token never leaves this package.
func openKubernetesCAPILifecycleObserver(config KubernetesAuthorityConfig, expectedAuthority, namespace, name string) (*observation.CAPILifecycleObserver, string, error) {
	if err := rejectKubernetesClientCertificate(config); err != nil {
		return nil, "", err
	}
	if config.Endpoint == "" || config.AuthorityIdentity == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, "", errors.New("Kubernetes CAPI observer endpoint, identity, token file, and CA file are required")
	}
	if expectedAuthority == "" || config.AuthorityIdentity != expectedAuthority {
		return nil, "", errors.New("Kubernetes CAPI observer authority differs from the verified management plane")
	}
	token, client, err := openBoundedKubernetesHTTP(config.TokenFile, config.CAFile)
	if err != nil {
		return nil, "", err
	}
	observer, err := observation.NewCAPILifecycleObserver(observation.CAPILifecycleObserverConfig{
		Endpoint: config.Endpoint, BearerToken: token, Namespace: namespace, Name: name, Client: client,
	})
	if err != nil {
		return nil, "", err
	}
	return observer, token, nil
}

// OpenKubernetesNetworkSourceCollector materializes two isolated TLS clients:
// one for HCP/HRP reads on the management authority and one for runtime reads
// on the immutable workload Cluster UID. It performs no API request itself.
func OpenKubernetesNetworkSourceCollector(config KubernetesNetworkObserverConfig) (*observation.NetworkSourceCollector, error) {
	collector, _, _, err := openKubernetesNetworkSourceCollector(config)
	return collector, err
}

// openKubernetesNetworkSourceCollector returns credential identities only to
// private stage composition so it can prove that capabilities remain separate.
func openKubernetesNetworkSourceCollector(config KubernetesNetworkObserverConfig) (*observation.NetworkSourceCollector, string, string, error) {
	if err := rejectKubernetesClientCertificate(config.Management); err != nil {
		return nil, "", "", err
	}
	if err := rejectKubernetesClientCertificate(config.Workload); err != nil {
		return nil, "", "", err
	}
	if config.ExpectedManagementAuthority == "" || config.Management.AuthorityIdentity != config.ExpectedManagementAuthority {
		return nil, "", "", errors.New("network observer management authority differs from the verified management plane")
	}
	if config.TargetClusterUID == "" || config.Workload.AuthorityIdentity != config.TargetClusterUID {
		return nil, "", "", errors.New("network observer workload authority differs from the runtime-bound target Cluster")
	}
	if config.Management.Endpoint == config.Workload.Endpoint {
		return nil, "", "", errors.New("network observer management and workload endpoints must be distinct")
	}
	managementToken, _, managementClient, err := openBoundedKubernetesMaterial(config.Management.TokenFile, config.Management.CAFile)
	if err != nil {
		return nil, "", "", errors.New("open bounded management network credential")
	}
	workloadTransport, err := openBoundedKubernetesAuthorityTransport(config.Workload)
	if err != nil {
		return nil, "", "", errors.New("open bounded workload network credential")
	}
	if !platformInputDigestPattern.MatchString(config.Workload.CABundleDigest) || digest.SHA256(workloadTransport.caData) != config.Workload.CABundleDigest {
		return nil, "", "", errors.New("workload network CA differs from the runtime-bound authority")
	}
	if sameSecret(managementToken, workloadTransport.credentialIdentity) {
		return nil, "", "", errors.New("network observer management and workload credentials must be distinct")
	}
	management, err := observation.NewKubernetesManagementNetworkReader(observation.KubernetesNetworkReaderConfig{
		Endpoint: config.Management.Endpoint, BearerToken: managementToken, Client: managementClient,
	}, config.Namespace, config.Name, config.HCPName)
	if err != nil {
		return nil, "", "", err
	}
	workload, err := observation.NewKubernetesWorkloadNetworkReader(observation.KubernetesNetworkReaderConfig{
		Endpoint: config.Workload.Endpoint, BearerToken: workloadTransport.bearerToken,
		ClientCertificate: workloadTransport.clientCertificate, Client: workloadTransport.client,
	})
	if err != nil {
		return nil, "", "", err
	}
	podExecutor, err := newKubernetesCiliumWebSocketExecutorWithTransport(config.Workload.Endpoint, workloadTransport)
	if err != nil {
		return nil, "", "", err
	}
	probe, err := observation.NewKubernetesFixedCiliumProbe(podExecutor)
	if err != nil {
		return nil, "", "", err
	}
	collector, err := observation.NewNetworkSourceCollector(management, workload, probe, observation.NetworkCollectorConfig{
		Namespace: config.Namespace, Name: config.Name, HCPName: config.HCPName,
		TargetClusterUID: config.TargetClusterUID, Clock: config.Clock,
	})
	if err != nil {
		return nil, "", "", err
	}
	return collector, managementToken, workloadTransport.credentialIdentity, nil
}

// OpenKubernetesPlatformSourceCollector materializes one TLS client restricted
// to exact Argo Application GETs on the configured GitOps control plane. It
// performs no API request itself and exposes no sync or mutation operation.
func OpenKubernetesPlatformSourceCollector(config KubernetesPlatformObserverConfig) (*observation.PlatformSourceCollector, error) {
	collector, _, err := openKubernetesPlatformSourceCollector(config)
	return collector, err
}

func openKubernetesPlatformSourceCollector(config KubernetesPlatformObserverConfig) (*observation.PlatformSourceCollector, string, error) {
	if err := rejectKubernetesClientCertificate(config.Argo); err != nil {
		return nil, "", err
	}
	if config.ExpectedArgoAuthority == "" || config.Argo.AuthorityIdentity != config.ExpectedArgoAuthority {
		return nil, "", errors.New("platform observer authority differs from the verified GitOps control plane")
	}
	if !platformInputDigestPattern.MatchString(config.Argo.CABundleDigest) {
		return nil, "", errors.New("platform observer CA identity is required")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Argo.TokenFile, config.Argo.CAFile)
	if err != nil {
		return nil, "", errors.New("open bounded GitOps observation credential")
	}
	if digest.SHA256(ca) != config.Argo.CABundleDigest {
		return nil, "", errors.New("platform observer CA differs from bound identity")
	}
	reader, err := observation.NewKubernetesPlatformReader(observation.KubernetesPlatformReaderConfig{
		Endpoint: config.Argo.Endpoint, BearerToken: token, Client: client,
	}, config.Profile)
	if err != nil {
		return nil, "", err
	}
	collector, err := observation.NewPlatformSourceCollector(reader, config.Capability, observation.PlatformCollectorConfig{
		Profile: config.Profile, TargetClusterUID: config.TargetClusterUID, Clock: config.Clock,
	})
	if err != nil {
		return nil, "", err
	}
	return collector, token, nil
}

// OpenKubernetesObservabilityTransport binds the fixed capability lifecycle to
// one runtime workload authority. It reads credential files but performs no
// Kubernetes request until the capability probe opens its execution gate.
func OpenKubernetesObservabilityTransport(config KubernetesObservabilityTransportConfig) (*KubernetesObservabilityTransport, error) {
	if err := rejectKubernetesClientCertificate(config.Workload); err != nil {
		return nil, err
	}
	if config.Workload.AuthorityIdentity != config.Run.TargetClusterUID || !platformInputDigestPattern.MatchString(config.Workload.CABundleDigest) {
		return nil, errors.New("observability transport workload authority differs from runtime target")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(config.Workload)
	if err != nil {
		return nil, errors.New("open bounded observability transport credential")
	}
	if digest.SHA256(transport.caData) != config.Workload.CABundleDigest {
		return nil, errors.New("observability transport CA differs from runtime-bound authority")
	}
	fixtureClient, err := NewKubernetesCapabilityFixtureClient(KubernetesCapabilityFixtureClientConfig{
		Endpoint: config.Workload.Endpoint, BearerToken: transport.bearerToken, ClientCertificate: transport.clientCertificate,
		AuthorityIdentity: config.Workload.AuthorityIdentity, Client: transport.client,
	}, config.Run, config.Fixture)
	if err != nil {
		return nil, errors.New("open bounded observability fixture client")
	}
	return newKubernetesObservabilityTransport(fixtureClient, config.Run, config.Checks)
}

func openBoundedKubernetesHTTP(tokenFile, caFile string) (string, *http.Client, error) {
	token, _, client, err := openBoundedKubernetesMaterial(tokenFile, caFile)
	return token, client, err
}

func openBoundedStageAuthorizationHTTP(tokenFile, caFile string) (string, *http.Client, error) {
	token, _, client, err := openBoundedBearerMaterial(tokenFile, caFile, true)
	return token, client, err
}

func openBoundedKubernetesMaterial(tokenFile, caFile string) (string, []byte, *http.Client, error) {
	return openBoundedBearerMaterial(tokenFile, caFile, false)
}

func openBoundedBearerMaterial(tokenFile, caFile string, allowSingleTrailingLF bool) (string, []byte, *http.Client, error) {
	token, caRaw, roots, err := readBoundedBearerMaterial(tokenFile, caFile, allowSingleTrailingLF)
	if err != nil {
		return "", nil, nil, err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		},
	}
	return token, caRaw, client, nil
}

// Parsing is shared with offline preparation; this half opens no HTTP client.
func readBoundedBearerMaterial(tokenFile, caFile string, allowSingleTrailingLF bool) (string, []byte, *x509.CertPool, error) {
	tokenRaw, err := readBoundedRegular(tokenFile, maximumTokenBytes)
	if err != nil {
		return "", nil, nil, errors.New("read projected Kubernetes token")
	}
	if allowSingleTrailingLF {
		tokenRaw = bytes.TrimSuffix(tokenRaw, []byte("\n"))
	}
	token := string(tokenRaw)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return "", nil, nil, errors.New("projected Kubernetes token is invalid")
	}
	caRaw, err := readBoundedRegular(caFile, maximumCABytes)
	if err != nil {
		return "", nil, nil, errors.New("read projected Kubernetes API CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return "", nil, nil, errors.New("projected Kubernetes API CA contains no certificate")
	}
	return token, append([]byte(nil), caRaw...), roots, nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Size() <= 0 || pathInfo.Size() > maximum {
		return nil, errors.New("projected file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
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
