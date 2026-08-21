package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const maximumLifecycleAuthorityResponseBytes = 4 * 1024 * 1024

// KubernetesLifecycleWorkloadAuthorityMaterializerConfig binds the exact
// management authority and the three private create-only destinations used to
// hand the lifecycle-derived workload authority to Stage 5 and later stages.
type KubernetesLifecycleWorkloadAuthorityMaterializerConfig struct {
	Management                  KubernetesAuthorityConfig
	ExpectedManagementAuthority string
	BindingPath                 string
	KubeconfigFile              string
	CAFile                      string
}

// KubernetesLifecycleWorkloadAuthorityMaterializer reads exactly one CAPI
// Cluster and its CAPI-owned kubeconfig Secret after the durable Stage-4
// prefix exists. It performs no Kubernetes mutation and creates the semantic
// binding last so partial local material cannot be mistaken for a complete
// handoff.
type KubernetesLifecycleWorkloadAuthorityMaterializer struct {
	config KubernetesLifecycleWorkloadAuthorityMaterializerConfig

	mu   sync.Mutex
	used bool
}

func OpenKubernetesLifecycleWorkloadAuthorityMaterializer(config KubernetesLifecycleWorkloadAuthorityMaterializerConfig) (*KubernetesLifecycleWorkloadAuthorityMaterializer, error) {
	if config.ExpectedManagementAuthority == "" || config.Management.AuthorityIdentity != config.ExpectedManagementAuthority ||
		config.Management.TokenFile == "" || config.Management.KubeconfigFile != "" {
		return nil, errors.New("lifecycle workload authority management binding is invalid")
	}
	if config.BindingPath == config.KubeconfigFile || config.BindingPath == config.CAFile || config.KubeconfigFile == config.CAFile {
		return nil, errors.New("lifecycle workload authority destinations are not distinct")
	}
	for _, path := range []string{config.KubeconfigFile, config.CAFile, config.BindingPath} {
		if validateRuntimeBindingOutputPath(path) != nil {
			return nil, errors.New("lifecycle workload authority destination is invalid")
		}
	}
	if _, _, err := openKubernetesSubmissionClient(config.Management); err != nil {
		return nil, fmt.Errorf("open bounded lifecycle workload management authority: %w", err)
	}
	return &KubernetesLifecycleWorkloadAuthorityMaterializer{config: config}, nil
}

func (materializer *KubernetesLifecycleWorkloadAuthorityMaterializer) ResolvePreRuntimeWorkloadAuthority(ctx context.Context, resume StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
	if materializer == nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("lifecycle workload authority materializer is required")
	}
	materializer.mu.Lock()
	if materializer.used {
		materializer.mu.Unlock()
		return WorkloadAuthorityFileResolverConfig{}, errors.New("lifecycle workload authority materializer is single-use")
	}
	materializer.used = true
	materializer.mu.Unlock()

	plan, cursor, prefix, err := loadStageResumeWithPrefix(resume)
	if err != nil || len(prefix) != 4 {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("verify exact Stage-5 workload authority cursor")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "network-observation" || decision.Authority != "workload" {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("workload authority materialization requires the Stage-5 cursor")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || lifecycle.State != "SUCCEEDED" ||
		lifecycle.PlanDigest != plan.PlanDigest || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("lifecycle receipt lacks target authority identity")
	}

	transport, err := openBoundedKubernetesAuthorityTransport(materializer.config.Management)
	if err != nil || transport.clientCertificate {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("open lifecycle workload management transport")
	}
	namespace, name := plan.ContractIdentity.Namespace, plan.ContractIdentity.Name
	clusterPath := "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + namespace + "/clusters/" + name
	clusterRaw, err := exactLifecycleAuthorityGET(ctx, materializer.config.Management.Endpoint, clusterPath, transport)
	if err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("read lifecycle-derived CAPI Cluster")
	}
	cluster, err := decodeLifecycleAuthorityCluster(clusterRaw, namespace, name)
	if err != nil || digest.SHA256([]byte(cluster.Metadata.UID)) != lifecycle.TargetClusterUIDDigest {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("CAPI Cluster differs from durable lifecycle identity")
	}
	endpoint := "https://" + net.JoinHostPort(cluster.Spec.ControlPlaneEndpoint.Host, strconv.Itoa(cluster.Spec.ControlPlaneEndpoint.Port))
	if !validFullRunKubernetesEndpoint(endpoint) {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("CAPI Cluster workload endpoint is invalid")
	}

	secretPath := "/api/v1/namespaces/" + namespace + "/secrets/" + name + "-kubeconfig"
	secretRaw, err := exactLifecycleAuthorityGET(ctx, materializer.config.Management.Endpoint, secretPath, transport)
	if err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("read lifecycle-derived workload kubeconfig Secret")
	}
	kubeconfigRaw, err := decodeLifecycleAuthorityKubeconfigSecret(secretRaw, namespace, name+"-kubeconfig")
	if err != nil {
		return WorkloadAuthorityFileResolverConfig{}, err
	}
	parsed, err := parseBoundedKubernetesKubeconfig(kubeconfigRaw, endpoint, nil)
	if err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("verify lifecycle-derived workload kubeconfig")
	}

	binding := WorkloadAuthorityBinding{
		Format: WorkloadAuthorityBindingFormat, IntentRevision: plan.IntentRevision,
		TargetClusterUID: cluster.Metadata.UID, TargetIdentityScheme: "capi-cluster-uid/v1",
		Endpoint: endpoint, CABundleDigest: digest.SHA256(parsed.caData),
	}
	bindingRaw, err := canonicalWorkloadAuthorityBinding(binding)
	if err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("canonicalize lifecycle workload authority binding")
	}
	bindingDigest := digest.SHA256(bindingRaw)

	// Secret-derived material comes first; the semantic binding is the final
	// completion marker. Any error preserves partial local state for diagnosis.
	for _, output := range []struct {
		path string
		raw  []byte
	}{
		{materializer.config.KubeconfigFile, kubeconfigRaw},
		{materializer.config.CAFile, parsed.caData},
		{materializer.config.BindingPath, bindingRaw},
	} {
		if err := writeExclusivePrivateMaterial(output.path, output.raw); err != nil {
			return WorkloadAuthorityFileResolverConfig{}, err
		}
	}
	result := WorkloadAuthorityFileResolverConfig{
		Path: materializer.config.BindingPath, ExpectedBindingDigest: bindingDigest,
		KubeconfigFile: materializer.config.KubeconfigFile, CAFile: materializer.config.CAFile,
	}
	if _, authority, err := loadWorkloadAuthorityFiles(result); err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("reload lifecycle workload authority binding")
	} else if _, err := openBoundedKubernetesAuthorityTransport(authority); err != nil {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("reopen lifecycle workload authority transport")
	}
	return result, nil
}

type lifecycleAuthorityCluster struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		ControlPlaneEndpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"controlPlaneEndpoint"`
	} `json:"spec"`
}

func decodeLifecycleAuthorityCluster(raw []byte, namespace, name string) (lifecycleAuthorityCluster, error) {
	var cluster lifecycleAuthorityCluster
	if err := decodeOneJSONDocument(raw, &cluster); err != nil || cluster.APIVersion != "cluster.x-k8s.io/v1beta2" || cluster.Kind != "Cluster" ||
		cluster.Metadata.Namespace != namespace || cluster.Metadata.Name != name || !runtimeInputUIDPattern.MatchString(cluster.Metadata.UID) ||
		cluster.Metadata.ResourceVersion == "" || cluster.Spec.ControlPlaneEndpoint.Host == "" || cluster.Spec.ControlPlaneEndpoint.Port < 1 || cluster.Spec.ControlPlaneEndpoint.Port > 65535 {
		return lifecycleAuthorityCluster{}, errors.New("lifecycle-derived CAPI Cluster is invalid")
	}
	return cluster, nil
}

func decodeLifecycleAuthorityKubeconfigSecret(raw []byte, namespace, name string) ([]byte, error) {
	var secret struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Type       string `json:"type"`
		Metadata   struct {
			Name            string `json:"name"`
			Namespace       string `json:"namespace"`
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := decodeOneJSONDocument(raw, &secret); err != nil || secret.APIVersion != "v1" || secret.Kind != "Secret" ||
		secret.Type != "cluster.x-k8s.io/secret" || secret.Metadata.Namespace != namespace || secret.Metadata.Name != name ||
		!runtimeInputUIDPattern.MatchString(secret.Metadata.UID) || secret.Metadata.ResourceVersion == "" || len(secret.Data) != 1 {
		return nil, errors.New("lifecycle-derived workload kubeconfig Secret is invalid")
	}
	encoded, ok := secret.Data["value"]
	if !ok || encoded == "" {
		return nil, errors.New("lifecycle-derived workload kubeconfig Secret lacks exact data.value")
	}
	rawKubeconfig, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(rawKubeconfig) == 0 || len(rawKubeconfig) > maximumCABytes {
		return nil, errors.New("lifecycle-derived workload kubeconfig value is invalid")
	}
	return rawKubeconfig, nil
}

func decodeOneJSONDocument(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON response has trailing content")
	}
	return nil
}

func exactLifecycleAuthorityGET(ctx context.Context, endpoint, path string, transport boundedKubernetesTransport) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return nil, errors.New("construct exact lifecycle authority request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+transport.bearerToken)
	response, err := transport.client.Do(request)
	if err != nil {
		return nil, errors.New("exact lifecycle authority request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumLifecycleAuthorityResponseBytes+1))
	if err != nil || len(raw) > maximumLifecycleAuthorityResponseBytes {
		return nil, errors.New("exact lifecycle authority response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exact lifecycle authority request returned HTTP %d", response.StatusCode)
	}
	return raw, nil
}

func writeExclusivePrivateMaterial(path string, raw []byte) error {
	if len(raw) == 0 || validateRuntimeBindingOutputPath(path) != nil {
		return errors.New("private workload authority output is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create exclusive private workload authority output")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return errors.New("write private workload authority output")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync private workload authority output")
	}
	if err := file.Close(); err != nil {
		return errors.New("close private workload authority output")
	}
	stored, err := readBoundedRegular(path, int64(len(raw)))
	if err != nil || !bytes.Equal(stored, raw) {
		return errors.New("private workload authority output differs after write")
	}
	return nil
}

var _ PreRuntimeWorkloadAuthorityResolver = (*KubernetesLifecycleWorkloadAuthorityMaterializer)(nil)
