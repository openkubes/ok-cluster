package targetadmission

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const (
	InstallNamespace          = "ok147-target-admission-system"
	InstallServiceAccount     = "ok147-target-admission"
	InstallClusterRole        = "ok147-target-admission-identity-reader"
	InstallClusterRoleBinding = "ok147-target-admission-identity-reader"
	InstallService            = "ok147-target-admission"
	InstallPolicySecret       = "ok147-target-admission-policy"
	InstallPublicKeyConfigMap = "ok147-target-admission-pin"
	InstallTLSSecret          = "ok147-target-admission-tls"
	InstallAPICACConfigMap    = "kube-root-ca.crt"
	InstallManifestFormat     = "ok147-target-admission-install-set/v1"
	InstallServiceDNS         = InstallService + "." + InstallNamespace + ".svc"
)

var immutableContainerImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$`)

// InstallObject is a reviewable manifest object. Its digest identifies the
// exact YAML bytes; it is a plan only and does not grant submission authority.
type InstallObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	Raw        []byte `json:"raw"`
}

type InstallSet struct {
	Format  string          `json:"format"`
	Objects []InstallObject `json:"objects"`
}

// RenderInstallSet emits the fixed, least-privilege workload scaffold for the
// local admission service. It deliberately excludes policy/TLS Secret data,
// the validating webhook configuration, and all apply/patch logic.
func RenderInstallSet(image string) (InstallSet, error) {
	if !immutableContainerImagePattern.MatchString(image) {
		return InstallSet{}, errors.New("target admission image must be a fully qualified immutable sha256 reference")
	}
	labels := map[string]any{"app.kubernetes.io/name": InstallService, "app.kubernetes.io/part-of": "ok147-target-admission"}
	manifest := []map[string]any{
		{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": InstallNamespace, "labels": map[string]any{"app.kubernetes.io/part-of": "ok147-target-admission", "pod-security.kubernetes.io/enforce": "restricted"}},
		},
		{
			"apiVersion": "v1", "kind": "ServiceAccount",
			"metadata":                     map[string]any{"name": InstallServiceAccount, "namespace": InstallNamespace, "labels": labels},
			"automountServiceAccountToken": false,
		},
		{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
			"metadata": map[string]any{"name": InstallClusterRole, "labels": labels},
			// Kubernetes exposes /version as a non-resource endpoint. Keep it
			// separate from the resource rule and grant only the read required by
			// startup target-version validation.
			"rules": []any{
				map[string]any{"apiGroups": []string{""}, "resources": []string{"namespaces"}, "resourceNames": []string{"kube-system"}, "verbs": []string{"get"}},
				map[string]any{"nonResourceURLs": []string{"/version"}, "verbs": []string{"get"}},
			},
		},
		{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
			"metadata": map[string]any{"name": InstallClusterRoleBinding, "labels": labels},
			"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": InstallClusterRole},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": InstallServiceAccount, "namespace": InstallNamespace}},
		},
		{
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": InstallService, "namespace": InstallNamespace, "labels": labels},
			"spec": map[string]any{
				"replicas": 1,
				"strategy": map[string]any{"type": "Recreate"},
				"selector": map[string]any{"matchLabels": labels},
				"template": map[string]any{
					"metadata": map[string]any{"labels": labels},
					"spec": map[string]any{
						"serviceAccountName":            InstallServiceAccount,
						"automountServiceAccountToken":  false,
						"terminationGracePeriodSeconds": 10,
						"securityContext":               map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
						"containers": []any{map[string]any{
							"name": "admission", "image": image, "imagePullPolicy": "IfNotPresent",
							"args": []string{
								"--bundle-file=/var/run/ok/policy/bundle.json",
								"--policy-public-key-file=/var/run/ok/pin/policy-public-key.bin",
								"--target-api-endpoint=https://kubernetes.default.svc",
								"--target-api-ca-file=/var/run/secrets/ok-target/ca.crt",
								"--target-read-token-file=/var/run/secrets/ok-target/token",
								"--tls-certificate-file=/var/run/ok/tls/tls.crt",
								"--tls-private-key-file=/var/run/ok/tls/tls.key",
								"--webhook-ca-file=/var/run/ok/tls/ca.crt",
								"--service-dns=" + InstallServiceDNS,
								"--listen=:8443",
							},
							"ports":           []any{map[string]any{"name": "https", "containerPort": 8443, "protocol": "TCP"}},
							"resources":       map[string]any{"requests": map[string]any{"cpu": "10m", "memory": "32Mi"}, "limits": map[string]any{"cpu": "500m", "memory": "128Mi"}},
							"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
							"readinessProbe":  map[string]any{"httpGet": map[string]any{"scheme": "HTTPS", "path": HealthPath, "port": "https"}, "periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 3},
							"livenessProbe":   map[string]any{"httpGet": map[string]any{"scheme": "HTTPS", "path": HealthPath, "port": "https"}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 3},
							"volumeMounts": []any{
								map[string]any{"name": "policy", "mountPath": "/var/run/ok/policy", "readOnly": true},
								map[string]any{"name": "policy-pin", "mountPath": "/var/run/ok/pin", "readOnly": true},
								map[string]any{"name": "serving-tls", "mountPath": "/var/run/ok/tls", "readOnly": true},
								map[string]any{"name": "target-identity", "mountPath": "/var/run/secrets/ok-target", "readOnly": true},
							},
						}},
						"volumes": []any{
							map[string]any{"name": "policy", "secret": map[string]any{"secretName": InstallPolicySecret, "defaultMode": 256, "items": []any{map[string]any{"key": "bundle.json", "path": "bundle.json"}}}},
							map[string]any{"name": "policy-pin", "configMap": map[string]any{"name": InstallPublicKeyConfigMap, "defaultMode": 292, "items": []any{map[string]any{"key": "policy-public-key.bin", "path": "policy-public-key.bin"}}}},
							map[string]any{"name": "serving-tls", "secret": map[string]any{"secretName": InstallTLSSecret, "defaultMode": 256, "items": []any{map[string]any{"key": "tls.crt", "path": "tls.crt"}, map[string]any{"key": "tls.key", "path": "tls.key"}, map[string]any{"key": "ca.crt", "path": "ca.crt"}}}},
							map[string]any{"name": "target-identity", "projected": map[string]any{"defaultMode": 256, "sources": []any{
								map[string]any{"serviceAccountToken": map[string]any{"path": "token", "expirationSeconds": 600}},
								map[string]any{"configMap": map[string]any{"name": InstallAPICACConfigMap, "items": []any{map[string]any{"key": "ca.crt", "path": "ca.crt"}}}},
							}}},
						},
					},
				},
			},
		},
		{
			"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": InstallService, "namespace": InstallNamespace, "labels": labels},
			"spec":     map[string]any{"type": "ClusterIP", "selector": labels, "ports": []any{map[string]any{"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"}}},
		},
	}
	set := InstallSet{Format: InstallManifestFormat, Objects: make([]InstallObject, 0, len(manifest))}
	for index, value := range manifest {
		raw, err := yaml.Marshal(value)
		if err != nil {
			return InstallSet{}, fmt.Errorf("encode target admission install object %d", index+1)
		}
		var identity struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
			Metadata   struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		}
		if err := yaml.Unmarshal(raw, &identity); err != nil || identity.APIVersion == "" || identity.Kind == "" || identity.Metadata.Name == "" {
			return InstallSet{}, fmt.Errorf("validate target admission install object %d", index+1)
		}
		set.Objects = append(set.Objects, InstallObject{APIVersion: identity.APIVersion, Kind: identity.Kind, Name: identity.Metadata.Name, Namespace: identity.Metadata.Namespace, Digest: digest.SHA256(raw), Raw: raw})
	}
	return set, nil
}
