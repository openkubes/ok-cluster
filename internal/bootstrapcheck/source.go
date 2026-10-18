package bootstrapcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// SourceOwner is an independent expectation, not an owner inferred from a
// Secret name. UID is already pinned by Binding.SourceOwnerUID / TargetUID.
type SourceOwner struct {
	APIVersion string
	Name       string
}

// encoding/json matches struct fields case-insensitively. Kubernetes identity
// keys are case-sensitive: do not let an alias shadow the actual UID/owner.
func hasCaseAlias(object map[string]json.RawMessage, fields ...string) bool {
	for key := range object {
		for _, field := range fields {
			if key != field && strings.EqualFold(key, field) {
				return true
			}
		}
	}
	return false
}

// ValidateSourceMetadata checks supplied metadata-only bytes. It does not fetch
// a Secret or verify CA contents, request authentication, provenance or freshness.
// A future caller must negotiate PartialObjectMetadata without a full-object
// fallback. Metadata annotations themselves may contain sensitive information;
// neither this function nor its errors return or log their contents.
func ValidateSourceMetadata(raw []byte, expected Binding, owner SourceOwner) error {
	if !validBinding(expected) || owner.Name == "" || strings.TrimSpace(owner.Name) != owner.Name ||
		(owner.APIVersion != "cluster.x-k8s.io/v1beta1" && owner.APIVersion != "cluster.x-k8s.io/v1beta2") || len(raw) == 0 || len(raw) > 256*1024 {
		return errors.New("explicit source metadata expectations required")
	}
	var document struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Metadata   json.RawMessage `json:"metadata"`
	}
	// Reject duplicate keys at every depth, trailing values and any full-object
	// fields, rather than silently projecting Secret.data out on the client.
	if jsonstrict.Decode(raw, &document) != nil || document.APIVersion != "meta.k8s.io/v1" || document.Kind != "PartialObjectMetadata" {
		return errors.New("metadata-only source response required")
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(raw, &root)
	for key := range root {
		if key != "apiVersion" && key != "kind" && key != "metadata" {
			return errors.New("metadata-only source response required")
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(document.Metadata, &fields) != nil || hasCaseAlias(fields, "name", "namespace", "uid", "resourceVersion", "deletionTimestamp", "ownerReferences") {
		return errors.New("invalid source metadata fields")
	}
	var owners []map[string]json.RawMessage
	if json.Unmarshal(fields["ownerReferences"], &owners) != nil {
		return errors.New("invalid source owner metadata")
	}
	for _, ref := range owners {
		if hasCaseAlias(ref, "apiVersion", "kind", "name", "uid", "controller") {
			return errors.New("invalid source owner metadata fields")
		}
	}
	var metadata struct {
		Name              string          `json:"name"`
		Namespace         string          `json:"namespace"`
		UID               string          `json:"uid"`
		ResourceVersion   string          `json:"resourceVersion"`
		DeletionTimestamp json.RawMessage `json:"deletionTimestamp"`
		OwnerReferences   []struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			UID        string `json:"uid"`
			Controller bool   `json:"controller"`
		} `json:"ownerReferences"`
	}
	// Kubernetes metadata has unrelated fields (labels, annotations, managedFields,
	// etc.). They are not evidence and are never copied into a result or digest.
	if json.Unmarshal(document.Metadata, &metadata) != nil || metadata.Name != expected.SourceName || metadata.Namespace != expected.SourceNamespace || metadata.UID != expected.SourceUID || metadata.ResourceVersion != expected.SourceResourceVersion {
		return errors.New("source metadata identity drift")
	}
	if len(metadata.DeletionTimestamp) != 0 && !bytes.Equal(bytes.TrimSpace(metadata.DeletionTimestamp), []byte("null")) {
		return errors.New("deleting source is not eligible")
	}
	if len(metadata.OwnerReferences) != 1 {
		return errors.New("source requires exactly one expected controller owner")
	}
	actual := metadata.OwnerReferences[0]
	if !actual.Controller || actual.Kind != "Cluster" || actual.APIVersion != owner.APIVersion || actual.Name != owner.Name || actual.UID != expected.SourceOwnerUID {
		return errors.New("source controller owner differs from expected target")
	}
	return nil
}
