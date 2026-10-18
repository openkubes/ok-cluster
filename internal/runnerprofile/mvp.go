// Package runnerprofile renders versioned, credential-free desired-state
// recipes. It owns no API client, lifecycle executor, credential or grant.
package runnerprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const TalosMVP = "talos-kubevirt-mvp"

type recipeDocument struct {
	Format             string `json:"format"`
	Profile            string `json:"profile"`
	GitOpsAuthority    string `json:"gitOpsAuthority"`
	EnablementRevision string `json:"enablementRevision"`
	PlatformRevision   string `json:"platformRevision"`
	Enablement         struct {
		Pins map[string]string `json:"pins"`
		Spec map[string]any    `json:"spec"`
	} `json:"enablement"`
	Network      observation.NetworkProfile `json:"network"`
	TargetAccess []map[string]any           `json:"targetAccess"`
}

type Recipe struct {
	raw             []byte
	digest          string
	gitOpsAuthority string
}

// Load matches the reviewed Contract revisions; a profile never selects its
// own E/P in place of the caller's already canonicalized Contract.
func Load(raw []byte, profile, enablementRevision, platformRevision string) (Recipe, error) {
	if len(raw) == 0 || len(raw) > 512*1024 || profile != TalosMVP {
		return Recipe{}, errors.New("no bounded runner recipe for this OS/provider profile")
	}
	var doc recipeDocument
	if err := jsonstrict.Decode(raw, &doc); err != nil {
		return Recipe{}, errors.New("decode strict runner recipe")
	}
	if doc.Format != "ok-cli-runner-recipe/v1" || doc.Profile != profile || doc.GitOpsAuthority != "ok-gitops" ||
		doc.EnablementRevision != enablementRevision || doc.PlatformRevision != platformRevision ||
		!shaPattern.MatchString(enablementRevision) || !shaPattern.MatchString(platformRevision) ||
		len(doc.TargetAccess) != submission.TargetAccessObjectCount || doc.Network.ExpectedNodeCount != 2 {
		return Recipe{}, errors.New("runner recipe differs from reviewed Contract revisions or bounded topology")
	}
	for _, name := range []string{"openkubes.io/oci-manifest-digest", "openkubes.io/chart-artifact-digest", "openkubes.io/values-digest"} {
		if !shaPattern.MatchString(doc.Enablement.Pins[name]) {
			return Recipe{}, errors.New("runner recipe lacks immutable chart pins")
		}
	}
	if len(doc.Enablement.Pins) != 4 || doc.Enablement.Pins["openkubes.io/digest-enforcement"] != "external-evidence-required" {
		return Recipe{}, errors.New("runner recipe must preserve external chart evidence enforcement")
	}
	return Recipe{raw: append([]byte(nil), raw...), digest: digest.SHA256(raw), gitOpsAuthority: doc.GitOpsAuthority}, nil
}

func (recipe Recipe) Digest() string          { return recipe.digest }
func (recipe Recipe) GitOpsAuthority() string { return recipe.gitOpsAuthority }

var shaPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

type Rendered struct {
	Files                map[string][]byte
	EnablementObject     projection.ResourceIdentity
	TargetAccessObjects  []projection.ResourceIdentity
	NetworkProfile       observation.NetworkProfile
	NetworkProfileDigest string
}

// Render makes only desired artifacts. Runtime target identity remains deferred;
// no UID, token, previous outcome or recovery material is accepted as input.
func (recipe Recipe) Render(identity contract.Identity, revision, fixture string) (Rendered, error) {
	if recipe.digest == "" || digest.SHA256(recipe.raw) != recipe.digest || identity.Name != identity.Namespace ||
		!namePattern.MatchString(identity.Name) || len(identity.Name) > 63 || identity.Name == "default" || strings.HasPrefix(identity.Name, "kube-") ||
		!shaPattern.MatchString(revision) || !shaPattern.MatchString(fixture) {
		return Rendered{}, errors.New("verified recipe and fresh Contract/fixture identities required")
	}
	raw := bytes.ReplaceAll(recipe.raw, []byte("${CLUSTER_NAME}"), []byte(identity.Name))
	if bytes.Contains(raw, []byte("${")) {
		return Rendered{}, errors.New("unresolved runner recipe token")
	}
	var doc recipeDocument
	if err := jsonstrict.Decode(raw, &doc); err != nil {
		return Rendered{}, err
	}
	annotations := map[string]string{
		"openkubes.io/contract-name": identity.Name, "openkubes.io/contract-namespace": identity.Namespace,
		"openkubes.io/intent-revision": revision, "openkubes.io/enablement-revision": doc.EnablementRevision,
		"openkubes.io/execution-fixture": fixture,
	}
	for k, v := range doc.Enablement.Pins {
		annotations[k] = v
	}
	hcpIdentity := projection.ResourceIdentity{APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: identity.Namespace, Name: identity.Name + "-cilium"}
	hcp := map[string]any{"apiVersion": hcpIdentity.APIVersion, "kind": hcpIdentity.Kind,
		"metadata": map[string]any{"name": hcpIdentity.Name, "namespace": hcpIdentity.Namespace, "annotations": annotations}, "spec": doc.Enablement.Spec}
	hcpRaw, err := json.MarshalIndent(hcp, "", "  ")
	if err != nil {
		return Rendered{}, err
	}
	hcpDigest, err := observation.ExpectedChartSpecDigest(doc.Enablement.Spec)
	if err != nil || hcpDigest != doc.Network.ExpectedHCPSpecDigest {
		return Rendered{}, errors.New("rendered HCP spec differs from reviewed network profile")
	}
	hrpDigest, err := observation.ExpectedLiteralReleaseSpecDigest(doc.Enablement.Spec, identity.Namespace, identity.Name)
	if err != nil {
		return Rendered{}, err
	}
	doc.Network.IntentRevision = revision
	doc.Network.EnablementRevision = doc.EnablementRevision
	doc.Network.ExpectedHRPSpecDigest = hrpDigest
	networkDigest, err := observation.NetworkProfileDigest(doc.Network)
	if err != nil {
		return Rendered{}, err
	}
	networkRaw, err := json.MarshalIndent(doc.Network, "", "  ")
	if err != nil {
		return Rendered{}, err
	}
	var target bytes.Buffer
	var identities []projection.ResourceIdentity
	for i, obj := range doc.TargetAccess {
		meta, ok := obj["metadata"].(map[string]any)
		if !ok {
			return Rendered{}, errors.New("target recipe metadata missing")
		}
		if i < submission.TargetAccessBaseObjectCount {
			a := map[string]string{"openkubes.io/intent-revision": revision, "openkubes.io/platform-revision": doc.PlatformRevision, "openkubes.io/execution-fixture": fixture}
			if i >= 8 {
				a["openkubes.io/target-identity-digest"] = submission.RuntimeTargetIdentityDigestPlaceholder
			}
			meta["annotations"] = a
		}
		api, _ := obj["apiVersion"].(string)
		kind, _ := obj["kind"].(string)
		name, _ := meta["name"].(string)
		ns, _ := meta["namespace"].(string)
		identities = append(identities, projection.ResourceIdentity{APIVersion: api, Kind: kind, Name: name, Namespace: ns})
		b, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return Rendered{}, err
		}
		if i > 0 {
			target.WriteString("---\n")
		}
		target.Write(b)
		target.WriteByte('\n')
	}
	return Rendered{Files: map[string][]byte{"enablement.yaml": append(hcpRaw, '\n'), "network-profile.json": append(networkRaw, '\n'), "target-access.yaml": target.Bytes()},
		EnablementObject: hcpIdentity, TargetAccessObjects: identities, NetworkProfile: doc.Network, NetworkProfileDigest: networkDigest}, nil
}
