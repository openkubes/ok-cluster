package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const observabilityCollectorObserverNamespace = "ok-observability"

type observerAuthorityObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name              string  `json:"name"`
		Namespace         string  `json:"namespace,omitempty"`
		UID               string  `json:"uid"`
		DeletionTimestamp *string `json:"deletionTimestamp,omitempty"`
	} `json:"metadata"`
	AutomountServiceAccountToken *bool            `json:"automountServiceAccountToken,omitempty"`
	Rules                        []map[string]any `json:"rules,omitempty"`
	RoleRef                      map[string]any   `json:"roleRef,omitempty"`
	Subjects                     []map[string]any `json:"subjects,omitempty"`
}

type observerAuthorityIdentity struct{ apiVersion, kind, name, path string }

var observerAuthorityIdentities = []observerAuthorityIdentity{
	{"v1", "Namespace", observabilityCollectorObserverNamespace, "/api/v1/namespaces/ok-observability"},
	{"v1", "ServiceAccount", observabilityCollectorObserverSA, "/api/v1/namespaces/ok-observability/serviceaccounts/ok147-observability-autonomy"},
	{"rbac.authorization.k8s.io/v1", "Role", observabilityCollectorObserverSA, "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/roles/ok147-observability-autonomy"},
	{"rbac.authorization.k8s.io/v1", "RoleBinding", observabilityCollectorObserverSA, "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/rolebindings/ok147-observability-autonomy"},
}

// awaitObserverAuthority performs only live GETs. Two identical consecutive
// snapshots are required before the sole TokenRequest is allowed.
func (issuer *KubernetesObservabilityCollectorObserverCredentialIssuer) awaitObserverAuthority(ctx context.Context) (string, error) {
	deadline := issuer.pollClock().Add(issuer.pollTimeout)
	previous := map[string]string{}
	seen := map[string]string{}
	for attempt := 1; attempt <= issuer.maxAttempts; attempt++ {
		if ctx.Err() != nil || !issuer.pollClock().Before(deadline) {
			return "", observerAuthorityExhausted()
		}
		current := map[string]string{}
		transient := false
		for _, identity := range observerAuthorityIdentities {
			uid, retry, err := issuer.readObserverAuthorityObject(ctx, deadline, identity)
			if err != nil {
				return "", err
			}
			if retry {
				if seen[identity.kind] != "" {
					return "", newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority object disappeared after becoming visible"))
				}
				transient = true
				break
			}
			if firstUID := seen[identity.kind]; firstUID != "" && firstUID != uid {
				return "", newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority object identity changed"))
			}
			seen[identity.kind] = uid
			current[identity.kind] = uid
		}
		if !transient && sameObserverAuthoritySnapshot(previous, current) {
			uid := current["ServiceAccount"]
			if uid == "" {
				return "", newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer service account identity is absent"))
			}
			return uid, nil
		}
		if len(previous) != 0 {
			return "", newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority regressed after becoming visible"))
		}
		if !transient {
			previous = current
		}
		if attempt == issuer.maxAttempts || !issuer.pollClock().Add(issuer.pollInterval).Before(deadline) {
			return "", observerAuthorityExhausted()
		}
		if err := issuer.wait(ctx, issuer.pollInterval); err != nil {
			return "", observerAuthorityExhausted()
		}
	}
	return "", observerAuthorityExhausted()
}

func observerAuthorityExhausted() error {
	return newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_CONVERGENCE_EXHAUSTED", errors.New("observer authority convergence exhausted"))
}

func (issuer *KubernetesObservabilityCollectorObserverCredentialIssuer) readObserverAuthorityObject(ctx context.Context, deadline time.Time, identity observerAuthorityIdentity) (string, bool, error) {
	requestURL := *issuer.endpoint
	requestURL.Path = identity.path
	requestContext, cancel := context.WithTimeout(ctx, deadline.Sub(issuer.pollClock()))
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("construct observer authority request"))
	}
	request.Header.Set("Accept", "application/json")
	if !issuer.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+issuer.authorityToken)
	}
	response, err := issuer.client.Do(request)
	if err != nil {
		if transientStageAuthorizationTransportError(err) {
			return "", true, nil
		}
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_CREDENTIAL_TRANSPORT_STOPPED", errors.New("observer authority transport stopped"))
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumTargetCredentialResponse+1))
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if readErr == nil && closeErr == nil && len(raw) <= maximumTargetCredentialResponse && transientObservabilityCollectorCredentialStatus(response.StatusCode) {
			return "", true, nil
		}
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority GET rejected"))
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > maximumTargetCredentialResponse || mediaErr != nil || mediaType != "application/json" {
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority response invalid"))
	}
	var document map[string]any
	if jsonstrict.Decode(raw, &document) != nil {
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority response is not strict JSON"))
	}
	normalized, marshalErr := json.Marshal(document)
	var object observerAuthorityObject
	if marshalErr != nil || json.Unmarshal(normalized, &object) != nil || !validObserverAuthorityObject(object, identity) {
		return "", false, newFixedRedactedStop("POST_PREFIX_OBSERVER_AUTHORITY_INVALID", errors.New("observer authority identity differs"))
	}
	return object.Metadata.UID, false, nil
}

func validObserverAuthorityObject(object observerAuthorityObject, identity observerAuthorityIdentity) bool {
	wantNamespace := observabilityCollectorObserverNamespace
	if identity.kind == "Namespace" {
		wantNamespace = ""
	}
	if object.APIVersion != identity.apiVersion || object.Kind != identity.kind || object.Metadata.Name != identity.name || object.Metadata.Namespace != wantNamespace || object.Metadata.UID == "" || object.Metadata.DeletionTimestamp != nil {
		return false
	}
	switch identity.kind {
	case "Namespace":
		return true
	case "ServiceAccount":
		return object.AutomountServiceAccountToken != nil && !*object.AutomountServiceAccountToken
	case "Role":
		return exactObserverAuthorityRules(object.Rules)
	case "RoleBinding":
		return exactObserverAuthorityBinding(object.RoleRef, object.Subjects)
	default:
		return false
	}
}

func exactObserverAuthorityRules(rules []map[string]any) bool {
	return len(rules) == 2 && len(rules[0]) == 3 && exactStringList(rules[0]["apiGroups"], []string{""}) && exactStringList(rules[0]["resources"], []string{"services"}) && exactStringList(rules[0]["verbs"], []string{"get"}) && len(rules[1]) == 3 && exactStringList(rules[1]["apiGroups"], []string{"discovery.k8s.io"}) && exactStringList(rules[1]["resources"], []string{"endpointslices"}) && exactStringList(rules[1]["verbs"], []string{"list"})
}

func exactObserverAuthorityBinding(roleRef map[string]any, subjects []map[string]any) bool {
	return exactStringMapKeys(roleRef, "apiGroup", "kind", "name") && roleRef["apiGroup"] == "rbac.authorization.k8s.io" && roleRef["kind"] == "Role" && roleRef["name"] == observabilityCollectorObserverSA && len(subjects) == 1 && exactStringMapKeys(subjects[0], "kind", "name", "namespace") && subjects[0]["kind"] == "ServiceAccount" && subjects[0]["name"] == observabilityCollectorObserverSA && subjects[0]["namespace"] == observabilityCollectorObserverNamespace
}

func sameObserverAuthoritySnapshot(left, right map[string]string) bool {
	if len(left) != len(observerAuthorityIdentities) || len(right) != len(observerAuthorityIdentities) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func observerCredentialEndpoint(base url.URL) url.URL {
	base.Path = "/api/v1/namespaces/ok-observability/serviceaccounts/" + observabilityCollectorObserverSA + "/token"
	return base
}
