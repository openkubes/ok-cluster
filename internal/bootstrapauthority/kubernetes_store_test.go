package bootstrapauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeIssuerAPI struct {
	mu                                                                                                        sync.Mutex
	server                                                                                                    *httptest.Server
	config                                                                                                    KubernetesStoreConfig
	nsUID, fenceUID, fenceRV, purpose, fenceState                                                             string
	objects                                                                                                   map[string]storeConfigMap
	requests                                                                                                  []string
	posts                                                                                                     int
	afterPost                                                                                                 func(*fakeIssuerAPI)
	mutateRead                                                                                                func(*storeConfigMap)
	badStatus, badJSON, namespaceFull, missingFence, dropAfterCommit, failAfterCommit, redirect, wrongContent bool
}

func newFakeIssuerAPI(t *testing.T) (*fakeIssuerAPI, *KubernetesStore) {
	t.Helper()
	f := &fakeIssuerAPI{nsUID: "fixture-namespace-uid", fenceUID: "fixture-fence-uid", fenceRV: "10", purpose: "bootstrap-issuer", fenceState: "ACTIVE", objects: map[string]storeConfigMap{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.config = KubernetesStoreConfig{Endpoint: f.server.URL, CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), BearerToken: "fixture-token", Namespace: "issuer-fixture", NamespaceUID: f.nsUID, FenceName: "issuer-store-fence", FenceUID: f.fenceUID, FenceResourceVersion: f.fenceRV}
	domain, err := KubernetesDomainDigest(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.config.ExpectedDomainDigest = domain
	s, err := NewKubernetesStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 0 {
		t.Fatal("constructor contacted API")
	}
	return f, s
}
func (f *fakeIssuerAPI) status(w http.ResponseWriter, code int, reason, name string) {
	w.WriteHeader(code)
	if f.badStatus {
		fmt.Fprint(w, `{"kind":"Status","message":"SENSITIVE_FIXTURE"}`)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason, "code": code, "details": map[string]string{"kind": "configmaps", "name": name}})
}
func (f *fakeIssuerAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer fixture-token" {
		f.status(w, 403, "Forbidden", "")
		return
	}
	if r.URL.RawQuery != "" {
		f.status(w, 400, "BadRequest", "")
		return
	}
	if f.redirect {
		w.Header().Set("Location", f.server.URL+"/redirect-target")
		w.WriteHeader(307)
		return
	}
	if f.wrongContent {
		w.Header().Set("Content-Type", "text/plain")
	}
	if f.badJSON {
		fmt.Fprint(w, `{"kind":"SENSITIVE_FIXTURE",`)
		return
	}
	nsPath := "/api/v1/namespaces/" + f.config.Namespace
	collection := nsPath + "/configmaps"
	if r.Method == "GET" && r.URL.Path == nsPath {
		if r.Header.Get("Accept") != metadataAccept {
			f.status(w, 406, "NotAcceptable", "")
			return
		}
		kind, version := "PartialObjectMetadata", "meta.k8s.io/v1"
		if f.namespaceFull {
			kind, version = "Namespace", "v1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": version, "kind": kind, "metadata": storeMetadata{Name: f.config.Namespace, UID: f.nsUID, ResourceVersion: "20", Labels: map[string]string{namespacePurpose: f.purpose}}})
		return
	}
	if r.Method == "GET" && r.URL.Path == collection+"/"+f.config.FenceName {
		if f.missingFence {
			f.status(w, 404, "NotFound", f.config.FenceName)
			return
		}
		_ = json.NewEncoder(w).Encode(storeConfigMap{APIVersion: "v1", Kind: "ConfigMap", Immutable: true, Metadata: storeMetadata{Name: f.config.FenceName, Namespace: f.config.Namespace, UID: f.fenceUID, ResourceVersion: f.fenceRV, Labels: map[string]string{"app.kubernetes.io/managed-by": issuerManagedBy, "cli.openkubes.io/issuer-record": "fence"}}, Data: map[string]string{"format": "ok147-bootstrap-store-fence-candidate/v1", "state": f.fenceState, "namespaceUID": f.nsUID}})
		return
	}
	if r.Method == "POST" && r.URL.Path == collection {
		f.posts++
		var object storeConfigMap
		if json.NewDecoder(r.Body).Decode(&object) != nil {
			f.status(w, 400, "BadRequest", "")
			return
		}
		if _, ok := f.objects[object.Metadata.Name]; ok {
			f.status(w, 409, "AlreadyExists", object.Metadata.Name)
			return
		}
		object.Metadata.UID = fmt.Sprintf("fixture-record-uid-%d", f.posts)
		object.Metadata.ResourceVersion = fmt.Sprint(f.posts)
		f.objects[object.Metadata.Name] = object
		if f.afterPost != nil {
			f.afterPost(f)
		}
		if f.dropAfterCommit {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if f.failAfterCommit {
			f.status(w, 500, "InternalError", object.Metadata.Name)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(object)
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, collection+"/") {
		name := strings.TrimPrefix(r.URL.Path, collection+"/")
		object, ok := f.objects[name]
		if !ok {
			f.status(w, 404, "NotFound", name)
			return
		}
		// Deep copy before adversarial response mutation.
		raw, _ := json.Marshal(object)
		_ = json.Unmarshal(raw, &object)
		if f.mutateRead != nil {
			f.mutateRead(&object)
		}
		_ = json.NewEncoder(w).Encode(object)
		return
	}
	f.status(w, 405, "MethodNotAllowed", "")
}
func fakeClaimRecord(t *testing.T, key string) []byte {
	t.Helper()
	raw, err := json.Marshal(claimRecord{"ok147-bootstrap-claim-candidate/v1", key, digest([]byte("authorization")), digest([]byte("policy")), digest([]byte("key")), time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKubernetesIssuerStoreRoundTripAndAtomicConflict(t *testing.T) {
	f, s := newFakeIssuerAPI(t)
	key := digest([]byte("slot"))
	raw := fakeClaimRecord(t, key)
	ctx := context.Background()
	if _, err := s.ReadClaim(ctx, key); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := s.CreateClaim(ctx, key, raw); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClaim(ctx, key, raw); err != ErrExists {
		t.Fatal(err)
	}
	replacement, err := NewKubernetesStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := replacement.ReadClaim(ctx, key)
	if err != nil || string(got) != string(raw) {
		t.Fatal("replacement adapter lost record", err)
	}
	if s.DomainDigest() != replacement.DomainDigest() {
		t.Fatal("domain changed on client restart")
	}
	for _, request := range f.requests {
		if !strings.HasPrefix(request, "GET /api/v1/namespaces/") && !strings.HasPrefix(request, "POST /api/v1/namespaces/issuer-fixture/configmaps") {
			t.Fatal("unexpected request", request)
		}
	}
	name, _ := recordName("claim", key)
	if strings.ReplaceAll(strings.TrimPrefix(name, "okbi-claim-"), ".", "") != key[7:] || !dnsName(name) {
		t.Fatal("slot key truncated or invalid DNS name")
	}
}

func TestKubernetesStoreBacksSeparateAuthority(t *testing.T) {
	api, s := newFakeIssuerAPI(t)
	f := newFixture(t)
	f.trust.StoreDomainDigest = s.DomainDigest()
	f.r.StoreDomainDigest = s.DomainDigest()
	f.signRequest(t)
	a, err := New(f.trust, s)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	c := f.claim(t)
	if err := a.Complete(context.Background(), c, f.result(t, c), f.now); err != nil {
		t.Fatal(err)
	}
	s2, err := NewKubernetesStore(api.config)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New(f.trust, s2)
	if err != nil {
		t.Fatal(err)
	}
	state, err := a2.Inspect(context.Background(), f.r, f.inputs)
	if err != nil || state.State != "RESULT_RECORDED_NOT_STAGE_AUTHORIZED" {
		t.Fatal(state, err)
	}
	r, err := a2.Verify(f.r, f.inputs, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a2.Claim(context.Background(), r, f.now); err != ErrConsumed {
		t.Fatal("replacement authority reopened slot", err)
	}
	if api.posts != 2 {
		t.Fatal("unexpected number of record creates", api.posts)
	}
}

func TestKubernetesStoreConcurrentCreateOnly(t *testing.T) {
	f, _ := newFakeIssuerAPI(t)
	key := digest([]byte("slot"))
	raw := fakeClaimRecord(t, key)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := NewKubernetesStore(f.config)
			if err != nil {
				t.Error(err)
				return
			}
			if err = s.CreateClaim(context.Background(), key, raw); err == nil {
				wins.Add(1)
			} else if err != ErrExists {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || len(f.objects) != 1 {
		t.Fatal("atomic create violated", wins.Load(), len(f.objects))
	}
}

func TestKubernetesStorePreconditionsNeverCreate(t *testing.T) {
	for name, mutate := range map[string]func(*fakeIssuerAPI){
		"namespace replacement":   func(f *fakeIssuerAPI) { f.nsUID = "replacement-uid" },
		"purpose drift":           func(f *fakeIssuerAPI) { f.purpose = "stage-ledger" },
		"fence replacement":       func(f *fakeIssuerAPI) { f.fenceUID = "replacement-fence" },
		"fence RV drift":          func(f *fakeIssuerAPI) { f.fenceRV = "11" },
		"inactive fence":          func(f *fakeIssuerAPI) { f.fenceState = "INACTIVE" },
		"missing fence":           func(f *fakeIssuerAPI) { f.missingFence = true },
		"full namespace fallback": func(f *fakeIssuerAPI) { f.namespaceFull = true },
		"invalid JSON":            func(f *fakeIssuerAPI) { f.badJSON = true },
		"wrong content type":      func(f *fakeIssuerAPI) { f.wrongContent = true },
	} {
		t.Run(name, func(t *testing.T) {
			f, s := newFakeIssuerAPI(t)
			mutate(f)
			key := digest([]byte("slot"))
			if s.CreateClaim(context.Background(), key, fakeClaimRecord(t, key)) != ErrStop || f.posts != 0 {
				t.Fatal("precondition allowed create")
			}
			if _, err := s.ReadClaim(context.Background(), key); err != ErrStop {
				t.Fatal("precondition failure became absence", err)
			}
		})
	}
}

func TestKubernetesStoreDetectsMidFlightDomainDrift(t *testing.T) {
	for _, which := range []string{"namespace", "fence"} {
		t.Run(which, func(t *testing.T) {
			f, s := newFakeIssuerAPI(t)
			key := digest([]byte("slot"))
			f.afterPost = func(f *fakeIssuerAPI) {
				if which == "namespace" {
					f.nsUID = "recreated"
				} else {
					f.fenceUID = "recreated"
				}
			}
			if s.CreateClaim(context.Background(), key, fakeClaimRecord(t, key)) != ErrStop || f.posts != 1 {
				t.Fatal("drift returned success or repeated POST")
			}
			if _, err := s.ReadClaim(context.Background(), key); err != ErrStop {
				t.Fatal("new namespace treated as original", err)
			}
		})
	}
}

func TestKubernetesStoreLostWriteResponseNeverRetries(t *testing.T) {
	for _, drop := range []bool{false, true} {
		f, s := newFakeIssuerAPI(t)
		key := digest([]byte("slot"))
		f.dropAfterCommit = drop
		f.failAfterCommit = !drop
		if s.CreateClaim(context.Background(), key, fakeClaimRecord(t, key)) != ErrStop || f.posts != 1 {
			t.Fatal("unknown write retried or reported success", f.posts)
		}
		f.dropAfterCommit = false
		f.failAfterCommit = false
		if _, err := s.ReadClaim(context.Background(), key); err != nil {
			t.Fatal("committed record not inspectable", err)
		}
	}
}

func TestKubernetesStoreRejectsRecordDrift(t *testing.T) {
	for name, mutate := range map[string]func(*storeConfigMap){
		"not immutable":   func(c *storeConfigMap) { c.Immutable = false },
		"wrong namespace": func(c *storeConfigMap) { c.Metadata.Namespace = "other" },
		"wrong name":      func(c *storeConfigMap) { c.Metadata.Name = "other" },
		"missing UID":     func(c *storeConfigMap) { c.Metadata.UID = "" },
		"missing RV":      func(c *storeConfigMap) { c.Metadata.ResourceVersion = "" },
		"foreign owner": func(c *storeConfigMap) {
			c.Metadata.OwnerReferences = []json.RawMessage{json.RawMessage(`{"kind":"Cluster"}`)}
		},
		"deleting": func(c *storeConfigMap) { c.Metadata.DeletionTimestamp = json.RawMessage(`"2026-10-18T13:00:00Z"`) },
		"domain annotation": func(c *storeConfigMap) {
			c.Metadata.Annotations["cli.openkubes.io/issuer-domain"] = digest([]byte("other"))
		},
		"payload hash": func(c *storeConfigMap) {
			c.Metadata.Annotations["cli.openkubes.io/record-digest"] = digest([]byte("other"))
		},
		"extra data":  func(c *storeConfigMap) { c.Data["private-key"] = "SENSITIVE_FIXTURE" },
		"binary data": func(c *storeConfigMap) { c.BinaryData = map[string]string{"key": "SENSITIVE_FIXTURE"} },
	} {
		t.Run(name, func(t *testing.T) {
			f, s := newFakeIssuerAPI(t)
			key := digest([]byte("slot"))
			if err := s.CreateClaim(context.Background(), key, fakeClaimRecord(t, key)); err != nil {
				t.Fatal(err)
			}
			f.mutateRead = mutate
			_, err := s.ReadClaim(context.Background(), key)
			if err != ErrStop || strings.Contains(err.Error(), "SENSITIVE_FIXTURE") {
				t.Fatal("record drift accepted or leaked", err)
			}
		})
	}
}

func TestKubernetesStoreRejectsUnsafeConfigAndPayloadsLocally(t *testing.T) {
	f, _ := newFakeIssuerAPI(t)
	for name, mutate := range map[string]func(*KubernetesStoreConfig){
		"HTTP":  func(c *KubernetesStoreConfig) { c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1) },
		"query": func(c *KubernetesStoreConfig) { c.Endpoint += "?x=1" },
		"userinfo": func(c *KubernetesStoreConfig) {
			c.Endpoint = strings.Replace(c.Endpoint, "https://", "https://user@", 1)
		},
		"default namespace": func(c *KubernetesStoreConfig) { c.Namespace = "default" },
		"stage namespace":   func(c *KubernetesStoreConfig) { c.Namespace = "openkubes-execution-system" },
		"missing UID":       func(c *KubernetesStoreConfig) { c.NamespaceUID = "" },
		"missing fence":     func(c *KubernetesStoreConfig) { c.FenceUID = "" },
		"wrong domain":      func(c *KubernetesStoreConfig) { c.ExpectedDomainDigest = digest([]byte("other")) },
		"bad CA":            func(c *KubernetesStoreConfig) { c.CABundle = []byte("invalid") },
		"empty token":       func(c *KubernetesStoreConfig) { c.BearerToken = "" },
		"token newline":     func(c *KubernetesStoreConfig) { c.BearerToken = "fixture\n-token" },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.config
			mutate(&c)
			if _, err := NewKubernetesStore(c); err != ErrStop {
				t.Fatal("unsafe configuration accepted", err)
			}
		})
	}
	_, s := newFakeIssuerAPI(t)
	key := digest([]byte("slot"))
	if s.CreateClaim(context.Background(), key, []byte(`{"format":"old-stage-ledger"}`)) != ErrStop {
		t.Fatal("old format accepted")
	}
	if s.CreateResult(context.Background(), key, fakeClaimRecord(t, key)) != ErrStop {
		t.Fatal("claim accepted as result")
	}
	if _, err := s.ReadClaim(context.Background(), "../../escape"); err != ErrStop {
		t.Fatal("invalid slot accepted")
	}
}

func TestKubernetesStoreBadAbsenceRedirectAndCancelledContext(t *testing.T) {
	f, s := newFakeIssuerAPI(t)
	key := digest([]byte("slot"))
	f.badStatus = true
	if _, err := s.ReadClaim(context.Background(), key); err != ErrStop {
		t.Fatal("bad status became NotFound", err)
	}
	f.badStatus = false
	f.redirect = true
	if _, err := s.ReadClaim(context.Background(), key); err != ErrStop {
		t.Fatal("redirect accepted", err)
	}
	for _, request := range f.requests {
		if strings.Contains(request, "redirect-target") {
			t.Fatal("followed redirect")
		}
	}
	f.redirect = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.CreateClaim(ctx, key, fakeClaimRecord(t, key)) != ErrStop || f.posts != 0 {
		t.Fatal("cancelled operation created a record")
	}
}

func TestKubernetesStoreTLSConfigurationAndWrongTrust(t *testing.T) {
	f, s := newFakeIssuerAPI(t)
	transport, ok := s.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableKeepAlives || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.TLSClientConfig.RootCAs == nil || len(transport.TLSClientConfig.Certificates) != 0 || transport.TLSClientConfig.GetClientCertificate != nil || s.client.Jar != nil {
		t.Fatal("unsafe transport configuration")
	}
	fixture := newFixture(t)
	config := f.config
	config.CABundle = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.ca.Raw})
	var err error
	config.ExpectedDomainDigest, err = KubernetesDomainDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewKubernetesStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.ReadClaim(context.Background(), digest([]byte("slot"))); err != ErrStop || len(f.requests) != 0 {
		t.Fatal("wrong CA reached authenticated API", err)
	}
}

func TestKubernetesStoreSecurityJSONAndRecordShapes(t *testing.T) {
	_, s := newFakeIssuerAPI(t)
	key := digest([]byte("slot"))
	raw := fakeClaimRecord(t, key)
	object, err := s.object("claim", key, raw)
	if err != nil {
		t.Fatal(err)
	}
	object.Metadata.UID = "fixture-record-uid"
	object.Metadata.ResourceVersion = "1"
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, broken := range []string{
		strings.Replace(string(encoded), `"uid":"fixture-record-uid"`, `"uid":"other","UID":"fixture-record-uid"`, 1),
		strings.Replace(string(encoded), `"kind":"ConfigMap"`, `"kind":"Secret","KIND":"ConfigMap"`, 1),
		strings.Replace(string(encoded), `"uid":"fixture-record-uid"`, `"uid":"other","uid":"fixture-record-uid"`, 1),
		string(encoded) + `{}`,
	} {
		if _, err := s.verifyMap([]byte(broken), "claim", key); err != ErrStop {
			t.Fatal("accepted ambiguous object JSON")
		}
	}
	status := `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"details":{"name":"wanted","kind":"configmaps"}}`
	if !statusMatches([]byte(status), 404, "NotFound", "wanted") {
		t.Fatal("valid status rejected")
	}
	for _, broken := range []string{
		strings.Replace(status, `"name":"wanted"`, `"name":"other","NAME":"wanted"`, 1),
		strings.Replace(status, `"kind":"Status"`, `"kind":"Secret","KIND":"Status"`, 1),
		strings.Replace(status, `"details":`, `"data":{"key":"SENSITIVE_FIXTURE"},"details":`, 1),
	} {
		if statusMatches([]byte(broken), 404, "NotFound", "wanted") {
			t.Fatal("accepted ambiguous absence status")
		}
	}
	if ValidateRecord("claim", key, append(raw, []byte("{}")...)) != ErrStop || ValidateRecord("other", key, raw) != ErrStop {
		t.Fatal("invalid record accepted")
	}
}
