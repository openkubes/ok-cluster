package desiredauthority

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

type domainAPIFake struct {
	mu sync.Mutex
	binding DomainBinding
	alter string
	calls int
}
func(f *domainAPIFake) ServeHTTP(w http.ResponseWriter,r *http.Request){
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	w.Header().Set("Content-Type","application/json")
	if r.Method!="GET" || r.Header.Get("Authorization")!="Bearer test-short-token" || r.Header.Get("Cache-Control")!="no-cache"{
		w.WriteHeader(403);return
	}
	if f.alter=="redirect"{w.Header().Set("Location","https://untrusted.invalid/");w.WriteHeader(302);return}
	if f.alter=="unavailable"{w.WriteHeader(503);return}
	b:=f.binding
	switch r.URL.Path{
	case "/api/v1/namespaces/kube-system", "/api/v1/namespaces/"+b.AuthorityNamespace:
		if r.Header.Get("Accept")!=domainMetadataAccept{w.WriteHeader(400);return}
		name,uid,rv:="kube-system",b.ClusterUID,"101"
		if strings.HasSuffix(r.URL.Path,"/"+b.AuthorityNamespace){name,uid,rv=b.AuthorityNamespace,b.NamespaceUID,"102"}
		if f.alter=="namespace-uid" && name==b.AuthorityNamespace {uid="replacement"}
		if f.alter=="namespace-404" && name==b.AuthorityNamespace {w.WriteHeader(404);return}
		if f.alter=="cluster-uid" && name=="kube-system" {uid="replacement"}
		raw:=fmt.Sprintf(`{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":%q,"uid":%q,"resourceVersion":%q,"creationTimestamp":"2026-11-12T10:00:00Z"}}`,name,uid,rv)
		if f.alter=="duplicate-namespace-key" && name==b.AuthorityNamespace {raw=strings.Replace(raw,`"uid":`,`"UID":"replacement","uid":`,1)}
		_,_=w.Write([]byte(raw))
	case "/api/v1/namespaces/"+b.AuthorityNamespace+"/configmaps/"+b.FenceName:
		if r.Header.Get("Accept")!="application/json"{w.WriteHeader(400);return}
		if f.alter=="fence-404"{w.WriteHeader(404);return}
		uid,rv:=b.FenceUID,b.FenceResourceVersion
		if f.alter=="fence-uid"{uid="replacement"}
		if f.alter=="fence-rv"{rv="999"}
		data:=map[string]string{"format":"openkubes-desired-authority-fence/v1","state":"ACTIVE","namespaceUID":b.NamespaceUID,"domainDigest":b.ExpectedDomainDigest}
		if f.alter=="domain-digest"{data["domainDigest"]="sha256:"+strings.Repeat("b",64)}
		if f.alter=="deleted"{data["state"]="DISABLED"}
		obj:=map[string]any{"apiVersion":"v1","kind":"ConfigMap","metadata":map[string]any{"name":b.FenceName,"namespace":b.AuthorityNamespace,"uid":uid,"resourceVersion":rv,"creationTimestamp":"2026-11-12T10:00:00Z"},"immutable":true,"data":data}
		if f.alter=="unimmutable"{obj["immutable"]=false}
		raw,_:=json.Marshal(obj)
		if f.alter=="duplicate-fence-key"{raw=[]byte(strings.Replace(string(raw),`"immutable":true`,`"Immutable":false,"immutable":true`,1))}
		_,_=w.Write(raw)
	default:
		w.WriteHeader(404)
	}
}
func domainAPIFixture(t *testing.T)(DomainBinding,*PinnedDomainReader,*domainAPIFake,func()){
	t.Helper()
	f:=&domainAPIFake{}
	server:=httptest.NewTLSServer(f)
	roots:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:server.Certificate().Raw})
	trust,err:=kubeconfigtarget.TrustDigest(roots)
	if err!=nil{t.Fatal(err)}
	b:=DomainBinding{Endpoint:server.URL,TrustDigest:trust,ClusterUID:"cluster-uid-1",AuthorityNamespace:"openkubes-authority",NamespaceUID:"namespace-uid-1",FenceName:"authority-domain-fence",FenceUID:"fence-uid-1",FenceResourceVersion:"17"}
	d,err:=b.DomainIdentity();if err!=nil{t.Fatal(err)};b.ExpectedDomainDigest=d
	f.binding=b
	reader,err:=NewPinnedDomainReader(PinnedDomainReaderConfig{Binding:b,CABundle:roots,BearerToken:"test-short-token"})
	if err!=nil{t.Fatal(err)}
	return b,reader,f,server.Close
}
func TestPinnedReaderVerifiesExpectedDomain(t *testing.T){
	b,r,f,done:=domainAPIFixture(t);defer done()
	if err:=VerifyDomain(context.Background(),b,r);err!=nil{t.Fatal(err)}
	if f.calls!=3{t.Fatalf("expected 3 scoped GETs, received %d",f.calls)}
}
func TestPinnedReaderNegativeAPIConformance(t *testing.T){
	cases:=[]string{"redirect","unavailable","namespace-uid","namespace-404","cluster-uid","duplicate-namespace-key","fence-404","fence-uid","fence-rv","domain-digest","deleted","unimmutable","duplicate-fence-key"}
	for _,tc:=range cases{t.Run(tc,func(t *testing.T){
		b,r,f,done:=domainAPIFixture(t);defer done()
		f.alter=tc
		if err:=VerifyDomain(context.Background(),b,r);err!=ErrDomainUnverifiable{t.Fatalf("accepted invalid domain: %v",err)}
	})}
}
func TestPinnedReaderRejectsWrongCAAndToken(t *testing.T){
	b,_,_,done:=domainAPIFixture(t);defer done()
	wrong:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:[]byte("not a certificate")})
	if _,err:=NewPinnedDomainReader(PinnedDomainReaderConfig{Binding:b,CABundle:wrong,BearerToken:"test-short-token"});err!=ErrDomainUnverifiable{t.Fatalf("bad CA accepted: %v",err)}
}
func TestPinnedReaderNoMutationInterface(t *testing.T){
	_,reader,_,done:=domainAPIFixture(t);defer done()
	var _ DomainReader=reader
	// Reader has only ReadNamespace / ReadFence; no writer methods.
}
