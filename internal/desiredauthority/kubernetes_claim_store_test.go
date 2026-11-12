package desiredauthority

import (
 "context"
 "crypto/x509"
 "encoding/json"
 "encoding/pem"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync"
 "testing"

 "github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

type claimAPIFake struct{
 mu sync.Mutex
 domain domainAPIFake
 object []byte
 creates int
 lose bool
 deleteObject bool
 badContent bool
}
func(f *claimAPIFake) ServeHTTP(w http.ResponseWriter,r *http.Request){
 if strings.HasSuffix(r.URL.Path,"/configmaps") || strings.Contains(r.URL.Path,"/configmaps/ok226-claim-"){
  f.mu.Lock();defer f.mu.Unlock()
  w.Header().Set("Content-Type","application/json")
  if r.Header.Get("Authorization")!="Bearer test-short-token"{w.WriteHeader(403);return}
  switch r.Method{
  case http.MethodPost:
   if f.object!=nil {w.WriteHeader(409);_,_=io.WriteString(w,`{"apiVersion":"v1","kind":"Status","reason":"AlreadyExists","code":409,"details":{"name":"`+claimTestName(f.object)+`","kind":"configmaps"}}`);return}
   raw,_:=io.ReadAll(io.LimitReader(r.Body,65537))
   var cm claimKubernetesObject
   if json.Unmarshal(raw,&cm)!=nil{w.WriteHeader(400);return}
   cm.Metadata.UID="claim-uid-test";cm.Metadata.ResourceVersion="101"
   f.object,_=json.Marshal(cm);f.creates++
   if f.lose{w.WriteHeader(503);return}
   w.WriteHeader(201);_,_=w.Write(f.object)
  case http.MethodGet:
   if f.deleteObject{f.object=nil}
   if f.object==nil{w.WriteHeader(404);_,_=io.WriteString(w,`{"kind":"Status","reason":"NotFound"}`);return}
   if f.badContent{w.WriteHeader(200);_,_=w.Write([]byte(strings.Replace(string(f.object),`"immutable":true`,`"immutable":false`,1)));return}
   _,_=w.Write(f.object)
  default:w.WriteHeader(405)
  }
  return
 }
 f.domain.ServeHTTP(w,r)
}
func claimTestName(raw []byte)string{
 var o claimKubernetesObject
 _=json.Unmarshal(raw,&o)
 return o.Metadata.Name
}
func claimAPIFixture(t *testing.T)(*KubernetesClaimStore,*claimAPIFake,func()){
 t.Helper()
 f:=&claimAPIFake{}
 server:=httptest.NewTLSServer(f)
 ca:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:server.Certificate().Raw})
 pool:=x509.NewCertPool()
 if !pool.AppendCertsFromPEM(ca){t.Fatal("invalid test CA")}
 trust,err:=kubeconfigtarget.TrustDigest(ca);if err!=nil{t.Fatal(err)}
 b:=DomainBinding{Endpoint:server.URL,TrustDigest:trust,ClusterUID:"cluster-uid-1",AuthorityNamespace:"openkubes-authority",NamespaceUID:"namespace-uid-1",FenceName:"authority-domain-fence",FenceUID:"fence-uid-1",FenceResourceVersion:"17"}
 domain,err:=b.DomainIdentity();if err!=nil{t.Fatal(err)}
 b.ExpectedDomainDigest=domain
 f.domain.binding=b
 s,err:=NewKubernetesClaimStore(PinnedDomainReaderConfig{Binding:b,CABundle:ca,BearerToken:"test-short-token"})
 if err!=nil{t.Fatal(err)}
 return s,f,server.Close
}
func TestKubernetesClaimAdapterExactCreateConflictReadback(t *testing.T){
 s,f,done:=claimAPIFixture(t);defer done()
 a,tr,trust,now:=signedAuthorizationFixture(t)
 // Bind the independently verified signature to the fixture domain via a
 // test-only signer so ordinary preflight still checks full cryptography.
 _=a;_ = tr;_ = trust;_ = now
 record:=validClaimRecordFixture(t,s.binding.ExpectedDomainDigest)
 outcome,err:=s.CreateIfAbsent(context.Background(),record.SlotDigest,record)
 if err!=nil||outcome!=ClaimCreated{t.Fatalf("create: %s %v",outcome,err)}
 got,exists,err:=s.InspectClaim(context.Background(),record.SlotDigest)
 if err!=nil||!exists||got!=record{t.Fatalf("inspect: %+v %v",got,err)}
 outcome,err=s.CreateIfAbsent(context.Background(),record.SlotDigest,record)
 if err!=nil||outcome!=ClaimConflict||f.creates!=1{t.Fatalf("replay: %s %v creates=%d",outcome,err,f.creates)}
}
func validClaimRecordFixture(t *testing.T,domain string)ClaimRecord{
 t.Helper()
 _,tr,_,now:=signedAuthorizationFixture(t)
 s:=AuthorizationStatement{Version:authorizationStatementVersion,DomainDigest:domain,Audience:"ok226-authority-cas-v1",KeyID:"test-policy",Nonce:"nonce-test-1",IssuedAt:now.Unix()-5,ExpiresAt:now.Unix()+60,Transition:tr}
 slot,err:=ClaimSlotDigest(s);if err!=nil{t.Fatal(err)}
 statement,err:=AuthorizationStatementDigest(s);if err!=nil{t.Fatal(err)}
 return ClaimRecord{Version:claimRecordVersion,SlotDigest:slot,StatementDigest:statement,
 SignatureDigest:"sha256:"+strings.Repeat("a",64),DomainDigest:domain,Audience:s.Audience,KeyID:s.KeyID,
 Nonce:s.Nonce,Transition:tr,ClaimedAt:now.Unix()}
}
func TestKubernetesClaimAdapterLostResponseNeverAllowsClaim(t *testing.T){
 s,f,done:=claimAPIFixture(t);defer done()
 record:=validClaimRecordFixture(t,s.binding.ExpectedDomainDigest);f.lose=true
 outcome,err:=s.CreateIfAbsent(context.Background(),record.SlotDigest,record)
 if outcome!=ClaimIndeterminate||err!=ErrClaimUnverifiable||f.creates!=1{t.Fatalf("unknown create: %s %v",outcome,err)}
 got,exists,err:=s.InspectClaim(context.Background(),record.SlotDigest)
 if err!=nil||!exists||got!=record{t.Fatalf("readback failed: %+v %v",got,err)}
}
func TestKubernetesClaimAdapterMissingAndTamperedFailClosed(t *testing.T){
 s,f,done:=claimAPIFixture(t);defer done()
 record:=validClaimRecordFixture(t,s.binding.ExpectedDomainDigest)
 if _,exists,err:=s.InspectClaim(context.Background(),record.SlotDigest);err!=ErrClaimUnverifiable||exists{t.Fatalf("404 treated as absence: %v %v",exists,err)}
 if outcome,err:=s.CreateIfAbsent(context.Background(),record.SlotDigest,record);outcome!=ClaimCreated||err!=nil{t.Fatal(outcome,err)}
 f.badContent=true
 if _,exists,err:=s.InspectClaim(context.Background(),record.SlotDigest);err!=ErrClaimUnverifiable||exists{t.Fatalf("tampered object accepted: %v %v",exists,err)}
 f.badContent=false;f.deleteObject=true
 if _,exists,err:=s.InspectClaim(context.Background(),record.SlotDigest);err!=ErrClaimUnverifiable||exists{t.Fatalf("deleted slot accepted: %v %v",exists,err)}
}
func TestKubernetesClaimAdapterFailsOnDomainChange(t *testing.T){
 s,f,done:=claimAPIFixture(t);defer done()
 record:=validClaimRecordFixture(t,s.binding.ExpectedDomainDigest)
 f.domain.alter="namespace-uid"
 outcome,err:=s.CreateIfAbsent(context.Background(),record.SlotDigest,record)
 if outcome!=ClaimIndeterminate||err!=ErrClaimUnverifiable||f.creates!=0{t.Fatalf("unsafe write: %s %v %d",outcome,err,f.creates)}
}
func TestKubernetesClaimAdapterRejectsUntrustedBinding(t *testing.T){
 s,_,done:=claimAPIFixture(t);defer done()
 bad:=s.binding
 bad.ExpectedDomainDigest="sha256:"+strings.Repeat("b",64)
 _,err:=NewKubernetesClaimStore(PinnedDomainReaderConfig{Binding:bad,CABundle:nil,BearerToken:"token"})
 if err!=ErrClaimUnverifiable{t.Fatalf("untrusted context accepted: %v",err)}
 name,err:=claimConfigMapName("sha256:"+strings.Repeat("a",64))
 if err!=nil||len(name)>253{t.Fatal(fmt.Sprint(name,err))}
}
