package desiredauthority

import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync"
 "testing"
)

type casFake struct {
 mu sync.Mutex
 stored *authorityConfigMap
 writes int
 lose bool
 deny bool
}
func (f *casFake) ServeHTTP(w http.ResponseWriter,r *http.Request) {
 f.mu.Lock();defer f.mu.Unlock()
 w.Header().Set("Content-Type","application/json")
 if f.deny {w.WriteHeader(403);return}
 switch r.Method {
 case http.MethodGet:
  if f.stored==nil {w.WriteHeader(404);return}
  _=json.NewEncoder(w).Encode(f.stored)
 case http.MethodPost,http.MethodPut:
  var cm authorityConfigMap
  if json.NewDecoder(r.Body).Decode(&cm)!=nil {w.WriteHeader(400);return}
  if r.Method==http.MethodPost {
   if f.stored!=nil {w.WriteHeader(409);return}
  } else if f.stored==nil||cm.Metadata.ResourceVersion!=f.stored.Metadata.ResourceVersion||cm.Metadata.UID!=f.stored.Metadata.UID {
   w.WriteHeader(409);return
  }
  f.writes++
  cm.Metadata.UID="fixed-test-uid"
  cm.Metadata.ResourceVersion=fmt.Sprintf("%d",f.writes+1)
  f.stored=&cm
  if f.lose {w.WriteHeader(503);return}
  if r.Method==http.MethodPost {w.WriteHeader(201)} else {w.WriteHeader(200)}
  _=json.NewEncoder(w).Encode(f.stored)
 default: w.WriteHeader(405)
 }
}
func casFixture(t *testing.T)(*KubernetesStore,*casFake,func()){
 t.Helper()
 f:=&casFake{}
 server:=httptest.NewTLSServer(f)
 s,e:=NewKubernetesStore(server.URL,"authority-system",server.Client())
 if e!=nil {t.Fatal(e)}
 return s,f,server.Close
}
func seedState(t *testing.T,s *KubernetesStore,f *casFake,q Transition){
 t.Helper()
 state:=authorityRecord{Tenant:q.Tenant,Cluster:q.Cluster,Profile:q.AuthorityProfile,Snapshot:Snapshot{Revision:q.To,Last:&q}}
 b,e:=json.Marshal(state);if e!=nil{t.Fatal(e)}
 cm:=&authorityConfigMap{APIVersion:"v1",Kind:"ConfigMap",Data:map[string]string{"state":string(b)}}
 cm.Metadata.Name=s.name(q.Tenant,q.Cluster,q.AuthorityProfile)
 cm.Metadata.Namespace=s.namespace
 cm.Metadata.UID="fixed-test-uid"
 cm.Metadata.ResourceVersion="1"
 f.stored=cm
}
func TestKubernetesStoreRejectsUnfenced404WithoutWrite(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 state,e:=store.Inspect(context.Background(),"team-a","alpha","same-plane-v1")
 if e!=ErrUnverifiable||state.Revision==Absent{t.Fatalf("incorrect absence inference: %+v %v",state,e)}
 result,e:=store.CompareAndSwap(context.Background(),request())
 if e!=ErrUnverifiable||result.Outcome!=Indeterminate||f.writes!=0{t.Fatalf("unsafe create: %+v %v",result,e)}
}
func TestKubernetesStoreExactReplayAndConflictingTuple(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 q:=request();seedState(t,store,f,q)
 snapshot,e:=store.Inspect(context.Background(),q.Tenant,q.Cluster,q.AuthorityProfile)
 if e!=nil||snapshot.Revision!=q.To{t.Fatalf("inspect failed: %+v %v",snapshot,e)}
 result,e:=store.CompareAndSwap(context.Background(),q)
 if e!=nil||result.Outcome!=AlreadyAccepted{t.Fatalf("replay: %+v %v",result,e)}
 different:=q;different.TransitionID="another"
 result,e=store.CompareAndSwap(context.Background(),different)
 if e!=nil||result.Outcome!=PreconditionFailed||f.writes!=0{t.Fatalf("conflict: %+v %v writes=%d",result,e,f.writes)}
}
func TestKubernetesStoreUnfencedConcurrentCreatesNeverWrite(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 const n=24
 var wg sync.WaitGroup
 outcomes:=make(chan string,n)
 for i:=0;i<n;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   q:=request();q.TransitionID=fmt.Sprintf("nonce-%d",i)
   result,e:=store.CompareAndSwap(context.Background(),q)
   if e!=ErrUnverifiable{outcomes<-"unexpected error"}else{outcomes<-result.Outcome}
  }(i)
 }
 wg.Wait();close(outcomes)
 for outcome:=range outcomes{if outcome!=Indeterminate{t.Fatalf("unexpected outcome %s",outcome)}}
 if f.writes!=0{t.Fatalf("unfenced creation made %d writes",f.writes)}
}
func TestKubernetesStoreLostReadAndDenyFailClosed(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 q:=request();seedState(t,store,f,q)
 f.deny=true
 result,e:=store.CompareAndSwap(context.Background(),q)
 if e!=ErrUnverifiable||result.Outcome!=Indeterminate||f.writes!=0{t.Fatalf("%+v %v",result,e)}
}
func TestKubernetesStoreRealisticMetadataAndDuplicateKeys(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 q:=request();seedState(t,store,f,q)
 f.mu.Lock()
 cm:=*f.stored
 b,e:=json.Marshal(cm);f.mu.Unlock()
 if e!=nil{t.Fatal(e)}
 // Reject duplicate protected fields even if the trailing copy looks valid.
 extra:=strings.Replace(string(b),`"kind":"ConfigMap"`,`"kind":"Other","kind":"ConfigMap"`,1)
 if extra==string(b){t.Fatal("fixture missing kind")}
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  if r.Method!=http.MethodGet{w.WriteHeader(405);return}
  if r.URL.Path!=store.path(store.name(q.Tenant,q.Cluster,q.AuthorityProfile))[len(store.endpoint):]{w.WriteHeader(404);return}
  _,_=w.Write([]byte(extra))
 }))
 defer server.Close()
 rogue,e:=NewKubernetesStore(server.URL,"authority-system",server.Client());if e!=nil{t.Fatal(e)}
 if _,e=rogue.Inspect(context.Background(),q.Tenant,q.Cluster,q.AuthorityProfile);e!=ErrUnverifiable{t.Fatalf("duplicate accepted: %v",e)}
 // Actual Kubernetes responses contain many unrelated top-level metadata fields.
 normal:=strings.Replace(string(b),`"resourceVersion":"1"`,`"resourceVersion":"1","creationTimestamp":"2026-11-12T00:00:00Z","managedFields":[]`,1)
 realistic:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(normal))
 }))
 defer realistic.Close()
 client,e:=NewKubernetesStore(realistic.URL,"authority-system",realistic.Client());if e!=nil{t.Fatal(e)}
 got,e:=client.Inspect(context.Background(),q.Tenant,q.Cluster,q.AuthorityProfile)
 if e!=nil||got.Revision!=q.To{t.Fatalf("realistic metadata rejected: %+v %v",got,e)}
}
func TestKubernetesStoreNoPlainHTTP(t *testing.T){
 if _,e:=NewKubernetesStore("http://example.test","authority-system",http.DefaultClient);e==nil{t.Fatal("HTTP accepted")}
}
