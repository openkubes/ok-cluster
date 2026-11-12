package desiredauthority

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
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
  cm.Metadata.ResourceVersion="1"
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
func TestKubernetesStoreCASAndReplay(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 q:=request()
 r,e:=store.CompareAndSwap(context.Background(),q)
 if e!=nil||r.Outcome!=Accepted {t.Fatalf("%+v %v",r,e)}
 r,e=store.CompareAndSwap(context.Background(),q)
 if e!=nil||r.Outcome!=AlreadyAccepted {t.Fatalf("%+v %v",r,e)}
 q.TransitionID="another"
 r,e=store.CompareAndSwap(context.Background(),q)
 if e!=nil||r.Outcome!=PreconditionFailed {t.Fatalf("%+v %v",r,e)}
 if f.writes!=1 {t.Fatalf("unexpected writes: %d",f.writes)}
}
func TestKubernetesStoreConcurrentSingleWinner(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 const n=24
 var wg sync.WaitGroup
 results:=make(chan string,n)
 for i:=0;i<n;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   q:=request()
   q.TransitionID=string(rune('a'+i))
   r,e:=store.CompareAndSwap(context.Background(),q)
   if e!=nil {results<-"error"} else {results<-r.Outcome}
  }(i)
 }
 wg.Wait();close(results)
 winners:=0
 for v:=range results {
  if v==Accepted {winners++} else if v!=PreconditionFailed {t.Fatalf("unexpected outcome %s",v)}
 }
 if winners!=1||f.writes!=1 {t.Fatalf("winners=%d writes=%d",winners,f.writes)}
}
func TestKubernetesStoreLostResponseStopsAndInspects(t *testing.T){
 store,f,cleanup:=casFixture(t);defer cleanup()
 f.lose=true
 q:=request()
 r,e:=store.CompareAndSwap(context.Background(),q)
 if e!=ErrUnverifiable||r.Outcome!=Indeterminate||f.writes!=1 {t.Fatalf("%+v %v writes=%d",r,e,f.writes)}
 recovered,e:=ReconcileIndeterminate(context.Background(),store,q)
 if e!=nil||recovered.Outcome!=AlreadyAccepted||f.writes!=1 {t.Fatalf("%+v %v writes=%d",recovered,e,f.writes)}
}
func TestKubernetesStoreNoPlainHTTPOrDeniedWrite(t *testing.T){
 if _,e:=NewKubernetesStore("http://example.test","authority-system",http.DefaultClient);e==nil {t.Fatal("HTTP accepted")}
 store,f,cleanup:=casFixture(t);defer cleanup()
 f.deny=true
 r,e:=store.CompareAndSwap(context.Background(),request())
 if e!=ErrUnverifiable||r.Outcome!=Indeterminate||f.writes!=0 {t.Fatalf("%+v %v",r,e)}
}
