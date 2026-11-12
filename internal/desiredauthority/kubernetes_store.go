package desiredauthority

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "net/http"
 "net/url"
 "strings"

 "github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// KubernetesStore is DISCONNECTED from the CLI and Executor. Kubernetes
// persistence alone does not establish policy authorization or anti-rollback.
type KubernetesStore struct { endpoint, namespace string; client *http.Client }
type authorityConfigMap struct {
 APIVersion string `json:"apiVersion"`
 Kind string `json:"kind"`
 Metadata struct {
  Name string `json:"name"`
  Namespace string `json:"namespace"`
  UID string `json:"uid,omitempty"`
  ResourceVersion string `json:"resourceVersion,omitempty"`
 } `json:"metadata"`
 Data map[string]string `json:"data"`
}
type authorityRecord struct {
 Tenant string `json:"tenant"`
 Cluster string `json:"cluster"`
 Profile string `json:"authorityProfile"`
 Snapshot Snapshot `json:"snapshot"`
}
func NewKubernetesStore(endpoint,namespace string,client *http.Client)(*KubernetesStore,error){
 u,e:=url.Parse(endpoint)
 if e!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!=""||!identityPattern.MatchString(namespace)||client==nil{return nil,ErrInvalid}
 c:=*client
 c.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
 return &KubernetesStore{strings.TrimSuffix(endpoint,"/"),namespace,&c},nil
}
func(s *KubernetesStore) name(tenant,cluster,profile string)string{
 h:=sha256.Sum256([]byte(tenant+"\x00"+cluster+"\x00"+profile))
 return "ok-authority-"+hex.EncodeToString(h[:16])
}
func(s *KubernetesStore) path(name string)string{
 p:=s.endpoint+"/api/v1/namespaces/"+s.namespace+"/configmaps"
 if name!=""{return p+"/"+name};return p
}
func(s *KubernetesStore) request(ctx context.Context,method,path string,body []byte)(int,[]byte,error){
 var reader io.Reader
 if body!=nil{reader=bytes.NewReader(body)}
 req,e:=http.NewRequestWithContext(ctx,method,path,reader);if e!=nil{return 0,nil,ErrUnverifiable}
 req.Header.Set("Accept","application/json")
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=s.client.Do(req);if e!=nil{return 0,nil,ErrUnverifiable}
 defer resp.Body.Close()
 if resp.Request==nil||resp.Request.URL==nil||resp.Request.URL.Scheme!="https"||resp.Request.URL.Host!=req.URL.Host{return 0,nil,ErrUnverifiable}
 raw,e:=io.ReadAll(io.LimitReader(resp.Body,131073))
 if e!=nil||len(raw)>131072{return 0,nil,ErrUnverifiable}
 return resp.StatusCode,raw,nil
}
func(s *KubernetesStore) read(ctx context.Context,name string)(authorityConfigMap,bool,error){
 code,raw,e:=s.request(ctx,http.MethodGet,s.path(name),nil);if e!=nil{return authorityConfigMap{},false,e}
 // 404 may mean deleted/recreated authority data, not a trusted ABSENT.
 // Until a separately proven fenced domain exists, fail closed.
 if code==http.StatusNotFound{return authorityConfigMap{},false,ErrUnverifiable}
 if code!=http.StatusOK{return authorityConfigMap{},false,ErrUnverifiable}
 var cm authorityConfigMap
 // Kubernetes includes additional metadata fields; validate duplicate keys
 // globally while decoding only our protected identity fields.
 var rawObject map[string]json.RawMessage
 if jsonstrict.Decode(raw,&rawObject)!=nil||json.Unmarshal(raw,&cm)!=nil{return authorityConfigMap{},false,ErrUnverifiable}
 if cm.Kind!="ConfigMap"||cm.APIVersion!="v1"||cm.Metadata.Name!=name||cm.Metadata.Namespace!=s.namespace||cm.Metadata.UID==""||cm.Metadata.ResourceVersion==""||len(cm.Data)!=1||cm.Data["state"]==""{return authorityConfigMap{},false,ErrUnverifiable}
 return cm,true,nil
}
func(s *KubernetesStore) inspect(ctx context.Context,tenant,cluster,profile string)(Snapshot,authorityConfigMap,bool,error){
 if !identityPattern.MatchString(tenant)||!identityPattern.MatchString(cluster)||!identityPattern.MatchString(profile){return Snapshot{},authorityConfigMap{},false,ErrInvalid}
 cm,found,e:=s.read(ctx,s.name(tenant,cluster,profile))
 if e!=nil{return Snapshot{},authorityConfigMap{},false,e}
 if !found{return Snapshot{Revision:Absent},authorityConfigMap{},false,nil}
 var rec authorityRecord
 if jsonstrict.Decode([]byte(cm.Data["state"]),&rec)!=nil||rec.Tenant!=tenant||rec.Cluster!=cluster||rec.Profile!=profile||rec.Snapshot.Revision==""||rec.Snapshot.Revision==Absent||rec.Snapshot.Last==nil||rec.Snapshot.Last.To!=rec.Snapshot.Revision||rec.Snapshot.Last.Tenant!=tenant||rec.Snapshot.Last.Cluster!=cluster||rec.Snapshot.Last.AuthorityProfile!=profile||rec.Snapshot.Last.Validate()!=nil{return Snapshot{},authorityConfigMap{},false,ErrUnverifiable}
 return rec.Snapshot,cm,true,nil
}
func(s *KubernetesStore) Inspect(ctx context.Context,tenant,cluster,profile string)(Snapshot,error){
 state,_,_,e:=s.inspect(ctx,tenant,cluster,profile);return state,e
}
func(s *KubernetesStore) CompareAndSwap(ctx context.Context,t Transition)(Result,error){
 if e:=t.Validate();e!=nil{return Result{},e}
 prev,cm,found,e:=s.inspect(ctx,t.Tenant,t.Cluster,t.AuthorityProfile)
 if e!=nil{return Result{Outcome:Indeterminate},e}
 if prev.Last!=nil&&*prev.Last==t&&prev.Revision==t.To{return Result{Outcome:AlreadyAccepted,State:prev},nil}
 if prev.Revision!=t.From{return Result{Outcome:PreconditionFailed,State:prev},nil}
 rec:=authorityRecord{Tenant:t.Tenant,Cluster:t.Cluster,Profile:t.AuthorityProfile,Snapshot:Snapshot{Revision:t.To,Last:&t}}
 encoded,e:=json.Marshal(rec);if e!=nil{return Result{},ErrInvalid}
 name:=s.name(t.Tenant,t.Cluster,t.AuthorityProfile)
 cmNext:=authorityConfigMap{APIVersion:"v1",Kind:"ConfigMap",Data:map[string]string{"state":string(encoded)}}
 cmNext.Metadata.Name=name;cmNext.Metadata.Namespace=s.namespace
 method,path:=http.MethodPost,s.path("")
 if found{
  method,path=http.MethodPut,s.path(name)
  cmNext.Metadata.UID=cm.Metadata.UID
  cmNext.Metadata.ResourceVersion=cm.Metadata.ResourceVersion
 }
 body,e:=json.Marshal(cmNext);if e!=nil{return Result{},ErrInvalid}
 code,_,e:=s.request(ctx,method,path,body)
 if e!=nil{return Result{Outcome:Indeterminate},e}
 if code==http.StatusConflict{return Result{Outcome:PreconditionFailed},nil}
 if (!found&&code!=http.StatusCreated)||(found&&code!=http.StatusOK){return Result{Outcome:Indeterminate},ErrUnverifiable}
 after,readCM,exists,e:=s.inspect(ctx,t.Tenant,t.Cluster,t.AuthorityProfile)
 if e!=nil||!exists||after.Last==nil||*after.Last!=t||after.Revision!=t.To{return Result{Outcome:Indeterminate},ErrUnverifiable}
 if found&&readCM.Metadata.UID!=cm.Metadata.UID{return Result{Outcome:Indeterminate},ErrUnverifiable}
 return Result{Outcome:Accepted,State:after},nil
}
var _ Store=(*KubernetesStore)(nil)
