package desiredauthority

import (
 "bytes"
 "context"
 "encoding/json"
 "io"
 "mime"
 "net/http"

 "github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// KubernetesClaimStore is an ISOLATED adapter candidate. Domain checks are
// read-only brackets, NOT an atomic server-side fence. It cannot guarantee
// anti-deletion, anti-rollback or durable single use. Never deploy as writer.
type KubernetesClaimStore struct {
 reader *PinnedDomainReader
 binding DomainBinding
}

func NewKubernetesClaimStore(c PinnedDomainReaderConfig)(*KubernetesClaimStore,error){
 reader,err:=NewPinnedDomainReader(c)
 if err!=nil{return nil,ErrClaimUnverifiable}
 return &KubernetesClaimStore{reader:reader,binding:c.Binding},nil
}

func(s *KubernetesClaimStore) guard(ctx context.Context)error{
 if s==nil||s.reader==nil||VerifyDomain(ctx,s.binding,s.reader)!=nil{return ErrClaimUnverifiable}
 return nil
}

func claimConfigMapName(slot string)(string,error){
 if !digestPattern.MatchString(slot){return "",ErrClaimUnverifiable}
 // ConfigMap names support DNS subdomains; avoid a >63-byte label.
 return "ok226-claim-"+slot[7:39]+"."+slot[39:],nil
}

type claimKubernetesMetadata struct {
 Name string `json:"name"`
 Namespace string `json:"namespace"`
 UID string `json:"uid,omitempty"`
 ResourceVersion string `json:"resourceVersion,omitempty"`
 Labels map[string]string `json:"labels,omitempty"`
 Annotations map[string]string `json:"annotations,omitempty"`
 DeletionTimestamp json.RawMessage `json:"deletionTimestamp,omitempty"`
 OwnerReferences []json.RawMessage `json:"ownerReferences,omitempty"`
}
type claimKubernetesObject struct{
 APIVersion string `json:"apiVersion"`
 Kind string `json:"kind"`
 Metadata claimKubernetesMetadata `json:"metadata"`
 Immutable bool `json:"immutable"`
 Data map[string]string `json:"data"`
}

func(s *KubernetesClaimStore) object(slot string,record ClaimRecord)(claimKubernetesObject,error){
 name,err:=claimConfigMapName(slot)
 if err!=nil||!validateClaimRecord(record)||record.SlotDigest!=slot||
 record.DomainDigest!=s.binding.ExpectedDomainDigest{return claimKubernetesObject{},ErrClaimUnverifiable}
 raw,err:=json.Marshal(record)
 if err!=nil||len(raw)>32768{return claimKubernetesObject{},ErrClaimUnverifiable}
 return claimKubernetesObject{
  APIVersion:"v1",Kind:"ConfigMap",Immutable:true,
  Metadata:claimKubernetesMetadata{Name:name,Namespace:s.binding.AuthorityNamespace,
   Labels:map[string]string{"app.kubernetes.io/managed-by":"ok226-authority-claim-candidate"},
   Annotations:map[string]string{"openkubes.io/claim-slot":slot,"openkubes.io/domain":record.DomainDigest,
    "openkubes.io/namespace-uid":s.binding.NamespaceUID}},
  Data:map[string]string{"claim.json":string(raw)},
 },nil
}

func(s *KubernetesClaimStore) request(ctx context.Context,method,path string,body []byte)(int,[]byte,error){
 req,err:=http.NewRequestWithContext(ctx,method,s.reader.endpoint+path,bytes.NewReader(body))
 if err!=nil{return 0,nil,ErrClaimUnverifiable}
 req.GetBody=nil // explicitly disable automatic replay for POST
 req.Header.Set("Authorization","Bearer "+s.reader.token)
 req.Header.Set("Accept","application/json")
 req.Header.Set("Cache-Control","no-cache")
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 resp,err:=s.reader.client.Do(req)
 if err!=nil{return 0,nil,ErrClaimUnverifiable}
 defer resp.Body.Close()
 media,_,err:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
 if err!=nil||media!="application/json"{return 0,nil,ErrClaimUnverifiable}
 raw,err:=io.ReadAll(io.LimitReader(resp.Body,65537))
 if err!=nil||len(raw)>65536{return 0,nil,ErrClaimUnverifiable}
 return resp.StatusCode,raw,nil
}

func(s *KubernetesClaimStore) verifyObject(raw []byte,slot string)(ClaimRecord,error){
 // jsonstrict rejects duplicate keys; reject case-shadowing on protected fields.
 fields,err:=domainExactFieldKeys(raw,[]string{"apiVersion","kind","metadata","immutable","data","binaryData"},false)
 if err!=nil||string(fields["apiVersion"])!=`"v1"`||string(fields["kind"])!=`"ConfigMap"`||string(fields["immutable"])!="true"{
  return ClaimRecord{},ErrClaimUnverifiable
 }
 if v,exists:=fields["binaryData"];exists&&string(bytes.TrimSpace(v))!="null"&&string(bytes.TrimSpace(v))!="{}"{
  return ClaimRecord{},ErrClaimUnverifiable
 }
 meta,err:=domainExactFieldKeys(fields["metadata"],[]string{"name","namespace","uid","resourceVersion","labels","annotations","deletionTimestamp","ownerReferences"},true)
 if err!=nil{return ClaimRecord{},ErrClaimUnverifiable}
 if v,ok:=meta["deletionTimestamp"];ok&&string(bytes.TrimSpace(v))!="null"{return ClaimRecord{},ErrClaimUnverifiable}
 var object claimKubernetesObject
 if json.Unmarshal(raw,&object)!=nil||!safeDomainID(object.Metadata.UID)||
 !safeDomainID(object.Metadata.ResourceVersion)||len(object.Metadata.OwnerReferences)!=0||
 len(object.Data)!=1||object.Data["claim.json"]==""{
  return ClaimRecord{},ErrClaimUnverifiable
 }
 var record ClaimRecord
 payload:=[]byte(object.Data["claim.json"])
 if len(payload)>32768||jsonstrict.Decode(payload,&record)!=nil||!validateClaimRecord(record)||
 record.SlotDigest!=slot||record.DomainDigest!=s.binding.ExpectedDomainDigest{
  return ClaimRecord{},ErrClaimUnverifiable
 }
 canonical,err:=json.Marshal(record)
 if err!=nil||!bytes.Equal(payload,canonical){return ClaimRecord{},ErrClaimUnverifiable}
 expected,err:=s.object(slot,record)
 if err!=nil||object.Metadata.Name!=expected.Metadata.Name||
 object.Metadata.Namespace!=expected.Metadata.Namespace||
 !object.Immutable||len(object.Metadata.Labels)!=len(expected.Metadata.Labels)||
 len(object.Metadata.Annotations)!=len(expected.Metadata.Annotations){
  return ClaimRecord{},ErrClaimUnverifiable
 }
 for k,v:=range expected.Metadata.Labels{if object.Metadata.Labels[k]!=v{return ClaimRecord{},ErrClaimUnverifiable}}
 for k,v:=range expected.Metadata.Annotations{if object.Metadata.Annotations[k]!=v{return ClaimRecord{},ErrClaimUnverifiable}}
 return record,nil
}
func(s *KubernetesClaimStore) collection()string{
 return "/api/v1/namespaces/"+s.binding.AuthorityNamespace+"/configmaps"
}

func(s *KubernetesClaimStore) CreateIfAbsent(ctx context.Context,slot string,record ClaimRecord)(ClaimWriteOutcome,error){
 if s==nil{return ClaimIndeterminate,ErrClaimUnverifiable}
 object,err:=s.object(slot,record)
 if err!=nil||s.guard(ctx)!=nil{return ClaimIndeterminate,ErrClaimUnverifiable}
 body,err:=json.Marshal(object)
 if err!=nil{return ClaimIndeterminate,ErrClaimUnverifiable}
 status,raw,err:=s.request(ctx,http.MethodPost,s.collection(),body)
 if err!=nil{return ClaimIndeterminate,ErrClaimUnverifiable}
 // Bracketing does not close TOCTOU; this is only a limited adapter prototype.
 if s.guard(ctx)!=nil{return ClaimIndeterminate,ErrClaimUnverifiable}
 if status==http.StatusConflict {
  var result struct{
   APIVersion string `json:"apiVersion"`
   Kind string `json:"kind"`
   Reason string `json:"reason"`
   Code int `json:"code"`
   Details struct{Name string `json:"name"`;Kind string `json:"kind"`} `json:"details"`
  }
  if jsonstrict.Decode(raw,&result)==nil&&result.APIVersion=="v1"&&result.Kind=="Status"&&
   result.Reason=="AlreadyExists"&&result.Code==409&&result.Details.Kind=="configmaps"&&result.Details.Name==object.Metadata.Name {
   return ClaimConflict,nil
  }
  return ClaimIndeterminate,ErrClaimUnverifiable
 }
 if status!=http.StatusCreated{return ClaimIndeterminate,ErrClaimUnverifiable}
 observed,err:=s.verifyObject(raw,slot)
 if err!=nil||observed!=record{return ClaimIndeterminate,ErrClaimUnverifiable}
 return ClaimCreated,nil
}

func(s *KubernetesClaimStore) InspectClaim(ctx context.Context,slot string)(ClaimRecord,bool,error){
 if s==nil||s.guard(ctx)!=nil{return ClaimRecord{},false,ErrClaimUnverifiable}
 name,err:=claimConfigMapName(slot)
 if err!=nil{return ClaimRecord{},false,ErrClaimUnverifiable}
 status,raw,err:=s.request(ctx,http.MethodGet,s.collection()+"/"+name,nil)
 if err!=nil||s.guard(ctx)!=nil{return ClaimRecord{},false,ErrClaimUnverifiable}
 // Missing is *never* trustworthy ABSENT: delete/recreate/rollback is not fenced.
 if status!=http.StatusOK{return ClaimRecord{},false,ErrClaimUnverifiable}
 record,err:=s.verifyObject(raw,slot)
 if err!=nil{return ClaimRecord{},false,ErrClaimUnverifiable}
 return record,true,nil
}

var _ ClaimStore=(*KubernetesClaimStore)(nil)
