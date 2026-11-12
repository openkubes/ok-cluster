package desiredauthority

import (
 "bytes"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "testing"

 "gopkg.in/yaml.v3"
)

// These tests inspect the candidate manifest offline. They do NOT execute
// Kubernetes CEL, prove admission rollout or model cluster-admin bypasses.
func TestAuthorityFreezeCandidateIsDenyOnly(t *testing.T){
 _,filename,_,ok:=runtime.Caller(0);if !ok{t.Fatal("source path unavailable")}
 raw,err:=os.ReadFile(filepath.Join(filepath.Dir(filename),"..","..","deploy","ok226-authority-freeze-candidate.yaml"))
 if err!=nil{t.Fatal(err)}
 decoder:=yaml.NewDecoder(bytes.NewReader(raw))
 objects:=map[string]map[string]any{}
 for {
  var o map[string]any
  if e:=decoder.Decode(&o);e==io.EOF{break}else if e!=nil{t.Fatal(e)}
  kind,_:=o["kind"].(string)
  metadata,_:=o["metadata"].(map[string]any)
  name,_:=metadata["name"].(string)
  key:=kind+"/"+name
  if _,exists:=objects[key];exists{t.Fatalf("duplicate %s",key)}
  objects[key]=o
 }
 if len(objects)!=4{t.Fatalf("expected 2 policies and 2 bindings, got %d",len(objects))}
 for _,name:=range []string{"ok226-authority-record-freeze","ok226-authority-namespace-freeze"}{
  policyObject,exists:=objects["ValidatingAdmissionPolicy/"+name]
  if !exists{t.Fatalf("missing policy %s",name)}
  policy:=requirePolicyObject(t,policyObject,"spec")
  if policy["failurePolicy"]!="Fail"{t.Fatalf("%s does not fail closed",name)}
  conditions:=requirePolicyList(t,policy,"matchConditions")
  if len(conditions)!=1{t.Fatalf("%s has unexpected matching conditions",name)}
  c:=conditions[0].(map[string]any)
  if name=="ok226-authority-record-freeze" && c["expression"]!="request.namespace == 'openkubes-authority'"{t.Fatal("record policy namespace not pinned")}
  if name=="ok226-authority-namespace-freeze" && c["expression"]!="request.name == 'openkubes-authority'"{t.Fatal("namespace policy name not pinned")}
  validation:=requirePolicyList(t,policy,"validations")
  if len(validation)!=1||validation[0].(map[string]any)["expression"]!="false"{t.Fatalf("%s permits a mutation",name)}
  rules:=requirePolicyObject(t,requirePolicyList(t,requirePolicyObject(t,policy,"matchConstraints"),"resourceRules")[0].(map[string]any),"")
  if name=="ok226-authority-record-freeze"{
   ensureStringSet(t,rules["operations"],"CREATE","UPDATE","DELETE")
   ensureStringSet(t,rules["resources"],"configmaps")
   if rules["scope"]!="Namespaced"{t.Fatal("wrong record scope")}
  }else{
   ensureStringSet(t,rules["operations"],"UPDATE","DELETE")
   ensureStringSet(t,rules["resources"],"namespaces")
   if rules["scope"]!="Cluster"{t.Fatal("wrong namespace scope")}
  }
  bindingObject,exists:=objects["ValidatingAdmissionPolicyBinding/"+name]
  if !exists{t.Fatalf("missing binding %s",name)}
  bind:=requirePolicyObject(t,bindingObject,"spec")
  if bind["policyName"]!=name{t.Fatalf("%s binding policy mismatch",name)}
  ensureStringSet(t,bind["validationActions"],"Deny")
 }
}
func requirePolicyObject(t *testing.T,source map[string]any,key string)map[string]any{
 t.Helper()
 if key==""{return source}
 v,ok:=source[key].(map[string]any);if !ok{t.Fatalf("missing object %s",key)}
 return v
}
func requirePolicyList(t *testing.T,source map[string]any,key string)[]any{
 t.Helper()
 v,ok:=source[key].([]any);if !ok{t.Fatalf("missing list %s",key)}
 return v
}
func ensureStringSet(t *testing.T,v any,want ...string){
 t.Helper()
 vals,ok:=v.([]any);if !ok||len(vals)!=len(want){t.Fatalf("expected %v, got %v",want,v)}
 expected:=map[string]bool{};for _,x:=range want{expected[x]=true}
 for _,x:=range vals{str,ok:=x.(string);if !ok||!expected[str]{t.Fatalf("unexpected value %v in %v",x,v)};delete(expected,str)}
 if len(expected)!=0{t.Fatalf("missing %v",expected)}
}
