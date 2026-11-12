package desiredauthority

import (
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"
)

// Structural guard only: it cannot prove Kubernetes admission behavior.
// The opt-in Kind conformance script must be exercised on a disposable cluster.
func TestAuthorityAdmissionKindHarnessSafetyBoundary(t *testing.T) {
 _,filename,_,ok:=runtime.Caller(0);if !ok{t.Fatal("source location unavailable")}
 script:=filepath.Join(filepath.Dir(filename),"..","..","scripts","ok226-admission-conformance-kind.sh")
 raw,err:=os.ReadFile(script);if err!=nil{t.Fatal(err)}
 s:=string(raw)
 expected:=[]string{
  "set -euo pipefail",
  "OK226_ALLOW_DISPOSABLE_KIND",
  "kind get clusters",
  "kind create cluster --name",
  "kind delete cluster --name",
  "kubectl --context",
  "ok226-authority-freeze-candidate.yaml",
  "expect_admission_denied",
  "ok226-authority-record-freeze",
  "ok226-authority-namespace-freeze",
  "create configmap ok226-test-new",
  "patch configmap ok226-test-record",
  "delete configmap ok226-test-record",
  "delete configmap ok226-test-fence",
  "delete namespace",
  "auth can-i",
  "ok226-test-executor",
  "ok226-test-observer",
  "jsonpath='{.metadata.uid}'",
 }
 for _,token:=range expected{if !strings.Contains(s,token){t.Errorf("conformance harness lacks %q",token)}}
 for _,forbidden:=range []string{"kubectl config use-context","kubectl config set-context","kubectl config delete-context","kind delete clusters --all","kubectl --context ${KUBECONFIG}"}{
  if strings.Contains(s,forbidden){t.Errorf("unsafe operation %q",forbidden)}
 }
}
