package main

import (
 "context"
 "errors"
 "io"
 "path/filepath"
 "strings"
 "testing"
)

func TestNonLifecycleSourcePinIsExplicitAndImmutable(t *testing.T) {
 if len(clusterProvisionReviewedNonLifecycleRev)!=40 || len(clusterProvisionReviewedNonLifecyclePaths)!=30 {
  t.Fatal("reviewed commit or frozen list changed; needs new audit")
 }
 seen:=map[string]bool{}
 for _,p:=range clusterProvisionReviewedNonLifecyclePaths {
  if seen[p] || p=="" || filepath.IsAbs(p) || filepath.Clean(p)!=p ||
   strings.ContainsAny(p,"*?[]:") || strings.HasPrefix(p,"..") {
   t.Fatalf("unsafe/non-exact reviewed path %q",p)
  }
  seen[p]=true
 }
}

func TestNonLifecycleSourceVerificationFailsClosed(t *testing.T) {
 for _,fail:=range []bool{false,true} {
  called:=0
  runtime:=clusterProvisionRuntime{
   toolPaths:map[string]string{"git":"/private/git"},
   command:func(_ context.Context,exe string,args []string,dir string,_ []string,_,_ io.Writer)error{
    called++
    if exe!="/private/git" || dir!="/reviewed/ok-cluster"{
     t.Fatalf("unexpected tool/cwd %s %s",exe,dir)
    }
    combined:=strings.Join(args," ")
    if !strings.Contains(combined,"diff --quiet --no-ext-diff --no-textconv "+clusterProvisionReviewedNonLifecycleRev+" --") {
     t.Fatalf("unpinned verification: %q",combined)
    }
    if !strings.Contains(combined," "+clusterProvisionReviewedNonLifecyclePaths[0]+" "){
     t.Fatal("missing exact pinned paths")
    }
    if fail{return errors.New("changed pinned source")}
    return nil
   },
  }
  err:=verifyProvisionNonLifecycleSource(context.Background(),runtime,"/reviewed/ok-cluster")
  if called!=1 {t.Fatalf("verification calls=%d",called)}
  if fail && (err==nil || !strings.Contains(err.Error(),"differs from the pinned reviewed revision")) {
   t.Fatalf("tamper allowed: %v",err)
  }
  if !fail && err!=nil {t.Fatalf("unexpected rejection: %v",err)}
 }
}
