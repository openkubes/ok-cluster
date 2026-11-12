package main

import (
 "bytes"
 "strings"
 "testing"
)

// The complete user-facing dispatcher must route up to Operator Mode.
// Unit tests of runOperatorUp alone cannot catch command alias rewrites.
func TestOperatorUpPublicRoutingAndHelp(t *testing.T) {
 for _,args:=range [][]string{{"up","--help"},{"help","up"},{"up"}}{
  var out,errOut bytes.Buffer
  if err:=run(args,&out,&errOut);err!=nil{t.Fatalf("%v: %v",args,err)}
  if !strings.Contains(out.String(),"--mode operator")||
    !strings.Contains(out.String(),"--topology same-plane") ||
    strings.Contains(out.String(),`"ok up" is an exact shorthand`){
   t.Fatalf("%v: stale up help: %s",args,out.String())
  }
 }
 var out,errOut bytes.Buffer
 err:=run([]string{"up","--mode","operator","--topology","same-plane",
  "-f","/nonexistent-operator-request.yaml",
  "--workload-kubeconfig","/private/unused.yaml"},&out,&errOut)
 if err==nil || !strings.Contains(err.Error(),"operator up stopped before provisioning"){
  t.Fatalf("operator up did not reach plan-before-provision: %v",err)
 }
 if strings.Contains(out.String(),"Scaffold review") {t.Fatal("unexpected provisioning output")}
}

func TestOperatorUpRejectsUnsupportedExplicitMode(t *testing.T) {
 var out,errOut bytes.Buffer
 err:=run([]string{"up","--mode","convergence","-f","/nonexistent.yaml","--prepare"},&out,&errOut)
 if err==nil || !strings.Contains(err.Error(),"--mode operator"){
  t.Fatalf("unsupported explicit mode fell back to legacy Runner: err=%v output=%s",err,out.String())
 }
}

func TestLegacyUpWithoutModeStillUsesRunner(t *testing.T) {
 var out,errOut bytes.Buffer
 err:=run([]string{"up","--file","/nonexistent-legacy-manifest.json","--dry-run"},&out,&errOut)
 if err==nil || strings.Contains(err.Error(),"flag provided but not defined") || strings.Contains(err.Error(),"--mode operator") {
  t.Fatalf("legacy up compatibility broken: err=%v",err)
 }
}
