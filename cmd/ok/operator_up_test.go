package main

import (
 "bytes"
 "context"
 "errors"
 "io"
 "strings"
 "testing"
)

func TestOperatorUpRequiresExplicitInputsAndNeverCallsProvision(t *testing.T){
 cases:=[][]string{
  nil,{"-f","request.yaml"},{"-f","request.yaml","--mode","convergence","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml"},
  {"-f","request.yaml","--mode","operator","--workload-kubeconfig","/private/cluster.yaml"},
  {"-f","request.yaml","--mode","operator","--topology","same-plane"},
  {"-f","request.yaml","--mode","operator","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml","--unsafe"},
  {"-f","request.yaml","--file","other.yaml","--mode","operator","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml"},
 }
 for i,args:=range cases {
  planned,provisioned:=0,0
  steps:=operatorUpSteps{
   plan:func([]string,io.Writer,io.Writer)error{planned++;return nil},
   provision:func(context.Context,[]string,io.Reader,io.Writer,io.Writer)error{provisioned++;return nil},
  }
  if err:=runOperatorUpWithSteps(context.Background(),args,strings.NewReader(""),io.Discard,io.Discard,steps);err==nil {
   t.Fatalf("case %d unexpectedly accepted %v",i,args)
  }
  if planned!=0||provisioned!=0{t.Fatalf("case %d ran steps: plan=%d provision=%d",i,planned,provisioned)}
 }
}

func TestOperatorUpDelegatesOnceInOrderAndPreservesStdin(t *testing.T){
 args:=[]string{"-f","cluster.yaml","--mode","operator","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml"}
 var order []string
 var out bytes.Buffer
 steps:=operatorUpSteps{
  plan:func(got []string,_,_ io.Writer)error{
   order=append(order,"plan")
   if strings.Join(got," ")!="--file cluster.yaml"{t.Fatalf("wrong plan args: %v",got)}
   return nil
  },
  provision:func(_ context.Context,got []string,stdin io.Reader,_,_ io.Writer)error{
   order=append(order,"provision")
   if strings.Join(got," ")!="--file cluster.yaml --topology same-plane --workload-kubeconfig /private/cluster.yaml"{
    t.Fatalf("wrong provision args: %v",got)
   }
   raw,err:=io.ReadAll(stdin)
   if err!=nil||string(raw)!="provision alpha\nbootstrap alpha\n"{t.Fatalf("stdin changed: %q %v",raw,err)}
   return nil
  },
 }
 err:=runOperatorUpWithSteps(context.Background(),args,strings.NewReader("provision alpha\nbootstrap alpha\n"),&out,io.Discard,steps)
 if err!=nil{t.Fatal(err)}
 if strings.Join(order,",")!="plan,provision"{t.Fatalf("wrong ordering: %v",order)}
 if !strings.Contains(out.String(),"informational only"){t.Fatal("missing non-authorizing disclaimer")}
}

func TestOperatorUpPlanFailureAndCancellationNeverProvision(t *testing.T){
 args:=[]string{"--file","cluster.yaml","--mode","operator","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml"}
 failure:=errors.New("invalid input")
 provisioned:=false
 steps:=operatorUpSteps{
  plan:func([]string,io.Writer,io.Writer)error{return failure},
  provision:func(context.Context,[]string,io.Reader,io.Writer,io.Writer)error{provisioned=true;return nil},
 }
 err:=runOperatorUpWithSteps(context.Background(),args,nil,io.Discard,io.Discard,steps)
 if !errors.Is(err,failure)||provisioned{t.Fatalf("plan error not propagated without mutation: %v",err)}
 ctx,cancel:=context.WithCancel(context.Background())
 steps.plan=func([]string,io.Writer,io.Writer)error{cancel();return nil}
 err=runOperatorUpWithSteps(ctx,args,nil,io.Discard,io.Discard,steps)
 if !errors.Is(err,context.Canceled)||provisioned{t.Fatalf("cancellation did not block provision: %v",err)}
}

func TestOperatorUpProvisionFailurePreservedNoRetry(t *testing.T){
 args:=[]string{"-f","cluster.yaml","--mode","operator","--topology","same-plane","--workload-kubeconfig","/private/cluster.yaml"}
 failure:=errors.New("scaffold preserved; bootstrap stopped")
 calls:=0
 steps:=operatorUpSteps{
  plan:func([]string,io.Writer,io.Writer)error{return nil},
  provision:func(context.Context,[]string,io.Reader,io.Writer,io.Writer)error{calls++;return failure},
 }
 err:=runOperatorUpWithSteps(context.Background(),args,nil,io.Discard,io.Discard,steps)
 if !errors.Is(err,failure)||calls!=1{t.Fatalf("provision must run once only: %v calls=%d",err,calls)}
}
