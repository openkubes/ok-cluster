package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

// operatorUpSteps lets the bounded operator UX call the existing CLI code,
// without a second provisioning implementation or a new authority.
type operatorUpSteps struct {
	plan func([]string, io.Writer, io.Writer) error
	provision func(context.Context, []string, io.Reader, io.Writer, io.Writer) error
}

// runOperatorUp is an explicitly selected trusted-operator workflow,
// NOT the ADR-034 authorized desired-state convergence contract.
// The existing provision command remains responsible for all target checks,
// two deliberate confirmations, make stages, failure retention and readiness.
func runOperatorUp(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runOperatorUpWithSteps(ctx,args,stdin,stdout,stderr,operatorUpSteps{
		plan:runClusterPlan,provision:runClusterProvision,
	})
}

func runOperatorUpWithSteps(ctx context.Context,args []string,stdin io.Reader,stdout,stderr io.Writer,steps operatorUpSteps) error {
	flags:=flag.NewFlagSet("ok up",flag.ContinueOnError)
	flags.SetOutput(stderr)
	var input clusterPlanInputFlag
	flags.Var(&input,"f","ClusterRequest YAML for trusted operator provisioning")
	flags.Var(&input,"file","ClusterRequest YAML for trusted operator provisioning")
	mode:=flags.String("mode","","required: operator (ADR-034 convergence remains unavailable)")
	topology:=flags.String("topology","","required: same-plane")
	workload:=flags.String("workload-kubeconfig","","private output path for workload kubeconfig")
	if err:=flags.Parse(args);err!=nil{return err}
	if flags.NArg()!=0 || !input.set || input.value=="" || *mode!="operator" ||
		*topology!="same-plane" || *workload=="" {
		return errors.New("operator up requires exactly one -f/--file, --mode operator, --topology same-plane and --workload-kubeconfig <private-output>; no implicit defaults")
	}
	if steps.plan==nil||steps.provision==nil{return errors.New("operator up unavailable: missing reviewed CLI steps")}
	if err:=ctx.Err();err!=nil{return err}
	// Preview is informative only, not an approval. Re-read, verify and compare
	// all inputs inside the existing provision command before mutation.
	if err:=steps.plan([]string{"--file",input.value},stdout,stderr);err!=nil{
		return fmt.Errorf("operator up stopped before provisioning: %w",err)
	}
	if err:=ctx.Err();err!=nil{return err}
	fmt.Fprintln(stdout,"Operator plan is informational only; provisioning will re-validate all sources and require two explicit confirmations.")
	return steps.provision(ctx,[]string{"--file",input.value,"--topology","same-plane",
		"--workload-kubeconfig",*workload},stdin,stdout,stderr)
}
