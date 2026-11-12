// Package desiredauthority defines desired-state CAS semantics for ADR-034.
// It has no Kubernetes client, signer, or executor and grants no authority.
package desiredauthority

import (
 "context"
 "errors"
 "regexp"
)

type Revision string
const (
 Absent Revision = "ABSENT"
 DesiredAbsent Revision = "DESIRED_ABSENT"
)
const (
 Accepted = "ACCEPTED"
 PreconditionFailed = "PRECONDITION_FAILED"
 AlreadyAccepted = "ALREADY_ACCEPTED"
 Indeterminate = "INDETERMINATE"
)
var ErrInvalid = errors.New("desired-state authority: invalid transition identity")
var ErrUnverifiable = errors.New("desired-state authority: store result cannot be verified")
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var identityPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type Transition struct {
 Tenant string
 Cluster string
 AuthorityProfile string
 TransitionID string
 From Revision
 To Revision
 Operation string
 RequestDigest string
 ExecutionBindingDigest string
 AuthorizationDigest string
}
// Snapshot records the authoritative revision and its exact last accepted tuple.
type Snapshot struct {
 Revision Revision
 Last *Transition
}
type Result struct {
 Outcome string
 State Snapshot
}
// Store requires a linearizable full-tuple compare-and-swap, atomic immutable
// correlation, independent inspection, and deployment-proven anti-rollback/fencing.
// The interface does not implement or certify any Kubernetes storage safeguards.
type Store interface {
 Inspect(context.Context,string,string,string)(Snapshot,error)
 CompareAndSwap(context.Context,Transition)(Result,error)
}
func (t Transition) Validate() error {
 if !identityPattern.MatchString(t.Tenant) || !identityPattern.MatchString(t.Cluster) ||
  !identityPattern.MatchString(t.AuthorityProfile) || t.TransitionID == "" ||
  !digestPattern.MatchString(t.RequestDigest) ||
  !digestPattern.MatchString(t.ExecutionBindingDigest) ||
  !digestPattern.MatchString(t.AuthorizationDigest) {return ErrInvalid}
 if t.From != Absent && t.From != DesiredAbsent && !digestPattern.MatchString(string(t.From)) {return ErrInvalid}
 if t.To != DesiredAbsent && !digestPattern.MatchString(string(t.To)) {return ErrInvalid}
 if t.From == t.To {return ErrInvalid}
 switch t.Operation {
 case "CreateCluster":
  if t.From != Absent || t.To == DesiredAbsent {return ErrInvalid}
 case "DeleteCluster":
  if t.From == Absent || t.From == DesiredAbsent || t.To != DesiredAbsent {return ErrInvalid}
 default:
  // Scale, Upgrade, Adopt and rollback are not authorized by this slice.
  return ErrInvalid
 }
 return nil
}
// ReconcileIndeterminate is strictly read-only. A lost response never licenses
// replay. An exact tuple+revision match is evidence of prior acceptance.
func ReconcileIndeterminate(ctx context.Context, store Store, attempted Transition)(Result,error){
 if err:=attempted.Validate();err!=nil{return Result{},err}
 snapshot,err:=store.Inspect(ctx,attempted.Tenant,attempted.Cluster,attempted.AuthorityProfile)
 if err!=nil{return Result{Outcome:Indeterminate},ErrUnverifiable}
 if snapshot.Last!=nil && *snapshot.Last==attempted && snapshot.Revision==attempted.To{
  return Result{Outcome:AlreadyAccepted,State:snapshot},nil
 }
 return Result{Outcome:Indeterminate,State:snapshot},ErrUnverifiable
}
