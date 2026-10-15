package stageplan

import "testing"

func TestRecoveryPlanRequiresIndependentSourceAndBareSevenStageScope(t *testing.T) {
	doc := validDocument()
	doc.Format = FormatRecovery
	doc.Stages = doc.Stages[:7]
	doc.CompletionMode = CompletionModeBareClusterMVP
	doc.RecoverySourcePlanDigest = sha("f")
	e := expected()
	e.CompletionMode = CompletionModeBareClusterMVP
	if _, err := Verify(planJSON(t, doc), e); err == nil {
		t.Fatal("recovery accepted without independently bound source")
	}
	e.RecoverySourcePlanDigest = doc.RecoverySourcePlanDigest
	plan, err := Verify(planJSON(t, doc), e)
	if err != nil {
		t.Fatal(err)
	}
	plan.RecoverySourcePlanDigest = sha("e")
	if _, _, err := plan.Stage("target-access"); err == nil {
		t.Fatal("recovery source mutated after verification")
	}
	full := validDocument()
	full.Format, full.RecoverySourcePlanDigest = FormatRecovery, doc.RecoverySourcePlanDigest
	full.CompletionMode = CompletionModeBareClusterMVP
	if _, err := Verify(planJSON(t, full), e); err == nil {
		t.Fatal("recovery broadened to twelve stages")
	}
	doc.Format = Format
	if _, err := Verify(planJSON(t, doc), e); err == nil {
		t.Fatal("ordinary plan accepted recovery fields")
	}
}
