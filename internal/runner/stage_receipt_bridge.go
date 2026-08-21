package runner

import (
	"context"
	"errors"
	"os"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
)

type StageRunReceiptReference struct {
	Format             string
	State              string
	PlanDigest         string
	StageID            string
	StageReceiptDigest string
}

type StageReceiptBridgeConfig struct {
	Bundle StageResumeConfig
	Ledger *ledger.Ledger
	Run    StageRunReceiptReference
}

type VerifiedStageReceiptMaterial struct {
	raw      []byte
	digest   string
	stageID  string
	verified bool
}

func StagedOperationReceiptReference(receipt execution.StagedOperationReceipt) StageRunReceiptReference {
	return StageRunReceiptReference{
		Format: receipt.Format, State: receipt.State, PlanDigest: receipt.PlanDigest,
		StageID: receipt.StageID, StageReceiptDigest: receipt.StageReceiptDigest,
	}
}

func ObservationStageReceiptReference(receipt execution.ObservationStageRunReceipt) StageRunReceiptReference {
	return StageRunReceiptReference{
		Format: receipt.Format, State: receipt.State, PlanDigest: receipt.PlanDigest,
		StageID: receipt.StageID, StageReceiptDigest: receipt.StageReceiptDigest,
	}
}

func BindingStageReceiptReference(receipt execution.BindingStageRunReceipt) StageRunReceiptReference {
	return StageRunReceiptReference{
		Format: receipt.Format, State: receipt.State, PlanDigest: receipt.PlanDigest,
		StageID: receipt.StageID, StageReceiptDigest: receipt.StageReceiptDigest,
	}
}

// LoadStageReceiptMaterial reads exactly one independently digest-bound,
// already durable redaction-safe stage receipt. It never reconstructs private
// credential material and performs no source-authority request.
func LoadStageReceiptMaterial(ctx context.Context, config StageReceiptBridgeConfig) (VerifiedStageReceiptMaterial, error) {
	if config.Ledger == nil || config.Run.State != "COMPLETED_SUCCEEDED" ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Run.PlanDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.Run.StageReceiptDigest) {
		return VerifiedStageReceiptMaterial{}, errors.New("stage receipt bridge input is invalid")
	}
	plan, cursor, _, err := loadStageResumeWithPrefix(config.Bundle)
	if err != nil {
		return VerifiedStageReceiptMaterial{}, errors.New("verify stage receipt bridge prefix")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != config.Run.StageID || config.Run.PlanDigest != plan.PlanDigest {
		return VerifiedStageReceiptMaterial{}, errors.New("stage receipt bridge differs from verified cursor")
	}
	if config.Run.Format != runReceiptFormatForStageKind(decision.Kind) {
		return VerifiedStageReceiptMaterial{}, errors.New("stage receipt bridge run format differs from stage kind")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedStageReceiptMaterial{}, errors.New("load stage receipt bridge predecessors")
	}
	verified, err := config.Ledger.LoadStageReceipt(ctx, plan, decision.StageID, config.Run.StageReceiptDigest, predecessors)
	if err != nil {
		return VerifiedStageReceiptMaterial{}, errors.New("load durable stage receipt for bridge")
	}
	raw, err := verified.Bytes()
	if err != nil || digest.SHA256(raw) != config.Run.StageReceiptDigest {
		return VerifiedStageReceiptMaterial{}, errors.New("durable stage receipt bridge identity changed")
	}
	return VerifiedStageReceiptMaterial{
		raw: append([]byte(nil), raw...), digest: config.Run.StageReceiptDigest,
		stageID: decision.StageID, verified: true,
	}, nil
}

func runReceiptFormatForStageKind(kind string) string {
	switch kind {
	case "Submission", "Credential":
		return execution.StagedReceiptFormat
	case "Observation":
		return execution.ObservationStageReceiptFormat
	case "Binding":
		return execution.BindingStageReceiptFormat
	case "Evaluation":
		return execution.EvaluationStageReceiptFormat
	default:
		return ""
	}
}

func (material VerifiedStageReceiptMaterial) Bytes() ([]byte, error) {
	if !material.verified || material.stageID == "" || !stageReceiptPrefixDigestPattern.MatchString(material.digest) || digest.SHA256(material.raw) != material.digest {
		return nil, errors.New("stage receipt bridge material is unverified")
	}
	return append([]byte(nil), material.raw...), nil
}

// Persist creates one exclusive 0600 redaction-safe receipt file below an
// existing private directory and returns the exact source for the next bundle.
// It has no overwrite or cleanup path.
func (material VerifiedStageReceiptMaterial) Persist(path string) (StageReceiptSource, error) {
	raw, err := material.Bytes()
	if err != nil {
		return StageReceiptSource{}, err
	}
	if err := validateRuntimeBindingOutputPath(path); err != nil {
		return StageReceiptSource{}, errors.New("stage receipt bridge output path is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return StageReceiptSource{}, errors.New("create exclusive stage receipt bridge output")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return StageReceiptSource{}, errors.New("write stage receipt bridge output")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return StageReceiptSource{}, errors.New("sync stage receipt bridge output")
	}
	if err := file.Close(); err != nil {
		return StageReceiptSource{}, errors.New("close stage receipt bridge output")
	}
	stored, err := readBoundedRegular(path, int64(len(raw)))
	if err != nil || digest.SHA256(stored) != material.digest {
		return StageReceiptSource{}, errors.New("persisted stage receipt bridge output differs")
	}
	return StageReceiptSource{Path: path, Digest: material.digest}, nil
}
