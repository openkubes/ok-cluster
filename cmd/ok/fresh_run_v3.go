package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/openkubes/ok-cluster/internal/runner"
)

var bindFreshRunV3 = runner.BindFreshRunV3

func runClusterStageRunFullBindV3(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full bind-v3", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publicationReceipt := flags.String("publication-receipt", "", "verified runner publication receipt")
	publicationReceiptDigest := flags.String("publication-receipt-digest", "", "exact runner publication receipt digest")
	sourceSHA := flags.String("source-sha", "", "exact published runner source SHA")
	fullRunReceipt := flags.String("full-run-package-receipt", "", "verified full-run activation package receipt")
	fullRunReceiptDigest := flags.String("full-run-package-receipt-digest", "", "exact full-run package receipt digest")
	collectorReceipt := flags.String("collector-package-receipt", "", "verified observability collector runtime package receipt")
	collectorReceiptDigest := flags.String("collector-package-receipt-digest", "", "exact collector package receipt digest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, input := range []string{*publicationReceipt, *publicationReceiptDigest, *sourceSHA, *fullRunReceipt,
		*fullRunReceiptDigest, *collectorReceipt, *collectorReceiptDigest} {
		if input == "" {
			return errors.New("all fresh-run v3 binding inputs are required")
		}
	}
	receipt, err := bindFreshRunV3(runner.FreshRunV3BindingConfig{
		PublicationReceiptPath: *publicationReceipt, ExpectedPublicationReceiptDigest: *publicationReceiptDigest,
		ExpectedSourceSHA: *sourceSHA, FullRunPackageReceiptPath: *fullRunReceipt,
		ExpectedFullRunPackageDigest: *fullRunReceiptDigest, CollectorPackageReceiptPath: *collectorReceipt,
		ExpectedCollectorPackageDigest: *collectorReceiptDigest,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}
