package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"fortik/internal/policy"
	"fortik/internal/replay"
)

const defaultCorpus = "testdata/replay/corpus.jsonl.gz"

// cmdReplay: the policy regression gate (internal/replay).
//
//	fortik replay run    [-corpus F] [-policy DIR] [-json]
//	fortik replay update [-corpus F] [-policy DIR]
//	fortik replay build  -capture F[,F...] [-n 10000] [-corpus F] [-policy DIR]
func cmdReplay(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("replay: want run | update | build")
	}
	fs := flag.NewFlagSet("replay "+args[0], flag.ExitOnError)
	corpus := fs.String("corpus", defaultCorpus, "corpus file (gzip JSON lines)")
	dir := fs.String("policy", "policies", "policy bundle directory")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	capture := fs.String("capture", "", "comma-separated "+policy.CaptureEnv+" files (build)")
	n := fs.Int("n", 10000, "corpus size (build)")
	_ = fs.Parse(args[1:])
	eng, err := policy.NewEngine(ctx, *dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	switch args[0] {
	case "run":
		recs, err := replay.Load(*corpus)
		if err != nil {
			return err
		}
		rep := replay.Run(ctx, eng, recs)
		printReport(rep, *asJSON)
		if !rep.OK() {
			return fmt.Errorf("replay: %d breaking change(s) (%d class changes), %d error(s): review the policy change, then 'fortik replay update'",
				rep.Breaking, rep.Classes, rep.Errors)
		}
		return nil
	case "update":
		recs, err := replay.Load(*corpus)
		if err != nil {
			return err
		}
		out, rep, err := replay.Update(ctx, eng, recs)
		printReport(rep, *asJSON)
		if err != nil {
			return err
		}
		if len(rep.Diffs) == 0 {
			fmt.Println("replay: nothing changed")
			return nil
		}
		if err := replay.Write(*corpus, out); err != nil {
			return err
		}
		fmt.Printf("replay: accepted %d change(s) into %s (commit it with the policy change)\n", len(rep.Diffs), *corpus)
		return nil
	case "build":
		if *capture == "" {
			return errors.New("replay build: -capture is required")
		}
		ins, err := replay.ReadCapture(strings.Split(*capture, ",")...)
		if err != nil {
			return err
		}
		recs, err := replay.Build(ctx, eng, ins, *n)
		if err != nil {
			return err
		}
		if len(recs) < *n {
			fmt.Fprintf(os.Stderr, "replay build: only %d distinct records available (asked for %d)\n", len(recs), *n)
		}
		if err := replay.Write(*corpus, recs); err != nil {
			return err
		}
		strata := map[string]int{}
		for _, r := range recs {
			strata[r.Expect.Class+" "+r.Expect.Decision]++
		}
		fmt.Printf("replay: wrote %d records (%d captured inputs) to %s; by class/decision: %v\n", len(recs), len(ins), *corpus, strata)
		return nil
	}
	return fmt.Errorf("replay: unknown subcommand %q", args[0])
}

func printReport(rep replay.Report, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("replay: %d records against policy %s: %d breaking (%d class changes), %d matched-only, %d errors\n",
		rep.Records, rep.Policy, rep.Breaking, rep.Classes, rep.Matched, rep.Errors)
	for i, d := range rep.Diffs {
		if i == 50 {
			fmt.Printf("  ... %d more\n", len(rep.Diffs)-50)
			break
		}
		tag := "matched-only"
		switch {
		case d.Err != "":
			tag = "ERROR " + d.Err
		case d.Class:
			tag = "CLASS"
		case d.Breaking:
			tag = "BEHAVIOUR"
		}
		fmt.Printf("  %-12s %s  %s: want %s/%s/%s got %s/%s/%s\n", tag, d.ID, d.Summary,
			d.Want.Class, d.Want.Decision, d.Want.RuleID, d.Got.Class, d.Got.Decision, d.Got.RuleID)
	}
}
