package benchmark

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// RunCLI validates identities before doing any work and reserves the report
// exclusively before paying for setup or proof generation. Existing paths,
// including dangling symlinks, are refused by O_CREATE|O_EXCL.
func RunCLI(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("privacy-proof-benchmark", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reportPath := flags.String("report", "", "new receipt file")
	var config Config
	flags.StringVar(&config.Commit, "commit", "", "exact lowercase 40-character commit identity")
	flags.StringVar(&config.Tree, "tree", "", "exact lowercase 40-character tree identity")
	flags.StringVar(&config.CircuitDigest, "circuit-digest", "", "exact lowercase 64-character circuit source digest")
	flags.IntVar(&config.Iterations, "iterations", 3, "proof/verification iterations (1 to 10)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *reportPath == "" {
		fmt.Fprintln(stderr, "invalid benchmark arguments")
		return 1
	}
	if err := config.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	report, err := os.OpenFile(*reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(stderr, "could not exclusively create a new receipt file")
		return 1
	}
	defer report.Close()
	receipt, err := RunBenchmark(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(report).Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "could not write benchmark receipt")
		return 1
	}
	if err := report.Sync(); err != nil {
		fmt.Fprintln(stderr, "could not synchronize benchmark receipt")
		return 1
	}
	if err := report.Close(); err != nil {
		fmt.Fprintln(stderr, "could not close benchmark receipt")
		return 1
	}
	summary := struct {
		Status     string `json:"status"`
		Cases      int    `json:"cases"`
		Iterations int    `json:"iterations"`
	}{Status: "passed", Cases: len(receipt.Cases), Iterations: config.Iterations}
	if err := json.NewEncoder(stdout).Encode(summary); err != nil {
		fmt.Fprintln(stderr, "could not write benchmark result")
		return 1
	}
	return 0
}
