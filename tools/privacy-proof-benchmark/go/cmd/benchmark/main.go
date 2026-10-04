package main

import (
	"os"

	benchmark "github.com/EternitiesAi/1soft/tools/privacy-proof-benchmark"
)

func main() {
	os.Exit(benchmark.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
