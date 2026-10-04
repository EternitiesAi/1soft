package benchmark

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cliArguments(report string) []string {
	return []string{"--report", report, "--commit", strings.Repeat("a", 40), "--tree", strings.Repeat("b", 40), "--circuit-digest", strings.Repeat("c", 64), "--iterations", "1"}
}

// Rejected flags must not execute the backend, create a report, or emit a pass.
func TestCLIRejectsInvalidArguments(t *testing.T) {
	report := filepath.Join(t.TempDir(), "receipt.json")
	valid := cliArguments(report)
	invalid := [][]string{
		{}, {"--report", report},
		append(append([]string{}, valid...), "unexpected"),
		append(append([]string{}, valid...), "--iterations", "0"),
		append(append([]string{}, valid...), "--iterations", "11"),
		append(append([]string{}, valid...), "--commit", strings.Repeat("A", 40)),
		append(append([]string{}, valid...), "--tree", strings.Repeat("b", 39)),
		append(append([]string{}, valid...), "--circuit-digest", strings.Repeat("c", 63)),
		append(append([]string{}, valid...), "--unknown"),
	}
	for _, arguments := range invalid {
		var stdout, stderr bytes.Buffer
		if RunCLI(arguments, &stdout, &stderr) == 0 {
			t.Fatal("invalid arguments were accepted")
		}
		if stdout.Len() != 0 {
			t.Fatal("invalid invocation emitted success output")
		}
		if _, err := os.Lstat(report); !os.IsNotExist(err) {
			t.Fatal("invalid invocation created a report")
		}
	}
}

// Opening the report must be exclusive, preserving regular files and symlinks.
func TestCLIRefusesExistingReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "receipt.json")
	contents := []byte("existing receipt must survive")
	if err := os.WriteFile(report, contents, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if RunCLI(cliArguments(report), &stdout, &stderr) == 0 {
		t.Fatal("existing report was overwritten")
	}
	after, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, contents) || stdout.Len() != 0 {
		t.Fatal("existing report was changed")
	}
	link := filepath.Join(dir, "receipt-link.json")
	if err := os.Symlink(report, link); err != nil {
		t.Fatal(err)
	}
	if RunCLI(cliArguments(link), &stdout, &stderr) == 0 {
		t.Fatal("report symlink was followed")
	}
	after, err = os.ReadFile(report)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatal("symlink target was changed")
	}
	dangling := filepath.Join(dir, "dangling.json")
	target := filepath.Join(dir, "absent.json")
	if err := os.Symlink(target, dangling); err != nil {
		t.Fatal(err)
	}
	if RunCLI(cliArguments(dangling), &stdout, &stderr) == 0 {
		t.Fatal("dangling report symlink was followed")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("dangling symlink target was created")
	}
}

// The real CLI must persist only receipt evidence and emit only its compact result.
func TestCLIWritesExclusiveReceipt(t *testing.T) {
	report := filepath.Join(t.TempDir(), "receipt.json")
	var stdout, stderr bytes.Buffer
	if RunCLI(cliArguments(report), &stdout, &stderr) != 0 {
		t.Fatalf("CLI failed: %s", stderr.String())
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "passed" || !receipt.ActualBackendRun || len(receipt.Cases) != 10 || receipt.Metrics.Iterations != 1 {
		t.Fatal("CLI did not write actual proof evidence")
	}
	if receipt.Source.Commit != strings.Repeat("a", 40) || receipt.Source.Tree != strings.Repeat("b", 40) || receipt.Circuit.SourceDigest != strings.Repeat("c", 64) {
		t.Fatal("CLI identities differ from its validated flags")
	}
	info, err := os.Stat(report)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt file permissions are not private")
	}
	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal("stdout contains backend logs or private bytes")
	}
	if len(summary) != 3 || summary["status"] != "passed" || summary["cases"] != float64(10) || summary["iterations"] != float64(1) || stderr.Len() != 0 {
		t.Fatal("CLI output includes unsupported evidence")
	}
}
