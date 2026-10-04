package benchmark

import (
	"encoding/json"
	"strings"
	"testing"
)

// Missing negative checks, forged acceptance, leaked witness fields, or incorrect
// source/timing/artifact evidence must not qualify as a successful benchmark.
func TestBenchmarkReceiptAndAdversarialCases(t *testing.T) {
	config := Config{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), CircuitDigest: strings.Repeat("c", 64), Iterations: 2}
	receipt, err := RunBenchmark(config)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	fields := []string{"format", "status", "actual_backend_run", "backend", "circuit", "source", "parameters", "artifacts", "metrics", "cases", "claims", "unassessed"}
	if len(document) != len(fields) {
		t.Fatal("receipt top-level fields differ")
	}
	for _, field := range fields {
		if _, found := document[field]; !found {
			t.Fatalf("missing receipt field %s", field)
		}
	}
	if document["format"] != float64(1) || document["status"] != "passed" || document["actual_backend_run"] != true {
		t.Fatal("backend execution is not positively recorded")
	}
	source := document["source"].(map[string]any)
	if source["commit"] != config.Commit || source["tree"] != config.Tree || len(source) != 2 {
		t.Fatal("source identities are not exact")
	}
	circuit := document["circuit"].(map[string]any)
	if circuit["source_digest"] != config.CircuitDigest || circuit["constraints"].(float64) < 1 || circuit["private_inputs_retained"] != false {
		t.Fatal("circuit evidence is invalid")
	}
	wantCases := []string{"valid-proof", "mutated-proof", "changed-public-input", "wrong-verifying-key", "invalid-membership", "invalid-nullifier", "invalid-output-commitment", "invalid-fee-conservation", "out-of-range-value", "changed-authorization-digest"}
	cases := document["cases"].([]any)
	if len(cases) != len(wantCases) {
		t.Fatal("case inventory differs")
	}
	for i, id := range wantCases {
		expected := "reject"
		if i == 0 {
			expected = "accept"
		}
		c := cases[i].(map[string]any)
		if len(c) != 3 || c["id"] != id || c["expected"] != expected || c["observed"] != expected {
			t.Fatalf("case %s is not verified", id)
		}
	}
	metrics := document["metrics"].(map[string]any)
	if len(metrics) != 5 || metrics["compile_ns"].(float64) < 1 || metrics["setup_ns"].(float64) < 1 || metrics["iterations"] != float64(2) {
		t.Fatal("compile/setup metrics are invalid")
	}
	for _, field := range []string{"prove_ns", "verify_ns"} {
		timings := metrics[field].([]any)
		if len(timings) != 2 {
			t.Fatal("iteration inventory differs")
		}
		for _, value := range timings {
			if value.(float64) < 1 {
				t.Fatal("nonpositive duration")
			}
		}
	}
	parameters := document["parameters"].(map[string]any)
	if parameters["kind"] != "ephemeral-local-groth16-setup" || parameters["ceremony"] != false || parameters["reusable"] != false || parameters["production"] != false {
		t.Fatal("ephemeral setup boundary differs")
	}
	checkArtifacts := func(record map[string]any, fields []string) {
		t.Helper()
		for _, field := range fields {
			value, ok := record[field].(string)
			if !ok || len(value) != 64 || strings.Trim(value, "0123456789abcdef") != "" {
				t.Fatal("artifact hash is invalid")
			}
			size := strings.TrimSuffix(field, "sha256") + "bytes"
			if record[size].(float64) < 1 {
				t.Fatal("artifact size is invalid")
			}
		}
	}
	checkArtifacts(parameters, []string{"proving_key_sha256", "verifying_key_sha256"})
	artifacts := document["artifacts"].(map[string]any)
	checkArtifacts(artifacts, []string{"proof_sha256", "public_witness_sha256"})
	if len(parameters) != 8 || len(artifacts) != 4 {
		t.Fatal("serialized key/proof bytes were added to the receipt")
	}
	claims := document["claims"].(map[string]any)
	if len(claims) != 6 {
		t.Fatal("claim inventory differs")
	}
	for _, value := range claims {
		if value != false {
			t.Fatal("unsupported safety claim")
		}
	}
	if len(document["unassessed"].([]any)) != 7 {
		t.Fatal("unassessed inventory differs")
	}
	for _, forbidden := range []string{"SpendSecret", "NoteSecret", "Path", "InputBlinding", "OutputKey", "witness_secret", "proof_base64", "proving_key_base64", "verifying_key_base64"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private or serialized evidence leaked")
		}
	}
}
