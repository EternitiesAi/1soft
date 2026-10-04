package benchmark

type Config struct {
	Commit        string
	Tree          string
	CircuitDigest string
	Iterations    int
}

type BackendReceipt struct {
	ID          string `json:"id"`
	Gnark       string `json:"gnark"`
	GnarkCrypto string `json:"gnark_crypto"`
	Curve       string `json:"curve"`
	ProofSystem string `json:"proof_system"`
	Hash        string `json:"hash"`
	License     string `json:"license"`
}

type CircuitReceipt struct {
	ID                    string   `json:"id"`
	SourceDigest          string   `json:"source_digest"`
	Constraints           int      `json:"constraints"`
	Depth                 int      `json:"depth"`
	Inputs                int      `json:"inputs"`
	Outputs               int      `json:"outputs"`
	ValueBits             int      `json:"value_bits"`
	PublicInputs          []string `json:"public_inputs"`
	PrivateInputsRetained bool     `json:"private_inputs_retained"`
}

type SourceReceipt struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

type ParameterReceipt struct {
	Kind               string `json:"kind"`
	Ceremony           bool   `json:"ceremony"`
	Reusable           bool   `json:"reusable"`
	Production         bool   `json:"production"`
	ProvingKeySHA256   string `json:"proving_key_sha256"`
	ProvingKeyBytes    int64  `json:"proving_key_bytes"`
	VerifyingKeySHA256 string `json:"verifying_key_sha256"`
	VerifyingKeyBytes  int64  `json:"verifying_key_bytes"`
}

type ArtifactReceipt struct {
	ProofSHA256         string `json:"proof_sha256"`
	ProofBytes          int64  `json:"proof_bytes"`
	PublicWitnessSHA256 string `json:"public_witness_sha256"`
	PublicWitnessBytes  int64  `json:"public_witness_bytes"`
}

type MetricReceipt struct {
	CompileNS  int64   `json:"compile_ns"`
	SetupNS    int64   `json:"setup_ns"`
	Iterations int     `json:"iterations"`
	ProveNS    []int64 `json:"prove_ns"`
	VerifyNS   []int64 `json:"verify_ns"`
}

type CaseReceipt struct {
	ID       string `json:"id"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

type ClaimReceipt struct {
	ProductionPrivacy   bool `json:"production_privacy"`
	ConsensusIntegrated bool `json:"consensus_integrated"`
	NetworkAnonymity    bool `json:"network_anonymity"`
	ProductionCustody   bool `json:"production_custody"`
	RealFunds           bool `json:"real_funds"`
	IndependentReview   bool `json:"independent_review"`
}

type Receipt struct {
	Format           int              `json:"format"`
	Status           string           `json:"status"`
	ActualBackendRun bool             `json:"actual_backend_run"`
	Backend          BackendReceipt   `json:"backend"`
	Circuit          CircuitReceipt   `json:"circuit"`
	Source           SourceReceipt    `json:"source"`
	Parameters       ParameterReceipt `json:"parameters"`
	Artifacts        ArtifactReceipt  `json:"artifacts"`
	Metrics          MetricReceipt    `json:"metrics"`
	Cases            []CaseReceipt    `json:"cases"`
	Claims           ClaimReceipt     `json:"claims"`
	Unassessed       []string         `json:"unassessed"`
}
