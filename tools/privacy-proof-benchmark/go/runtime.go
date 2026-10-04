package benchmark

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"regexp"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	backendBN254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (c Config) validate() error {
	if !hex40.MatchString(c.Commit) || !hex40.MatchString(c.Tree) || !hex64.MatchString(c.CircuitDigest) {
		return errors.New("source identities must be exact lowercase hexadecimal IDs")
	}
	if c.Iterations < 1 || c.Iterations > 10 {
		return errors.New("iterations must be between 1 and 10")
	}
	return nil
}

// serializedDigest streams serialization directly into SHA-256. The caller
// retains only its digest and size, never serialized proof, witness or key bytes.
func serializedDigest(value io.WriterTo) (string, int64, error) {
	h := sha256.New()
	size, err := value.WriteTo(h)
	if err != nil || size <= 0 {
		return "", 0, errors.New("artifact serialization failed")
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// RunBenchmark owns a fresh local setup and all proof operations for this run.
// All setup keys and synthetic openings remain local to this invocation.
func RunBenchmark(config Config) (Receipt, error) {
	if err := config.validate(); err != nil {
		return Receipt{}, err
	}
	// Constraint errors can include witness-dependent values. Suppress backend
	// logging and return only fixed, non-sensitive stage descriptions.
	logger.Disable()
	started := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	compileNS := time.Since(started).Nanoseconds()
	if err != nil {
		return Receipt{}, errors.New("circuit compilation failed")
	}
	assignment, err := SyntheticFixture()
	if err != nil {
		return Receipt{}, errors.New("synthetic fixture construction failed")
	}
	full, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return Receipt{}, errors.New("synthetic witness construction failed")
	}
	public, err := full.Public()
	if err != nil {
		return Receipt{}, errors.New("public witness construction failed")
	}
	started = time.Now()
	pk, vk, err := groth16.Setup(cs)
	setupNS := time.Since(started).Nanoseconds()
	if err != nil {
		return Receipt{}, errors.New("ephemeral local setup failed")
	}
	pkHash, pkSize, err := serializedDigest(pk)
	if err != nil {
		return Receipt{}, err
	}
	vkHash, vkSize, err := serializedDigest(vk)
	if err != nil {
		return Receipt{}, err
	}
	publicHash, publicSize, err := serializedDigest(public)
	if err != nil {
		return Receipt{}, err
	}
	proveNS := make([]int64, config.Iterations)
	verifyNS := make([]int64, config.Iterations)
	var proof groth16.Proof
	for i := 0; i < config.Iterations; i++ {
		started = time.Now()
		proof, err = groth16.Prove(cs, pk, full)
		proveNS[i] = time.Since(started).Nanoseconds()
		if err != nil {
			return Receipt{}, errors.New("valid synthetic proof generation failed")
		}
		started = time.Now()
		err = groth16.Verify(proof, vk, public)
		verifyNS[i] = time.Since(started).Nanoseconds()
		if err != nil {
			return Receipt{}, errors.New("valid synthetic proof verification failed")
		}
		if proveNS[i] <= 0 || verifyNS[i] <= 0 {
			return Receipt{}, errors.New("nonpositive measured duration")
		}
	}
	if compileNS <= 0 || setupNS <= 0 || cs.GetNbConstraints() <= 0 {
		return Receipt{}, errors.New("invalid compile/setup measurement")
	}
	proofHash, proofSize, err := serializedDigest(proof)
	if err != nil {
		return Receipt{}, err
	}
	cases, err := adversarialCases(cs, pk, vk, proof, public, assignment)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		Format: 1, Status: "passed", ActualBackendRun: true,
		Backend: BackendReceipt{ID: "gnark-groth16-bn254", Gnark: "v0.16.3", GnarkCrypto: "v0.21.0", Curve: "BN254", ProofSystem: "Groth16", Hash: "Poseidon2", License: "Apache-2.0"},
		Circuit: CircuitReceipt{ID: "1soft/privacy-proof-benchmark/v1", SourceDigest: config.CircuitDigest, Constraints: cs.GetNbConstraints(), Depth: Depth, Inputs: 1, Outputs: 2, ValueBits: 64,
			PublicInputs: []string{"version", "genesis", "asset", "context", "epoch", "height", "expiry", "policy", "root", "nullifier", "output_commitment_0", "output_commitment_1", "fee", "authorization_digest"}, PrivateInputsRetained: false},
		Source:     SourceReceipt{Commit: config.Commit, Tree: config.Tree},
		Parameters: ParameterReceipt{Kind: "ephemeral-local-groth16-setup", Ceremony: false, Reusable: false, Production: false, ProvingKeySHA256: pkHash, ProvingKeyBytes: pkSize, VerifyingKeySHA256: vkHash, VerifyingKeyBytes: vkSize},
		Artifacts:  ArtifactReceipt{ProofSHA256: proofHash, ProofBytes: proofSize, PublicWitnessSHA256: publicHash, PublicWitnessBytes: publicSize},
		Metrics:    MetricReceipt{CompileNS: compileNS, SetupNS: setupNS, Iterations: config.Iterations, ProveNS: proveNS, VerifyNS: verifyNS},
		Cases:      cases, Claims: ClaimReceipt{},
		Unassessed: []string{
			"global nullifier uniqueness and consensus ordering",
			"production parameter ceremony",
			"independent cryptographic review",
			"wallet scanning and recovery",
			"network anonymity and metadata resistance",
			"production custody and side-channel resistance",
			"public-network and real-funds safety",
		},
	}, nil
}

func adversarialCases(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, proof groth16.Proof, public witness.Witness, original Circuit) ([]CaseReceipt, error) {
	cases := []CaseReceipt{{ID: "valid-proof", Expected: "accept", Observed: "accept"}}
	recordRejection := func(id string, rejected bool) error {
		if !rejected {
			return errors.New("adversarial case accepted: " + id)
		}
		cases = append(cases, CaseReceipt{ID: id, Expected: "reject", Observed: "reject"})
		return nil
	}
	// Mutate an actual proof with a nonzero valid subgroup point. This reaches
	// the verifier's pairing check rather than accepting a mere decoder error.
	concrete, ok := proof.(*backendBN254.Proof)
	if !ok {
		return nil, errors.New("unexpected proof curve")
	}
	mutated := *concrete
	_, _, generator, _ := curve.Generators()
	mutated.Ar.Add(&mutated.Ar, &generator)
	if err := recordRejection("mutated-proof", groth16.Verify(&mutated, vk, public) != nil); err != nil {
		return nil, err
	}
	changed := original
	changed.Context = 14
	changedFull, err := frontend.NewWitness(&changed, ecc.BN254.ScalarField())
	if err != nil {
		return nil, errors.New("changed public witness construction failed")
	}
	changedPublic, err := changedFull.Public()
	if err != nil {
		return nil, errors.New("changed public witness extraction failed")
	}
	if err := recordRejection("changed-public-input", groth16.Verify(proof, vk, changedPublic) != nil); err != nil {
		return nil, err
	}
	_, wrongVK, err := groth16.Setup(cs)
	if err != nil {
		return nil, errors.New("wrong-key adversarial setup failed")
	}
	if err := recordRejection("wrong-verifying-key", groth16.Verify(proof, wrongVK, public) != nil); err != nil {
		return nil, err
	}
	invalid, err := invalidAssignments(original)
	if err != nil {
		return nil, errors.New("adversarial witness construction failed")
	}
	for _, candidate := range invalid {
		full, err := frontend.NewWitness(&candidate.Assignment, ecc.BN254.ScalarField())
		if err != nil {
			return nil, errors.New("adversarial witness encoding failed")
		}
		pub, err := full.Public()
		if err != nil {
			return nil, errors.New("adversarial public witness extraction failed")
		}
		invalidProof, proveErr := groth16.Prove(cs, pk, full)
		rejected := proveErr != nil
		if !rejected {
			rejected = groth16.Verify(invalidProof, vk, pub) != nil
		}
		if err := recordRejection(candidate.ID, rejected); err != nil {
			return nil, err
		}
	}
	return cases, nil
}

type invalidAssignment struct {
	ID         string
	Assignment Circuit
}

func increment(value frontend.Variable) (*big.Int, error) {
	var result big.Int
	switch value := value.(type) {
	case *big.Int:
		result.Set(value)
	case int:
		result.SetInt64(int64(value))
	default:
		return nil, errors.New("unsupported synthetic mutation input")
	}
	return result.Add(&result, big.NewInt(1)), nil
}

func refreshAuthorization(c *Circuit) error {
	var err error
	c.Authorization, err = nativeDigest(105, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch,
		c.Height, c.Expiry, c.Policy, c.Root, c.Nullifier, c.Output0, c.Output1, c.Fee)
	return err
}

// rebuildBindings makes an internally bound synthetic statement for the range
// test. Its sole remaining failure is the input value exceeding unsigned 64 bits.
func rebuildBindings(c *Circuit) error {
	key, err := nativeDigest(106, c.SpendSecret)
	if err != nil {
		return err
	}
	input, err := nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.InputExpiry, c.Value, key, c.NoteSecret, c.InputBlinding)
	if err != nil {
		return err
	}
	root, err := nativeDigest(101, input)
	if err != nil {
		return err
	}
	for i := 0; i < Depth; i++ {
		if c.Bits[i] == 1 {
			root, err = nativeDigest(102, c.Path[i], root)
		} else {
			root, err = nativeDigest(102, root, c.Path[i])
		}
		if err != nil {
			return err
		}
	}
	c.Root = root
	c.Nullifier, err = nativeDigest(103, c.Version, c.Genesis, c.Asset, c.Epoch, c.Policy,
		c.Context, c.SpendSecret, c.NoteSecret, input, c.Position)
	if err != nil {
		return err
	}
	c.Output0, err = nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry0, c.OutputValue0, c.OutputKey0, c.OutputNote0, c.Blind0)
	if err != nil {
		return err
	}
	c.Output1, err = nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry1, c.OutputValue1, c.OutputKey1, c.OutputNote1, c.Blind1)
	if err != nil {
		return err
	}
	return refreshAuthorization(c)
}

func invalidAssignments(original Circuit) ([]invalidAssignment, error) {
	membership := original
	var err error
	membership.Path[0], err = increment(membership.Path[0])
	if err != nil {
		return nil, err
	}
	nullifier := original
	nullifier.Nullifier, err = increment(nullifier.Nullifier)
	if err != nil {
		return nil, err
	}
	if err := refreshAuthorization(&nullifier); err != nil {
		return nil, err
	}
	output := original
	output.Output0, err = increment(output.Output0)
	if err != nil {
		return nil, err
	}
	if err := refreshAuthorization(&output); err != nil {
		return nil, err
	}
	fee := original
	fee.Fee = 2
	if err := refreshAuthorization(&fee); err != nil {
		return nil, err
	}
	outOfRange := original
	outOfRange.Value = new(big.Int).Lsh(big.NewInt(1), 64)
	outOfRange.OutputValue0 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(2))
	outOfRange.OutputValue1 = 1
	if err := rebuildBindings(&outOfRange); err != nil {
		return nil, err
	}
	authorization := original
	authorization.Authorization, err = increment(authorization.Authorization)
	if err != nil {
		return nil, err
	}
	return []invalidAssignment{
		{ID: "invalid-membership", Assignment: membership},
		{ID: "invalid-nullifier", Assignment: nullifier},
		{ID: "invalid-output-commitment", Assignment: output},
		{ID: "invalid-fee-conservation", Assignment: fee},
		{ID: "out-of-range-value", Assignment: outOfRange},
		{ID: "changed-authorization-digest", Assignment: authorization},
	}, nil
}
