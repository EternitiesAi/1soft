package benchmark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type nativeHashCircuit struct {
	Values [5]frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *nativeHashCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(digest(api, c.Values[:]...), c.Hash)
	return nil
}

// A wrong field encoding or mismatched Poseidon2 construction must fail the real circuit.
func TestNativePoseidon2MatchesCircuit(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &nativeHashCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	values := [5]frontend.Variable{105, 0, 1, new(big.Int).Lsh(big.NewInt(1), 64), new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))}
	expected, err := nativeDigest(values[:]...)
	if err != nil {
		t.Fatal(err)
	}
	assignment := nativeHashCircuit{Values: values, Hash: expected}
	full, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(full); err != nil {
		t.Fatal("native Poseidon2 differs from the circuit")
	}
}

// Any mismatch in note, Merkle, nullifier, output, or authorization construction must fail.
func TestSyntheticFixtureMatchesCircuit(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(full); err != nil {
		t.Fatal("synthetic native fixture does not satisfy the circuit")
	}
	again, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := frontend.NewWitness(&again, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := full.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	repeatedBytes, err := repeated.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(repeatedBytes) {
		t.Fatal("synthetic fixture is not deterministic")
	}
}

func bindTestCircuit(t *testing.T, c *Circuit) *big.Int {
	t.Helper()
	hash := func(values ...frontend.Variable) *big.Int {
		value, err := nativeDigest(values...)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	spendKey := hash(106, c.SpendSecret)
	input := hash(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.InputExpiry, c.Value, spendKey, c.NoteSecret, c.InputBlinding)
	root := hash(101, input)
	for i := 0; i < Depth; i++ {
		if c.Bits[i] == 1 {
			root = hash(102, c.Path[i], root)
		} else {
			root = hash(102, root, c.Path[i])
		}
	}
	c.Root = root
	c.Nullifier = hash(103, c.Version, c.Genesis, c.Asset, c.Epoch, c.Policy,
		c.Context, c.SpendSecret, c.NoteSecret, input, c.Position)
	c.Output0 = hash(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry0, c.OutputValue0, c.OutputKey0, c.OutputNote0, c.Blind0)
	c.Output1 = hash(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry1, c.OutputValue1, c.OutputKey1, c.OutputNote1, c.Blind1)
	refreshTestAuthorization(t, c)
	return input
}

func refreshTestAuthorization(t *testing.T, c *Circuit) {
	t.Helper()
	var err error
	c.Authorization, err = nativeDigest(105, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch,
		c.Height, c.Expiry, c.Policy, c.Root, c.Nullifier, c.Output0, c.Output1, c.Fee)
	if err != nil {
		t.Fatal(err)
	}
}

// A generated output must use the exact input note formula and be spendable by its recipient.
func TestOutputOpeningCanBecomeInput(t *testing.T) {
	c, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	outputCommitment := new(big.Int).Set(c.Output0.(*big.Int))
	c.Value, c.InputExpiry, c.SpendSecret, c.NoteSecret, c.InputBlinding =
		c.OutputValue0, c.OutputExpiry0, 33, c.OutputNote0, c.Blind0
	c.OutputValue0, c.OutputValue1 = 10, 29
	inputCommitment := bindTestCircuit(t, &c)
	if inputCommitment.Cmp(outputCommitment) != 0 {
		t.Fatal("output opening cannot be consumed under the input note formula")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(full); err != nil {
		t.Fatal("recipient cannot consume its output opening")
	}
}

// Distinct output commitments are required even when every other binding is valid.
func TestDuplicateOutputOpeningRejected(t *testing.T) {
	c, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	c.Value, c.OutputValue0, c.OutputValue1 = 99, 49, 49
	c.OutputExpiry1, c.OutputKey1, c.OutputNote1, c.Blind1 = c.OutputExpiry0, c.OutputKey0, c.OutputNote0, c.Blind0
	bindTestCircuit(t, &c)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(full) == nil {
		t.Fatal("duplicate output openings are accepted")
	}
}

// Knowing the output note secret and blinding cannot replace the recipient spend secret.
func TestWrongSpendSecretRejected(t *testing.T) {
	c, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	originalRoot := c.Root
	c.SpendSecret = 99
	bindTestCircuit(t, &c)
	// Bind the forged nullifier and authorization to the attacker's secret, but keep
	// the accepted tree containing the actual recipient's committed spend key.
	c.Root = originalRoot
	refreshTestAuthorization(t, &c)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(full) == nil {
		t.Fatal("wrong spend secret satisfies the committed note")
	}
}

// The serialized public witness must use the frozen fourteen-field transaction order.
func TestPublicWitnessOrder(t *testing.T) {
	c, err := SyntheticFixture()
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	vector, ok := public.Vector().(fr.Vector)
	if !ok || len(vector) != 14 {
		t.Fatal("public witness shape differs")
	}
	ordered := []frontend.Variable{c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Height,
		c.Expiry, c.Policy, c.Root, c.Nullifier, c.Output0, c.Output1, c.Fee, c.Authorization}
	for i, value := range ordered {
		var expected fr.Element
		if _, err := expected.SetInterface(value); err != nil {
			t.Fatal(err)
		}
		if !vector[i].Equal(&expected) {
			t.Fatal("public witness order differs from the frozen statement")
		}
	}
}
