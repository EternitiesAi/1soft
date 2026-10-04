package benchmark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

const Depth = 4

type Circuit struct {
	Version, Genesis, Asset, Context, Epoch, Height, Expiry, Policy, Root, Nullifier, Output0, Output1, Fee, Authorization     frontend.Variable `gnark:",public"`
	Position, Value, InputExpiry, InputBlinding, SpendSecret, NoteSecret                                                       frontend.Variable
	Path                                                                                                                       [Depth]frontend.Variable
	Bits                                                                                                                       [Depth]frontend.Variable
	OutputValue0, OutputValue1, OutputExpiry0, OutputExpiry1, OutputKey0, OutputKey1, Blind0, Blind1, OutputNote0, OutputNote1 frontend.Variable
}

func digest(api frontend.API, values ...frontend.Variable) frontend.Variable {
	h, err := poseidon2.New(api)
	if err != nil {
		panic("Poseidon2 is unavailable for this circuit field")
	}
	h.Write(values...)
	return h.Sum()
}

// noteCommitment is shared by consumed and created notes. Output recipients expose
// only the hash of their spend secret; spending requires the corresponding preimage.
func noteCommitment(api frontend.API, version, genesis, asset, context, epoch, policy, expiry, value, spendKey, noteSecret, blinding frontend.Variable) frontend.Variable {
	return digest(api, 100, version, genesis, asset, context, epoch, policy, expiry, value, spendKey, noteSecret, blinding)
}

func (c *Circuit) Define(api frontend.API) error {
	positionBits := api.ToBinary(c.Position, Depth)
	for i := 0; i < Depth; i++ {
		api.AssertIsBoolean(c.Bits[i])
		api.AssertIsEqual(positionBits[i], c.Bits[i])
	}
	api.ToBinary(c.Version, 64)
	api.ToBinary(c.Epoch, 64)
	api.ToBinary(c.Height, 64)
	api.ToBinary(c.Expiry, 64)
	api.ToBinary(c.Position, 64)
	api.ToBinary(c.Value, 64)
	api.ToBinary(c.InputExpiry, 64)
	api.ToBinary(c.OutputValue0, 64)
	api.ToBinary(c.OutputValue1, 64)
	api.ToBinary(c.OutputExpiry0, 64)
	api.ToBinary(c.OutputExpiry1, 64)
	api.ToBinary(c.Fee, 64)
	api.AssertIsEqual(c.Version, 1)
	api.AssertIsLessOrEqual(api.Add(c.Height, 1), c.Expiry)
	api.AssertIsLessOrEqual(api.Add(c.Height, 1), c.InputExpiry)
	api.AssertIsLessOrEqual(api.Add(c.Height, 1), c.OutputExpiry0)
	api.AssertIsLessOrEqual(api.Add(c.Height, 1), c.OutputExpiry1)
	api.AssertIsLessOrEqual(1, c.Value)
	api.AssertIsLessOrEqual(1, c.OutputValue0)
	api.AssertIsLessOrEqual(1, c.OutputValue1)
	sum := api.Add(c.OutputValue0, c.OutputValue1)
	api.ToBinary(sum, 65)
	total := api.Add(sum, c.Fee)
	api.ToBinary(total, 65)
	api.AssertIsEqual(c.Value, total)
	spendKey := digest(api, 106, c.SpendSecret)
	inputCommitment := noteCommitment(api, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.InputExpiry, c.Value, spendKey, c.NoteSecret, c.InputBlinding)
	cur := digest(api, 101, inputCommitment)
	for i := 0; i < Depth; i++ {
		left := api.Select(c.Bits[i], c.Path[i], cur)
		right := api.Select(c.Bits[i], cur, c.Path[i])
		cur = digest(api, 102, left, right)
	}
	api.AssertIsEqual(cur, c.Root)
	api.AssertIsEqual(digest(api, 103, c.Version, c.Genesis, c.Asset, c.Epoch, c.Policy,
		c.Context, c.SpendSecret, c.NoteSecret, inputCommitment, c.Position), c.Nullifier)
	api.AssertIsEqual(noteCommitment(api, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry0, c.OutputValue0, c.OutputKey0, c.OutputNote0, c.Blind0), c.Output0)
	api.AssertIsEqual(noteCommitment(api, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry1, c.OutputValue1, c.OutputKey1, c.OutputNote1, c.Blind1), c.Output1)
	api.AssertIsDifferent(c.Output0, c.Output1)
	api.AssertIsEqual(digest(api, 105, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch,
		c.Height, c.Expiry, c.Policy, c.Root, c.Nullifier, c.Output0, c.Output1, c.Fee), c.Authorization)
	return nil
}
