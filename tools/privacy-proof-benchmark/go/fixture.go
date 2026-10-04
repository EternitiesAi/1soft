package benchmark

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativePoseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

// nativeDigest matches the circuit's default Poseidon2 Merkle-Damgard construction.
// Each input is encoded as one canonical, big-endian BN254 scalar-field element.
func nativeDigest(values ...frontend.Variable) (*big.Int, error) {
	h := nativePoseidon2.NewMerkleDamgardHasher()
	for _, value := range values {
		var element fr.Element
		if _, err := element.SetInterface(value); err != nil {
			return nil, errors.New("invalid synthetic hash input")
		}
		encoded := element.Bytes()
		if _, err := h.Write(encoded[:]); err != nil {
			return nil, errors.New("synthetic hash failed")
		}
	}
	var result fr.Element
	result.SetBytes(h.Sum(nil))
	return result.BigInt(new(big.Int)), nil
}

// SyntheticFixture creates a deterministic, entirely synthetic note and depth-four
// tree. The private opening exists only in memory and is never receipt evidence.
func SyntheticFixture() (Circuit, error) {
	c := Circuit{
		Version: 1, Genesis: 11, Asset: 12, Context: 13, Epoch: 2, Height: 100,
		Expiry: 200, Policy: 14, Fee: 1,
		Position: 5, Value: 100, InputExpiry: 300, InputBlinding: 21, SpendSecret: 22, NoteSecret: 23,
		Bits:         [Depth]frontend.Variable{1, 0, 1, 0},
		OutputValue0: 40, OutputValue1: 59, OutputExpiry0: 400, OutputExpiry1: 500,
		Blind0: 32, Blind1: 42,
		OutputNote0: 34, OutputNote1: 44,
	}
	var err error
	c.OutputKey0, err = nativeDigest(106, 33)
	if err != nil {
		return Circuit{}, err
	}
	c.OutputKey1, err = nativeDigest(106, 43)
	if err != nil {
		return Circuit{}, err
	}
	spendKey, err := nativeDigest(106, c.SpendSecret)
	if err != nil {
		return Circuit{}, err
	}
	input, err := nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.InputExpiry, c.Value, spendKey, c.NoteSecret, c.InputBlinding)
	if err != nil {
		return Circuit{}, err
	}
	nodes := make([]*big.Int, 1<<Depth)
	for i := range nodes {
		commitment := input
		if i != 5 {
			commitment, err = nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
				300, 10+i, 70+i, 90+i, 110+i)
			if err != nil {
				return Circuit{}, err
			}
		}
		nodes[i], err = nativeDigest(101, commitment)
		if err != nil {
			return Circuit{}, err
		}
	}
	position := 5
	for level := 0; level < Depth; level++ {
		c.Path[level] = new(big.Int).Set(nodes[position^1])
		parents := make([]*big.Int, len(nodes)/2)
		for i := range parents {
			parents[i], err = nativeDigest(102, nodes[2*i], nodes[2*i+1])
			if err != nil {
				return Circuit{}, err
			}
		}
		nodes = parents
		position >>= 1
	}
	c.Root = nodes[0]
	c.Nullifier, err = nativeDigest(103, c.Version, c.Genesis, c.Asset, c.Epoch, c.Policy,
		c.Context, c.SpendSecret, c.NoteSecret, input, c.Position)
	if err != nil {
		return Circuit{}, err
	}
	c.Output0, err = nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry0, c.OutputValue0, c.OutputKey0, c.OutputNote0, c.Blind0)
	if err != nil {
		return Circuit{}, err
	}
	c.Output1, err = nativeDigest(100, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch, c.Policy,
		c.OutputExpiry1, c.OutputValue1, c.OutputKey1, c.OutputNote1, c.Blind1)
	if err != nil {
		return Circuit{}, err
	}
	c.Authorization, err = nativeDigest(105, c.Version, c.Genesis, c.Asset, c.Context, c.Epoch,
		c.Height, c.Expiry, c.Policy, c.Root, c.Nullifier, c.Output0, c.Output1, c.Fee)
	if err != nil {
		return Circuit{}, err
	}
	return c, nil
}
