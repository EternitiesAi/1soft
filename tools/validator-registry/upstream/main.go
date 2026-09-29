// Full registry response compatibility only. No node, private key, signing or RPC.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/cometbft/cometbft/types"
	"io"
	"os"
)

type Row struct {
	PublicKey string `json:"public_key"`
	Power     int64  `json:"power"`
}
type ExecutionResult struct {
	Code uint32 `json:"code"`
	Data string `json:"data"`
	Log  string `json:"log"`
}
type Vector struct {
	AppHash     string            `json:"app_hash"`
	Results     []ExecutionResult `json:"tx_results"`
	Name        string            `json:"name"`
	Current     []Row             `json:"current"`
	Target      []Row             `json:"target"`
	Updates     []Row             `json:"updates"`
	CurrentHash string            `json:"current_hash"`
	TargetHash  string            `json:"target_hash"`
	Wire        string            `json:"wire"`
}

func key(r Row) []byte {
	b, err := hex.DecodeString(r.PublicKey)
	if err != nil || len(b) != 32 {
		panic("invalid fixture public key")
	}
	return b
}
func set(rows []Row) *types.ValidatorSet {
	if len(rows) == 0 || len(rows) > 256 {
		panic("invalid fixture roster")
	}
	vals := make([]*types.Validator, 0, len(rows))
	for _, r := range rows {
		if r.Power <= 0 {
			panic("invalid fixture power")
		}
		vals = append(vals, types.NewValidator(ed25519.PubKey(key(r)), r.Power))
	}
	return types.NewValidatorSet(vals)
}
func run() error {
	d := json.NewDecoder(io.LimitReader(os.Stdin, 8*1024*1024))
	d.DisallowUnknownFields()
	var vectors []Vector
	if err := d.Decode(&vectors); err != nil {
		return err
	}
	if len(vectors) == 0 || len(vectors) > 32 {
		return fmt.Errorf("invalid vector count")
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(vectors))
	for _, v := range vectors {
		if v.Name == "" || seen[v.Name] {
			return fmt.Errorf("duplicate/empty name")
		}
		seen[v.Name] = true
		before, after := set(v.Current), set(v.Target)
		if hex.EncodeToString(before.Hash()) != v.CurrentHash || hex.EncodeToString(after.Hash()) != v.TargetHash {
			return fmt.Errorf("%s: set hash differs", v.Name)
		}
		updates := make([]abci.ValidatorUpdate, 0, len(v.Updates))
		changes := make([]*types.Validator, 0, len(v.Updates))
		for _, r := range v.Updates {
			k := key(r)
			updates = append(updates, abci.ValidatorUpdate{PubKey: cmtcrypto.PublicKey{Sum: &cmtcrypto.PublicKey_Ed25519{Ed25519: k}}, Power: r.Power})
			changes = append(changes, types.NewValidator(ed25519.PubKey(k), r.Power))
		}
		if err := before.UpdateWithChangeSet(changes); err != nil {
			return err
		}
		if hex.EncodeToString(before.Hash()) != v.TargetHash {
			return fmt.Errorf("%s: delta result differs", v.Name)
		}
		appHash, err := hex.DecodeString(v.AppHash)
		if err != nil || len(appHash) != 32 {
			return fmt.Errorf("bad AppHash")
		}
		response := abci.ResponseFinalizeBlock{ValidatorUpdates: updates, AppHash: appHash}
		for _, r := range v.Results {
			response.TxResults = append(response.TxResults, &abci.ExecTxResult{Code: r.Code, Data: []byte(r.Data), Log: r.Log})
		}
		raw, err := response.Marshal()
		if err != nil {
			return err
		}
		if hex.EncodeToString(raw) != v.Wire {
			return fmt.Errorf("%s: protobuf differs", v.Name)
		}
		names = append(names, v.Name)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "passed", "engine_version": "0.38.25", "vectors": names, "consensus_executed": false})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
