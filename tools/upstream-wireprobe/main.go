// Wire fixtures emitted by the REAL upstream Go protobuf implementation.
// This program is a compatibility gate, not a consensus engine.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	cmttypes "github.com/cometbft/cometbft/types"
	"os"
	"time"
)

type message interface {
	Reset()
	String() string
	ProtoMessage()
}

func main() {
	fixtures := map[string]message{
		"request_info":     abci.ToRequestInfo(&abci.RequestInfo{}),
		"request_commit":   abci.ToRequestCommit(),
		"request_finalize": abci.ToRequestFinalizeBlock(&abci.RequestFinalizeBlock{Height: 7}),
		"request_offer_snapshot": abci.ToRequestOfferSnapshot(&abci.RequestOfferSnapshot{
			Snapshot: &abci.Snapshot{Height: 9, Format: 1, Chunks: 2, Hash: bytes.Repeat([]byte{3}, 32), Metadata: []byte("meta")},
			AppHash: bytes.Repeat([]byte{4}, 32),
		}),
		"request_load_snapshot": abci.ToRequestLoadSnapshotChunk(&abci.RequestLoadSnapshotChunk{Height: 9, Format: 1, Chunk: 1}),
		"request_apply_snapshot": abci.ToRequestApplySnapshotChunk(&abci.RequestApplySnapshotChunk{Index: 1, Chunk: []byte("chunk"), Sender: "peer"}),
		"response_finalize": &abci.Response{Value: &abci.Response_FinalizeBlock{
			FinalizeBlock: &abci.ResponseFinalizeBlock{AppHash: []byte("abc")},
		}},
		"response_list_snapshots": abci.ToResponseListSnapshots(&abci.ResponseListSnapshots{Snapshots: []*abci.Snapshot{
			{Height: 9, Format: 1, Chunks: 2, Hash: bytes.Repeat([]byte{3}, 32), Metadata: []byte("meta")},
		}}),
		"response_load_snapshot": abci.ToResponseLoadSnapshotChunk(&abci.ResponseLoadSnapshotChunk{Chunk: []byte("chunk")}),
		"response_apply_snapshot": abci.ToResponseApplySnapshotChunk(&abci.ResponseApplySnapshotChunk{Result: abci.ResponseApplySnapshotChunk_RETRY, RefetchChunks: []uint32{0, 1}, RejectSenders: []string{"bad-peer"}}),
	}
	out := map[string]string{}
	for name, value := range fixtures {
		var buffer bytes.Buffer
		if err := abci.WriteMessage(value, &buffer); err != nil {
			panic(err)
		}
		out[name] = hex.EncodeToString(buffer.Bytes())
	}
	// Cross-check the independent verifier's encodings using actual upstream
	// types, not hand-authored expected bytes. This is still NOT a network run.
	out["vote_zero_time"] = hex.EncodeToString(cmttypes.VoteSignBytes("", &cmtproto.Vote{
		Type: cmtproto.PrecommitType, Height: 1, Round: 1,
	}))
	id := cmtproto.BlockID{Hash: bytes.Repeat([]byte{1}, 32),
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{2}, 32)}}
	out["vote_with_block"] = hex.EncodeToString(cmttypes.VoteSignBytes("eternities-wire-probe", &cmtproto.Vote{
		Type: cmtproto.PrecommitType, Height: 7, Round: 2, BlockID: id,
		Timestamp: time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.UTC),
	}))
	header := &cmttypes.Header{
		Version: cmtversion.Consensus{Block: 1, App: 2}, ChainID: "chainId", Height: 3,
		Time: time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC),
		LastBlockID: cmttypes.BlockID{Hash: make([]byte, 32),
			PartSetHeader: cmttypes.PartSetHeader{Total: 6, Hash: make([]byte, 32)}},
		LastCommitHash: tmhash.Sum([]byte("last_commit_hash")), DataHash: tmhash.Sum([]byte("data_hash")),
		ValidatorsHash: tmhash.Sum([]byte("validators_hash")), NextValidatorsHash: tmhash.Sum([]byte("next_validators_hash")),
		ConsensusHash: tmhash.Sum([]byte("consensus_hash")), AppHash: tmhash.Sum([]byte("app_hash")),
		LastResultsHash: tmhash.Sum([]byte("last_results_hash")), EvidenceHash: tmhash.Sum([]byte("evidence_hash")),
		ProposerAddress: tmhash.SumTruncated([]byte("proposer_address")),
	}
	out["header_hash"] = hex.EncodeToString(header.Hash())
	validator := cmttypes.NewValidator(ed25519.PubKey(bytes.Repeat([]byte{7}, 32)), 10)
	out["validator_hash"] = hex.EncodeToString(cmttypes.NewValidatorSet([]*cmttypes.Validator{validator}).Hash())
	out["transaction_data_size"] = fmt.Sprint(cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{
		{}, bytes.Repeat([]byte{1}, 127), bytes.Repeat([]byte{2}, 128), bytes.Repeat([]byte{3}, 16384),
	}))
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
