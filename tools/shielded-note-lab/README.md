# 1soft shielded-note laboratory

This component is a deterministic **transparent-witness** model for the semantics a future shielded transaction would need. It is research code, isolated from the live 1soft transaction, wallet, browser, validator, genesis and receipt paths.

It does not provide zero-knowledge proofs, production privacy, anonymity, consensus enforcement, public-network behavior or real-funds safety. SHA-256 supplies versioned commitments and Ed25519 supplies spending authorization in this model. Neither primitive hides the witness.

## What the laboratory executes

One transition consumes a committed input note and creates one to four ordered output commitments plus an explicit fee. Before state changes, the ledger checks:

- an exact genesis, asset, authority epoch, context, height and expiry domain;
- the input opening, note-secret commitment, fixed-depth membership path and position;
- a nullifier derived from the committed note, secret, position and context;
- a signature made by the input note's spending key over the complete public transaction body;
- every output opening, recipient material, policy commitment and expiry;
- bounded integer conservation and fresh output commitments;
- tree capacity, duplicate rejection and canonical schemas.

Caller-owned transactions, private witnesses, public checkpoints and mutable helper inputs are copied into bounded canonical JSON-shaped snapshots at their public boundaries. Accepted transactions retain their exact public bytes and receipt. Exact replay returns the original receipt without another transition. A different transaction attempting the same nullifier is refused. Failed application leaves the public serialization unchanged.

Public export and cold reopen validate the retained signed public transcript, roots, heights, receipts and nullifier inventory. Reopen cannot reconstruct or independently re-prove deliberately absent private witnesses. Callers need an authenticated complete checkpoint from prior trusted execution; a trusted genesis identifies only the initial domain and cannot authenticate later witness-free history.

## Disclosure and clone boundary

Ordinary public transactions, receipts and state contain commitments, nullifiers, public authorization and roots. They do not contain note secrets, private keys, blindings, witness paths or full viewing authority.

An explicit selected-output disclosure reveals one output's non-secret opening and blinding so its exact commitment can be recomputed against a retained receipt. That creates linkability to the selected transaction and output. It does not reveal the note secret, a private spending key, unselected output openings or unrelated history.

One shared `Ledger` serializes its own spent-nullifier set. Independent clones can each accept a competing spend because this lab has no consensus or shared authority. A local pass is not global double-spend prevention.

## Run the tests

From the repository root, using the pinned environment:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=tools/shielded-note-lab/src \
python -m unittest discover -s tools/shielded-note-lab/tests -p 'test_*.py' -v
```

The strict verifier additionally requires a clean Git checkout, an exact format-2 source manifest and an external report destination:

```sh
python tools/shielded-note-lab/tools/verify.py \
  --report /path/outside/the/repository/shielded-note-lab-verification.json
```

The verifier denies Python socket and DNS APIs in its process, restricts children to the same Python interpreter, and injects the same deny layer into those children. This is a bounded Python execution policy, not an operating-system network sandbox. The repository current checker invokes this verifier and requires its source-bound receipt before local checks can pass.

See [the design specification](../../docs/superpowers/specs/2026-10-04-shielded-note-lab-design.md) and [verification contract](VERIFICATION.md).
