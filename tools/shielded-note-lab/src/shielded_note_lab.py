"""Deterministic, transparent-witness shielded-note transition laboratory.

Research only: no zero knowledge, production privacy, consensus integration,
public network, or real funds. Reopening checks the retained public history;
it cannot re-prove private openings that are deliberately absent from that history.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"1soft/shielded-note-lab/v1\0"
MAX_BYTES = 16384
MAX_STATE_BYTES = 131072
MAX_VALUE = 2**53 - 1
DEPTH = 4
CAPACITY = 2**DEPTH
MAX_OUTPUTS = 4
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
NONCLAIMS = {
    "production_privacy": False, "zero_knowledge": False,
    "consensus_integrated": False, "public_network": False, "real_funds": False,
}
EXECUTION_SCOPE = "one shared laboratory state; independent clones may accept competing spends"
LINKABILITY = "reveals the selected opening and blinding; links that output to this transaction and receipt"
NOTE_FIELDS = {
    "version", "genesis", "asset", "value", "spend_key", "incoming_view_key",
    "outgoing_view_key", "epoch", "policy_commitment", "expiry",
    "secret_commitment", "blinding",
}
AUTH_FIELDS = {
    "version", "genesis", "asset", "root", "nullifiers", "outputs", "fee",
    "epoch", "height", "expiry", "context",
}
TX_FIELDS = AUTH_FIELDS | {"signer", "signature"}
RECEIPT_FIELDS = {
    "version", "txid", "genesis", "asset", "context", "epoch", "height",
    "expiry", "root_before", "root", "nullifiers", "outputs", "fee",
    "execution_scope",
}
STATE_FIELDS = {
    "version", "genesis", "asset", "epoch", "context", "initial_height",
    "current_height", "initial_commitments", "root", "commitments",
    "spent_nullifiers", "transactions", "receipts",
}
DISCLOSURE_FIELDS = {
    "version", "txid", "output_index", "receipt_commitment", "commitment",
    "opening", "linkability",
}


class NoteError(ValueError):
    pass


def enc(value, maximum=MAX_BYTES):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise NoteError("invalid canonical input") from exc
    if len(raw) > maximum:
        raise NoteError("input exceeds bound")
    return raw


def _snapshot(value, maximum=MAX_BYTES):
    """Copy caller-owned JSON-shaped input before validation or retention."""
    active = set()

    def clone(item):
        kind = type(item)
        if kind in (str, int, bool, type(None)):
            return item
        if kind not in (dict, list):
            raise NoteError("invalid canonical input")
        identity = id(item)
        if identity in active:
            raise NoteError("invalid canonical input")
        active.add(identity)
        try:
            if kind is list:
                return [clone(child) for child in item]
            copied = {}
            for name, child in item.items():
                if type(name) is not str:
                    raise NoteError("invalid canonical input")
                copied[name] = clone(child)
            return copied
        except (RuntimeError, RecursionError) as exc:
            raise NoteError("invalid canonical input") from exc
        finally:
            active.remove(identity)

    try:
        copied = clone(value)
        enc(copied, maximum)
        return copied
    except RecursionError as exc:
        raise NoteError("invalid canonical input") from exc


def h(tag, value):
    return hashlib.sha256(DOMAIN + tag + enc(value)).hexdigest()


def schema(value, fields, name):
    if type(value) is not dict or set(value) != fields:
        raise NoteError("invalid " + name + " schema")


def text(value, name):
    if (type(value) is not str or not value or len(value) > 128
            or not all(32 <= ord(char) < 127 for char in value)):
        raise NoteError("invalid " + name)
    return value


def integer(value, name, maximum=MAX_VALUE, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise NoteError("invalid " + name)
    return value


def version(value, name="version"):
    return integer(value, name, maximum=1, minimum=1)


def key(value, name):
    if type(value) is not str or not HEX64.fullmatch(value):
        raise NoteError("invalid " + name)
    return value


def genesis_id(value):
    return key(value, "genesis")


def note_commitment(note):
    note = _snapshot(note)
    schema(note, NOTE_FIELDS, "note")
    version(note["version"])
    genesis_id(note["genesis"])
    text(note["asset"], "asset")
    integer(note["value"], "value", minimum=1)
    for name in ("spend_key", "incoming_view_key", "outgoing_view_key",
                 "policy_commitment", "secret_commitment", "blinding"):
        key(note[name], name)
    integer(note["epoch"], "epoch")
    integer(note["expiry"], "expiry", minimum=1)
    return h(b"commitment", note)


def secret_commitment(secret):
    return h(b"secret", {"secret": key(secret, "secret")})


def make_note(*, genesis, asset, value, spend_key, incoming_view_key,
              outgoing_view_key, secret_commitment, blinding, epoch=0,
              policy_commitment="0" * 64, expiry=100):
    note = {
        "version": 1, "genesis": genesis, "asset": asset, "value": value,
        "spend_key": spend_key, "incoming_view_key": incoming_view_key,
        "outgoing_view_key": outgoing_view_key, "epoch": epoch,
        "policy_commitment": policy_commitment, "expiry": expiry,
        "secret_commitment": secret_commitment, "blinding": blinding,
    }
    return note, note_commitment(note)


def nullifier(secret, commitment, position, context):
    key(secret, "secret")
    key(commitment, "commitment")
    integer(position, "position", CAPACITY - 1)
    text(context, "context")
    # The commitment binds genesis, asset, epoch and every other opening field.
    return h(b"nullifier", {"secret": secret, "commitment": commitment,
                            "position": position, "context": context})


def leaf_hash(commitment):
    return h(b"leaf", {"commitment": key(commitment, "commitment")})


def node_hash(left, right):
    return h(b"node", {"left": key(left, "left node"),
                        "right": key(right, "right node")})


def _leaves(commitments):
    if type(commitments) is not list or len(commitments) > CAPACITY:
        raise NoteError("invalid tree capacity")
    for commitment in commitments:
        key(commitment, "commitment")
    if len(set(commitments)) != len(commitments):
        raise NoteError("duplicate commitment")
    return ([leaf_hash(commitment) for commitment in commitments]
            + [h(b"empty", {"depth": 0})] * (CAPACITY - len(commitments)))


def tree_root(commitments):
    commitments = _snapshot(commitments)
    nodes = _leaves(commitments)
    for _ in range(DEPTH):
        nodes = [node_hash(nodes[index], nodes[index + 1])
                 for index in range(0, len(nodes), 2)]
    return nodes[0]


def membership(commitment, position, commitments):
    key(commitment, "commitment")
    integer(position, "position", CAPACITY - 1)
    commitments = _snapshot(commitments)
    nodes = _leaves(commitments)
    if position >= len(commitments) or commitments[position] != commitment:
        raise NoteError("membership absent")
    path = []
    cursor = position
    for _ in range(DEPTH):
        path.append(nodes[cursor ^ 1])
        nodes = [node_hash(nodes[index], nodes[index + 1])
                 for index in range(0, len(nodes), 2)]
        cursor //= 2
    return path


def verify_membership(commitment, position, path, root):
    key(commitment, "commitment")
    key(root, "root")
    integer(position, "position", CAPACITY - 1)
    path = _snapshot(path)
    if type(path) is not list or len(path) != DEPTH:
        raise NoteError("invalid membership path")
    current = leaf_hash(commitment)
    cursor = position
    for sibling in path:
        key(sibling, "path node")
        current = (node_hash(current, sibling) if cursor % 2 == 0
                   else node_hash(sibling, current))
        cursor //= 2
    return current == root


def _outputs(outputs):
    if type(outputs) is not list or not 1 <= len(outputs) <= MAX_OUTPUTS:
        raise NoteError("invalid outputs")
    commitments = []
    for output in outputs:
        schema(output, {"commitment"}, "output")
        commitments.append(key(output["commitment"], "output commitment"))
    if len(set(commitments)) != len(commitments):
        raise NoteError("duplicate output commitment")
    return commitments


def _authorization(tx):
    schema(tx, TX_FIELDS, "transaction")
    version(tx["version"])
    genesis_id(tx["genesis"])
    text(tx["asset"], "asset")
    key(tx["root"], "root")
    if type(tx["nullifiers"]) is not list or len(tx["nullifiers"]) != 1:
        raise NoteError("exactly one nullifier required")
    key(tx["nullifiers"][0], "nullifier")
    _outputs(tx["outputs"])
    integer(tx["fee"], "fee")
    integer(tx["epoch"], "epoch")
    integer(tx["height"], "height")
    integer(tx["expiry"], "expiry", minimum=1)
    text(tx["context"], "context")
    key(tx["signer"], "signer")
    if type(tx["signature"]) is not str or not HEX128.fullmatch(tx["signature"]):
        raise NoteError("invalid signature encoding")
    enc(tx)
    return {name: copy.deepcopy(tx[name]) for name in AUTH_FIELDS}


def authorization(tx):
    """Return the exact public body to sign from one isolated caller snapshot."""
    return _authorization(_snapshot(tx))


def _validated_transaction(tx):
    transaction = _snapshot(tx)
    body = _authorization(transaction)
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(transaction["signer"])
        ).verify(
            bytes.fromhex(transaction["signature"]), DOMAIN + enc(body)
        )
    except Exception as exc:
        raise NoteError("authorization failure") from exc
    txid = h(
        b"txid",
        {
            "body": body,
            "signer": transaction["signer"],
            "signature": transaction["signature"],
        },
    )
    return transaction, body, txid


def transaction_id(tx):
    return _validated_transaction(tx)[2]


def _receipt(txid, tx, notes):
    return {
        "version": 1, "txid": txid, "genesis": tx["genesis"],
        "asset": tx["asset"], "context": tx["context"], "epoch": tx["epoch"],
        "height": tx["height"], "expiry": tx["expiry"],
        "root_before": tx["root"], "root": tree_root(notes),
        "nullifiers": copy.deepcopy(tx["nullifiers"]),
        "outputs": copy.deepcopy(tx["outputs"]), "fee": tx["fee"],
        "execution_scope": EXECUTION_SCOPE,
    }


def _validate_receipt(receipt):
    schema(receipt, RECEIPT_FIELDS, "receipt")
    version(receipt["version"])
    for name in ("txid", "genesis", "root_before", "root"):
        key(receipt[name], name)
    text(receipt["asset"], "asset")
    text(receipt["context"], "context")
    for name in ("epoch", "height", "fee"):
        integer(receipt[name], name)
    integer(receipt["expiry"], "expiry", minimum=1)
    if receipt["height"] >= receipt["expiry"]:
        raise NoteError("expired receipt")
    if type(receipt["nullifiers"]) is not list or len(receipt["nullifiers"]) != 1:
        raise NoteError("invalid receipt nullifiers")
    key(receipt["nullifiers"][0], "nullifier")
    _outputs(receipt["outputs"])
    if receipt["execution_scope"] != EXECUTION_SCOPE:
        raise NoteError("invalid execution scope")
    enc(receipt)


class Ledger:
    def __init__(self, genesis, asset, epoch=0, context="lab-context", current_height=0):
        self._lock = threading.RLock()
        self.genesis = genesis_id(genesis)
        self.asset = text(asset, "asset")
        self.epoch = integer(epoch, "epoch")
        self.context = text(context, "context")
        self._height = integer(current_height, "current height")
        self._initial_height = self._height
        self._initial_commitments = None
        self.notes = []
        self.spent = set()
        self.transactions = {}
        self.receipts = {}

    @property
    def current_height(self):
        with self._lock:
            return self._height

    @current_height.setter
    def current_height(self, height):
        with self._lock:
            integer(height, "current height")
            if height < self._height:
                raise NoteError("height cannot decrease")
            self._height = height

    def advance_height(self, height):
        self.current_height = height

    def export_public(self):
        with self._lock:
            return self._export_public_unlocked()

    def _export_public_unlocked(self):
        initial = self.notes if self._initial_commitments is None else self._initial_commitments
        return {
            "version": 1, "genesis": self.genesis, "asset": self.asset,
            "epoch": self.epoch, "context": self.context,
            "initial_height": self._initial_height, "current_height": self.current_height,
            "initial_commitments": list(initial), "root": tree_root(self.notes),
            "commitments": list(self.notes), "spent_nullifiers": sorted(self.spent),
            "transactions": copy.deepcopy(list(self.transactions.values())),
            "receipts": copy.deepcopy(list(self.receipts.values())),
        }

    def __deepcopy__(self, memo):
        clone = type(self).from_public(copy.deepcopy(self.export_public(), memo))
        memo[id(self)] = clone
        return clone

    @classmethod
    def from_public(cls, data):
        """Validate a public checkpoint's signed transition history and exact receipts.

        This is deterministic reopen, not proof of absent private witnesses.
        Callers need an authenticated complete checkpoint from prior trusted
        execution. A trusted genesis identifies the domain only and cannot
        authenticate later witness-free history.
        """
        data = _snapshot(data, MAX_STATE_BYTES)
        schema(data, STATE_FIELDS, "public state")
        enc(data, MAX_STATE_BYTES)
        version(data["version"], "state version")
        initial_height = integer(data["initial_height"], "initial height")
        height = integer(data["current_height"], "current height")
        if height < initial_height:
            raise NoteError("state height decreased")
        obj = cls(data["genesis"], data["asset"], data["epoch"], data["context"], initial_height)
        notes = list(data["initial_commitments"]) if type(data["initial_commitments"]) is list else None
        tree_root(notes)
        key(data["root"], "state root")
        tree_root(data["commitments"])
        spent = data["spent_nullifiers"]
        if type(spent) is not list or len(spent) > CAPACITY:
            raise NoteError("invalid spent nullifiers")
        for nf in spent:
            key(nf, "spent nullifier")
        if spent != sorted(set(spent)):
            raise NoteError("noncanonical spent nullifiers")
        txs, receipts = data["transactions"], data["receipts"]
        if (type(txs) is not list or type(receipts) is not list
                or len(txs) != len(receipts) or len(txs) > CAPACITY):
            raise NoteError("invalid retained history")
        seen = set()
        last_height = initial_height
        for tx, receipt in zip(txs, receipts):
            tx, _, txid = _validated_transaction(tx)
            obj._domain(tx)
            if not last_height <= tx["height"] <= height or tx["height"] >= tx["expiry"]:
                raise NoteError("invalid historical height")
            if tx["root"] != tree_root(notes):
                raise NoteError("historical root mismatch")
            nf = tx["nullifiers"][0]
            if nf in seen or txid in obj.transactions:
                raise NoteError("duplicate retained transaction or nullifier")
            outputs = _outputs(tx["outputs"])
            obj._fresh_outputs(notes, outputs)
            next_notes = notes + outputs
            expected = _receipt(txid, tx, next_notes)
            _validate_receipt(receipt)
            if enc(receipt) != enc(expected):
                raise NoteError("retained receipt mismatch")
            obj.transactions[txid] = copy.deepcopy(tx)
            obj.receipts[txid] = copy.deepcopy(expected)
            seen.add(nf)
            notes = next_notes
            last_height = tx["height"]
        if (notes != data["commitments"] or sorted(seen) != spent
                or tree_root(notes) != data["root"]):
            raise NoteError("public state does not match retained history")
        obj.notes = notes
        obj.spent = seen
        obj._initial_commitments = list(data["initial_commitments"])
        obj._height = height
        return obj

    def _domain(self, tx):
        if tx["genesis"] != self.genesis or tx["asset"] != self.asset:
            raise NoteError("domain mismatch")
        if tx["epoch"] != self.epoch or tx["context"] != self.context:
            raise NoteError("authority domain mismatch")

    @staticmethod
    def _fresh_outputs(notes, outputs):
        tree_root(notes)
        if len(notes) + len(outputs) > CAPACITY:
            raise NoteError("tree capacity exceeded")
        if any(output in notes for output in outputs):
            raise NoteError("output commitment is not fresh")

    def apply(self, tx, witness=None):
        with self._lock:
            return self._apply_unlocked(tx, witness)

    def _apply_unlocked(self, tx, witness=None):
        tx, _, txid = _validated_transaction(tx)
        # A completed operation needs no private witness, even after height/expiry.
        # Full retained bytes must match; replay never changes state.
        if txid in self.transactions:
            if enc(tx) != enc(self.transactions[txid]):
                raise NoteError("conflicting transaction identity")
            return copy.deepcopy(self.receipts[txid])
        witness = _snapshot(witness)
        self._domain(tx)
        if tx["height"] != self.current_height:
            raise NoteError("stale transaction height")
        if self.current_height >= tx["expiry"]:
            raise NoteError("expired transaction")
        root = tree_root(self.notes)
        if tx["root"] != root:
            raise NoteError("stale root")
        nf = tx["nullifiers"][0]
        if nf in self.spent:
            raise NoteError("nullifier already spent")
        outputs = _outputs(tx["outputs"])
        self._fresh_outputs(self.notes, outputs)
        schema(witness, {"input", "secret", "position", "path", "outputs"}, "private witness")
        enc(witness)
        note = witness["input"]
        commitment = note_commitment(note)
        secret = key(witness["secret"], "note secret")
        position = integer(witness["position"], "position", CAPACITY - 1)
        if position >= len(self.notes) or self.notes[position] != commitment:
            raise NoteError("input opening or position mismatch")
        if not verify_membership(commitment, position, witness["path"], root):
            raise NoteError("invalid membership")
        if note["secret_commitment"] != secret_commitment(secret):
            raise NoteError("secret commitment mismatch")
        if nf != nullifier(secret, commitment, position, self.context):
            raise NoteError("nullifier mismatch")
        self._domain({"genesis": note["genesis"], "asset": note["asset"],
                      "epoch": note["epoch"], "context": self.context})
        if self.current_height >= note["expiry"]:
            raise NoteError("expired input note")
        if tx["signer"] != note["spend_key"]:
            raise NoteError("input spend key mismatch")
        openings = witness["outputs"]
        if type(openings) is not list or len(openings) != len(outputs):
            raise NoteError("output witness length mismatch")
        total = 0
        for commitment, opening in zip(outputs, openings):
            if note_commitment(opening) != commitment:
                raise NoteError("output opening mismatch")
            self._domain({"genesis": opening["genesis"], "asset": opening["asset"],
                          "epoch": opening["epoch"], "context": self.context})
            if opening["policy_commitment"] != note["policy_commitment"]:
                raise NoteError("output policy mismatch")
            if self.current_height >= opening["expiry"]:
                raise NoteError("expired output note")
            total += opening["value"]
            integer(total, "output total")
        integer(total + tx["fee"], "conservation total")
        if note["value"] != total + tx["fee"]:
            raise NoteError("conservation failure")
        # All parsing, authorization, witness, freshness, capacity and conservation
        # checks precede the first assignment. No rollback hides partial mutation.
        next_notes = self.notes + outputs
        receipt = _receipt(txid, tx, next_notes)
        retained_tx = copy.deepcopy(tx)
        retained_receipt = copy.deepcopy(receipt)
        initial = (list(self.notes) if self._initial_commitments is None
                   else self._initial_commitments)
        next_spent = self.spent | {nf}
        next_txs = {**self.transactions, txid: retained_tx}
        next_receipts = {**self.receipts, txid: retained_receipt}
        self.notes, self.spent = next_notes, next_spent
        self.transactions, self.receipts = next_txs, next_receipts
        self._initial_commitments = initial
        return copy.deepcopy(receipt)

    def recover_receipt(self, txid):
        with self._lock:
            key(txid, "transaction id")
            if txid not in self.receipts:
                raise NoteError("receipt unavailable")
            return copy.deepcopy(self.receipts[txid])

    def disclose(self, txid, output_index, opening):
        return disclose(txid, output_index, opening, self.recover_receipt(txid))

    def verify_disclosure(self, bundle):
        bundle = _snapshot(bundle)
        schema(bundle, DISCLOSURE_FIELDS, "disclosure")
        receipt = self.recover_receipt(bundle["txid"])
        return verify_disclosure(bundle, receipt)


def disclose(txid, output_index, opening, receipt):
    """Reveal exactly one opening against a retained, externally trusted receipt.

    Public viewing material and a secret commitment are non-secret fields. The
    note secret, private keys and other openings are never accepted by the schema.
    """
    opening = _snapshot(opening)
    receipt = _snapshot(receipt)
    _validate_receipt(receipt)
    key(txid, "transaction id")
    integer(output_index, "output index", MAX_OUTPUTS - 1)
    if receipt["txid"] != txid or output_index >= len(receipt["outputs"]):
        raise NoteError("disclosure transaction or index mismatch")
    commitment = note_commitment(opening)
    if commitment != receipt["outputs"][output_index]["commitment"]:
        raise NoteError("selected output opening mismatch")
    bundle = {
        "version": 1, "txid": txid, "output_index": output_index,
        "receipt_commitment": h(b"receipt", receipt), "commitment": commitment,
        "opening": copy.deepcopy(opening), "linkability": LINKABILITY,
    }
    verify_disclosure(bundle, receipt)
    return bundle


def verify_disclosure(bundle, receipt):
    """Verify the bundle against the caller's trusted retained public receipt."""
    bundle = _snapshot(bundle)
    receipt = _snapshot(receipt)
    schema(bundle, DISCLOSURE_FIELDS, "disclosure")
    enc(bundle)
    version(bundle["version"])
    key(bundle["txid"], "transaction id")
    key(bundle["receipt_commitment"], "receipt commitment")
    key(bundle["commitment"], "output commitment")
    index = integer(bundle["output_index"], "output index", MAX_OUTPUTS - 1)
    if bundle["linkability"] != LINKABILITY:
        raise NoteError("missing disclosure linkability label")
    _validate_receipt(receipt)
    if (bundle["txid"] != receipt["txid"]
            or bundle["receipt_commitment"] != h(b"receipt", receipt)
            or index >= len(receipt["outputs"])):
        raise NoteError("disclosure receipt mismatch")
    if (note_commitment(bundle["opening"]) != bundle["commitment"]
            or bundle["commitment"] != receipt["outputs"][index]["commitment"]):
        raise NoteError("disclosure opening or index mismatch")
    return True
