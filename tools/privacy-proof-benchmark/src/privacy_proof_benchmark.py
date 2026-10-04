"""Strict receipt contract for the isolated 1soft privacy-proof benchmark.

This module validates evidence emitted by the owned benchmark executable.  It
does not verify a Groth16 proof itself and cannot promote the candidate into a
production privacy, consensus, custody, network, or real-funds boundary.
"""
from __future__ import annotations

import copy
import json
import re


class QualificationError(ValueError):
    pass


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECEIPT_BYTES = 1_048_576

EXPECTED_PUBLIC_INPUTS = (
    "version",
    "genesis",
    "asset",
    "context",
    "epoch",
    "height",
    "expiry",
    "policy",
    "root",
    "nullifier",
    "output_commitment_0",
    "output_commitment_1",
    "fee",
    "authorization_digest",
)

EXPECTED_CASES = {
    "valid-proof": "accept",
    "mutated-proof": "reject",
    "changed-public-input": "reject",
    "wrong-verifying-key": "reject",
    "invalid-membership": "reject",
    "invalid-nullifier": "reject",
    "invalid-output-commitment": "reject",
    "invalid-fee-conservation": "reject",
    "out-of-range-value": "reject",
    "changed-authorization-digest": "reject",
}

EXPECTED_CLAIMS = {
    "production_privacy": False,
    "consensus_integrated": False,
    "network_anonymity": False,
    "production_custody": False,
    "real_funds": False,
    "independent_review": False,
}

EXPECTED_UNASSESSED = (
    "global nullifier uniqueness and consensus ordering",
    "production parameter ceremony",
    "independent cryptographic review",
    "wallet scanning and recovery",
    "network anonymity and metadata resistance",
    "production custody and side-channel resistance",
    "public-network and real-funds safety",
)

TOP_FIELDS = {
    "format",
    "status",
    "actual_backend_run",
    "backend",
    "circuit",
    "source",
    "parameters",
    "artifacts",
    "metrics",
    "cases",
    "claims",
    "unassessed",
}


def _fail(message):
    raise QualificationError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key: " + key)
        result[key] = value
    return result


def _reject_number(value):
    _fail("non-integer JSON number refused: " + value)


def load_unique_json_bytes(data):
    if type(data) is not bytes or len(data) > MAX_RECEIPT_BYTES:
        _fail("invalid receipt bytes")
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except QualificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise QualificationError("invalid receipt JSON") from exc


def _exact_dict(value, fields, name):
    if type(value) is not dict or set(value) != set(fields):
        _fail("invalid " + name + " fields")
    return value


def _integer(value, name, minimum=1):
    if type(value) is not int or value < minimum:
        _fail("invalid " + name)
    return value


def _hex(value, pattern, name):
    if type(value) is not str or not pattern.fullmatch(value):
        _fail("invalid " + name)
    return value


def _exact_value(value, expected, name):
    if type(value) is not type(expected) or value != expected:
        _fail("invalid " + name)
    return value


def validate_backend_receipt(
    receipt,
    *,
    expected_commit,
    expected_tree,
    expected_circuit_digest,
):
    """Validate exact benchmark evidence and return an isolated copy.

    The caller supplies the independently observed Git and circuit identities.
    A structurally valid JSON document alone is not evidence that a backend ran.
    The component verifier must own process execution and pass those identities.
    """
    receipt = copy.deepcopy(receipt)
    _exact_dict(receipt, TOP_FIELDS, "receipt")
    _exact_value(receipt["format"], 1, "format")
    _exact_value(receipt["status"], "passed", "status")
    _exact_value(receipt["actual_backend_run"], True, "actual backend run")

    backend = _exact_dict(
        receipt["backend"],
        {"id", "gnark", "gnark_crypto", "curve", "proof_system", "hash", "license"},
        "backend",
    )
    expected_backend = {
        "id": "gnark-groth16-bn254",
        "gnark": "v0.16.3",
        "gnark_crypto": "v0.21.0",
        "curve": "BN254",
        "proof_system": "Groth16",
        "hash": "Poseidon2",
        "license": "Apache-2.0",
    }
    if backend != expected_backend:
        _fail("backend identity differs from pinned candidate")

    circuit = _exact_dict(
        receipt["circuit"],
        {
            "id",
            "source_digest",
            "constraints",
            "depth",
            "inputs",
            "outputs",
            "value_bits",
            "public_inputs",
            "private_inputs_retained",
        },
        "circuit",
    )
    _exact_value(circuit["id"], "1soft/privacy-proof-benchmark/v1", "circuit id")
    _hex(circuit["source_digest"], HEX64, "circuit source digest")
    _hex(expected_circuit_digest, HEX64, "expected circuit source digest")
    if circuit["source_digest"] != expected_circuit_digest:
        _fail("circuit source digest differs")
    _integer(circuit["constraints"], "constraint count")
    for field, expected in (("depth", 4), ("inputs", 1), ("outputs", 2), ("value_bits", 64)):
        _exact_value(circuit[field], expected, "circuit " + field)
    if circuit["public_inputs"] != list(EXPECTED_PUBLIC_INPUTS):
        _fail("public input inventory differs")
    _exact_value(circuit["private_inputs_retained"], False, "private input retention")

    source = _exact_dict(receipt["source"], {"commit", "tree"}, "source")
    for field, expected in (("commit", expected_commit), ("tree", expected_tree)):
        _hex(source[field], HEX40, "source " + field)
        _hex(expected, HEX40, "expected source " + field)
        if source[field] != expected:
            _fail("source " + field + " differs")

    parameters = _exact_dict(
        receipt["parameters"],
        {
            "kind",
            "ceremony",
            "reusable",
            "production",
            "proving_key_sha256",
            "proving_key_bytes",
            "verifying_key_sha256",
            "verifying_key_bytes",
        },
        "parameters",
    )
    _exact_value(parameters["kind"], "ephemeral-local-groth16-setup", "parameter kind")
    for field in ("ceremony", "reusable", "production"):
        _exact_value(parameters[field], False, "parameter " + field)
    for field in ("proving_key_sha256", "verifying_key_sha256"):
        _hex(parameters[field], HEX64, field)
    for field in ("proving_key_bytes", "verifying_key_bytes"):
        _integer(parameters[field], field)

    artifacts = _exact_dict(
        receipt["artifacts"],
        {"proof_sha256", "proof_bytes", "public_witness_sha256", "public_witness_bytes"},
        "artifacts",
    )
    for field in ("proof_sha256", "public_witness_sha256"):
        _hex(artifacts[field], HEX64, field)
    for field in ("proof_bytes", "public_witness_bytes"):
        _integer(artifacts[field], field)

    metrics = _exact_dict(
        receipt["metrics"],
        {"compile_ns", "setup_ns", "iterations", "prove_ns", "verify_ns"},
        "metrics",
    )
    _integer(metrics["compile_ns"], "compile duration")
    _integer(metrics["setup_ns"], "setup duration")
    iterations = _integer(metrics["iterations"], "iterations")
    for field in ("prove_ns", "verify_ns"):
        values = metrics[field]
        if type(values) is not list or len(values) != iterations:
            _fail("invalid " + field + " inventory")
        for value in values:
            _integer(value, field + " duration")

    cases = receipt["cases"]
    if type(cases) is not list or len(cases) != len(EXPECTED_CASES):
        _fail("invalid case inventory")
    observed_ids = []
    for case, (case_id, expected) in zip(cases, EXPECTED_CASES.items()):
        _exact_dict(case, {"id", "expected", "observed"}, "case")
        _exact_value(case["id"], case_id, "case id")
        _exact_value(case["expected"], expected, "case expected result")
        _exact_value(case["observed"], expected, "case observed result")
        observed_ids.append(case["id"])
    if len(set(observed_ids)) != len(observed_ids):
        _fail("duplicate case identity")

    claims = _exact_dict(receipt["claims"], EXPECTED_CLAIMS, "claims")
    for field, expected in EXPECTED_CLAIMS.items():
        _exact_value(claims[field], expected, "claim " + field)
    if receipt["unassessed"] != list(EXPECTED_UNASSESSED):
        _fail("unassessed boundary differs")

    return receipt
