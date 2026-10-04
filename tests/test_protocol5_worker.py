from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest

from protocol5_encoding import (
    DEPLOYMENT_DOMAIN, DeploymentBinding, ProfileDescriptor, canonical_json,
    field_bytes, genesis_document, h2f,
)
from protocol5_fixture import make_genesis, make_public_fields
from protocol5_worker import (
    INVALID_PROOF, OK, VerifierUnavailable, WorkerClient,
)
from shielded_worker_fixture import KAT_DOMAIN, kat_bytes, profile_bytes, write_worker

class Protocol5WorkerTests(unittest.TestCase):
    def _artifacts(self, directory, mode="normal"):
        root = Path(directory)
        base = make_genesis()
        fields = tuple(bytes.fromhex(v) for v in make_public_fields(base))
        kat = kat_bytes(fields)
        profile = profile_bytes(kat)
        worker = root / "worker"
        write_worker(worker, profile, mode)
        toolchain = root / "toolchain.json"
        policy = root / "policy.json"
        toolchain.write_bytes(b'{"rust":"1.97.1"}')
        policy.write_bytes(b'{"sandbox":"fixture-only"}')
        profile_id = hashlib.sha256(
            b"1soft/shielded-profile/v1\0" + profile).digest()
        deployment = (
            b"1SFTDEP1" + struct.pack("<HH", 1, 1) + profile_id
            + hashlib.sha256(worker.read_bytes()).digest()
            + hashlib.sha256(toolchain.read_bytes()).digest()
            + hashlib.sha256(policy.read_bytes()).digest()
        )
        genesis = make_genesis(
            profile_descriptor=base64.b64encode(profile).decode("ascii"),
            profile_id=profile_id.hex(),
            deployment_binding=base64.b64encode(deployment).decode("ascii"),
            deployment_id=hashlib.sha256(
                b"1soft/shielded-deployment/v1\0" + deployment).hexdigest(),
        )
        return worker, toolchain, policy, kat, genesis_document(canonical_json(genesis))

    def test_startup_binds_profile_deployment_kat_and_increasing_ids(self):
        with tempfile.TemporaryDirectory() as td:
            worker, toolchain, policy, kat, genesis = self._artifacts(td)
            with WorkerClient(worker, genesis, kat, toolchain, policy) as client:
                self.assertEqual(client.next_request_id, 4)
                root = client.tree_root([])
                self.assertEqual(len(root), 32)
                self.assertEqual(client.next_request_id, 5)
                self.assertEqual(
                    client.verify_proof(tuple(bytes.fromhex(v) for v in make_public_fields(genesis.value)),
                                        b"BAD!"),
                    INVALID_PROOF,
                )
                self.assertEqual(client.next_request_id, 6)

    def test_symlink_or_broad_write_worker_is_refused_before_launch(self):
        with tempfile.TemporaryDirectory() as td:
            worker, toolchain, policy, kat, genesis = self._artifacts(td)
            link = Path(td) / "link"
            link.symlink_to(worker)
            with self.assertRaises(VerifierUnavailable):
                WorkerClient(link, genesis, kat, toolchain, policy)
            worker.chmod(0o722)
            with self.assertRaises(VerifierUnavailable):
                WorkerClient(worker, genesis, kat, toolchain, policy)

    def test_protocol_fault_permanently_quarantines_client(self):
        for mode in ("wrong_id", "internal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                worker, toolchain, policy, kat, genesis = self._artifacts(td, mode)
                with self.assertRaises(VerifierUnavailable):
                    WorkerClient(worker, genesis, kat, toolchain, policy)

    @unittest.skipUnless(
        os.environ.get("ONE_P5_WORKER") and os.environ.get("ONE_P5_PROFILE")
        and os.environ.get("ONE_P5_KAT") and os.environ.get("ONE_P5_TOOLCHAIN")
        and os.environ.get("ONE_P5_POLICY") and os.environ.get("ONE_P5_GENESIS"),
        "real Protocol 5 release worker inputs unavailable; cryptographic startup unassessed",
    )
    def test_actual_release_worker_and_kat(self):
        genesis = genesis_document(Path(os.environ["ONE_P5_GENESIS"]).read_bytes())
        with WorkerClient(
            Path(os.environ["ONE_P5_WORKER"]), genesis,
            Path(os.environ["ONE_P5_KAT"]).read_bytes(),
            Path(os.environ["ONE_P5_TOOLCHAIN"]),
            Path(os.environ["ONE_P5_POLICY"]),
        ) as client:
            self.assertFalse(client.quarantined)

if __name__ == "__main__":
    unittest.main()
