from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from protocol5_encoding import canonical_json, derive_genesis_field, genesis_document
from protocol5_fixture import PROFILE_BYTES, make_genesis
from build_protocol5_inputs import (
    SETTINGS_KEYS, _write_new, build_protocol5_inputs,
)


class Protocol5InputBuilderTests(unittest.TestCase):
    def _inputs(self, root: Path):
        worker = root / "shielded-verifier-worker"
        profile = root / "profile-descriptor-v1.bin"
        toolchain = root / "toolchain-manifest-v1.json"
        policy = root / "sandbox-policy-v1.json"
        settings = root / "settings.json"
        worker.write_bytes(b"exact worker")
        profile.write_bytes(PROFILE_BYTES)
        toolchain.write_bytes(b'{"toolchain":"fixture"}\n')
        policy.write_bytes(b'{"sandbox":"fixture"}\n')
        source = make_genesis()
        settings.write_bytes(canonical_json({
            name: source[name] for name in (
                "chain_id", "asset_field", "context_field", "policy_field",
                "authority_epoch", "fee", "validators", "limits",
            )
        }))
        return worker, profile, toolchain, policy, settings

    def test_tracked_qualification_settings_are_canonical_and_closed(self):
        path = (Path(__file__).parents[1]
                / "reference/protocol5-qualification-settings-v1.json")
        raw = path.read_bytes()
        from protocol5_encoding import decode_canonical_json
        value = decode_canonical_json(raw)
        self.assertEqual(set(value), SETTINGS_KEYS)
        self.assertEqual(value["chain_id"], "p5-qualification-template")
        self.assertEqual(len(value["validators"]), 4)

    def test_builds_exact_deployment_and_empty_commitment_template(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worker, profile, toolchain, policy, settings = self._inputs(root)
            binding = root / "deployment-binding-v1.bin"
            genesis = root / "protocol5-template.json"
            result = build_protocol5_inputs(
                worker=worker, profile=profile, toolchain=toolchain,
                policy=policy, settings=settings,
                binding_output=binding, genesis_output=genesis)

            parsed = genesis_document(genesis.read_bytes())
            expected_binding = (
                b"1SFTDEP1" + b"\x01\x00\x01\x00"
                + parsed.profile.identity
                + hashlib.sha256(worker.read_bytes()).digest()
                + hashlib.sha256(toolchain.read_bytes()).digest()
                + hashlib.sha256(policy.read_bytes()).digest()
            )
            self.assertEqual(binding.read_bytes(), expected_binding)
            self.assertEqual(parsed.deployment.raw, expected_binding)
            self.assertEqual(parsed.value["initial_commitments"], [])
            self.assertEqual(
                bytes.fromhex(parsed.value["genesis_field"]),
                derive_genesis_field(parsed.value))
            self.assertEqual(result["deployment_id"], parsed.deployment.identity.hex())
            self.assertEqual(result["genesis_sha256"], parsed.sha256.hex())
            self.assertEqual(
                parsed.value["profile_descriptor"],
                base64.b64encode(PROFILE_BYTES).decode("ascii"))

    def test_is_byte_deterministic_and_binds_worker(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inputs = self._inputs(root)
            outputs = []
            for suffix in ("a", "b"):
                binding = root / f"binding-{suffix}.bin"
                genesis = root / f"genesis-{suffix}.json"
                build_protocol5_inputs(
                    worker=inputs[0], profile=inputs[1], toolchain=inputs[2],
                    policy=inputs[3], settings=inputs[4],
                    binding_output=binding, genesis_output=genesis)
                outputs.append((binding.read_bytes(), genesis.read_bytes()))
            self.assertEqual(outputs[0], outputs[1])

            inputs[0].write_bytes(b"different exact worker")
            changed_binding = root / "binding-c.bin"
            changed_genesis = root / "genesis-c.json"
            build_protocol5_inputs(
                worker=inputs[0], profile=inputs[1], toolchain=inputs[2],
                policy=inputs[3], settings=inputs[4],
                binding_output=changed_binding, genesis_output=changed_genesis)
            self.assertNotEqual(outputs[0][0], changed_binding.read_bytes())
            self.assertNotEqual(outputs[0][1], changed_genesis.read_bytes())

    def test_rejects_invalid_manifests_and_unlinks_partial_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worker, profile, toolchain, policy, settings = self._inputs(root)
            toolchain.write_bytes(b"")
            with self.assertRaises(ValueError):
                build_protocol5_inputs(
                    worker=worker, profile=profile, toolchain=toolchain,
                    policy=policy, settings=settings,
                    binding_output=root / "binding.bin",
                    genesis_output=root / "genesis.json")
            self.assertFalse((root / "binding.bin").exists())

            partial = root / "partial.bin"
            with mock.patch("build_protocol5_inputs.os.fsync",
                            side_effect=OSError("disk fault")):
                with self.assertRaises(OSError):
                    _write_new(partial, b"partial")
            self.assertFalse(partial.exists())

    def test_rejects_noncanonical_settings_and_preserves_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worker, profile, toolchain, policy, settings = self._inputs(root)
            binding = root / "binding.bin"
            genesis = root / "genesis.json"
            settings.write_bytes(settings.read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                build_protocol5_inputs(
                    worker=worker, profile=profile, toolchain=toolchain,
                    policy=policy, settings=settings,
                    binding_output=binding, genesis_output=genesis)
            self.assertFalse(binding.exists())
            self.assertFalse(genesis.exists())

            source = make_genesis()
            settings.write_bytes(canonical_json({
                name: source[name] for name in (
                    "chain_id", "asset_field", "context_field", "policy_field",
                    "authority_epoch", "fee", "validators", "limits",
                )
            }))
            binding.write_bytes(b"preserve")
            with self.assertRaises(FileExistsError):
                build_protocol5_inputs(
                    worker=worker, profile=profile, toolchain=toolchain,
                    policy=policy, settings=settings,
                    binding_output=binding, genesis_output=genesis)
            self.assertEqual(binding.read_bytes(), b"preserve")
            self.assertFalse(genesis.exists())


if __name__ == "__main__":
    unittest.main()