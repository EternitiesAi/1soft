"""Original private artifact membership, permissions and byte validation."""
from pathlib import Path
import tempfile
import unittest
from check_protocol4_state_sync import artifact_manifest,verify_private_artifacts

class Protocol4PrivateArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.log=self.root/'engine.log';self.log.write_bytes(b'original engine stdout\n');self.log.chmod(0o600)
    def tearDown(self):self.tmp.cleanup()
    def test_manifest_records_original_file_and_private_mode(self):
        record=artifact_manifest(self.root)
        self.assertEqual([r['path'] for r in record],['engine.log'])
        self.assertEqual(record[0]['mode'],'0600')
        self.assertEqual(record[0]['bytes'],23)
    def test_changed_original_bytes_refused(self):
        value={'artifacts':artifact_manifest(self.root),'logs':[]}
        self.log.write_bytes(b'changed')
        with self.assertRaises(ValueError):verify_private_artifacts(value,self.root)
    def test_extra_original_file_refused(self):
        value={'artifacts':artifact_manifest(self.root),'logs':[]}
        extra=self.root/'extra';extra.write_text('unlisted');extra.chmod(0o600)
        with self.assertRaises(ValueError):verify_private_artifacts(value,self.root)
    def test_symlink_or_public_private_fixture_refused(self):
        self.log.chmod(0o644)
        with self.assertRaises(ValueError):artifact_manifest(self.root)
        self.log.chmod(0o600);(self.root/'alias').symlink_to(self.log)
        with self.assertRaises(ValueError):artifact_manifest(self.root)
