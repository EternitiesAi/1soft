import os
from pathlib import Path
import tempfile
import unittest

try:
    from local_devnet import WorkspaceLock, read_private, private_new, verify_engine, initialize
except ImportError:
    WorkspaceLock=read_private=private_new=verify_engine=initialize=None


class DevnetSafetyTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(WorkspaceLock,'local network lifecycle is missing')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
    def tearDown(self):
        if hasattr(self,'tmp'):self.tmp.cleanup()
    def test_exclusive_private_creation_and_no_overwrite(self):
        p=self.root/'file';private_new(p,b'first')
        self.assertEqual(0o600,p.stat().st_mode&0o777)
        with self.assertRaises(FileExistsError):private_new(p,b'second')
        self.assertEqual(b'first',read_private(p))
    def test_read_refuses_public_file_hardlink_and_symlink(self):
        p=self.root/'file';private_new(p,b'first');p.chmod(0o644)
        with self.assertRaises(ValueError):read_private(p)
        p.chmod(0o600);alias=self.root/'alias';os.link(p,alias)
        with self.assertRaises(ValueError):read_private(p)
        alias.unlink();alias.symlink_to(p)
        with self.assertRaises(ValueError):read_private(alias)
    def test_private_read_bound(self):
        p=self.root/'file';private_new(p,b'x'*1025)
        with self.assertRaises(ValueError):read_private(p,maximum=1024)
    def test_lock_owns_exact_workspace_and_contends(self):
        p=self.root/'owner.lock';private_new(p,b'')
        with WorkspaceLock(self.root):
            with self.assertRaises(ValueError):
                with WorkspaceLock(self.root):pass
        with WorkspaceLock(self.root):pass
    def test_lock_refuses_missing_symlink_and_aliased_lock(self):
        with self.assertRaises(ValueError):
            with WorkspaceLock(self.root):pass
        p=self.root/'owner.lock';other=self.root/'other';private_new(other,b'');p.symlink_to(other)
        with self.assertRaises(ValueError):
            with WorkspaceLock(self.root):pass
    def test_bad_engine_pin_is_refused_before_execution(self):
        p=self.root/'fake-engine';private_new(p,b'#!/bin/sh\nexit 0\n');p.chmod(0o700)
        with self.assertRaises(ValueError):verify_engine(p,'0'*64)
        with self.assertRaises(ValueError):verify_engine(p,'UPPER')
    def test_initialize_bad_pin_never_creates_workspace(self):
        p=self.root/'fake-engine';private_new(p,b'not executable')
        target=self.root/'new'
        with self.assertRaises(ValueError):initialize(target,p,'0'*64,password=b'development passphrase')
        self.assertFalse(target.exists())
    def test_initialize_cannot_overwrite_owned_existing_path(self):
        p=self.root/'fake-engine';private_new(p,b'not executable')
        private_new(self.root/'valuable',b'save')
        with self.assertRaises((ValueError,FileExistsError)):
            initialize(self.root,p,'0'*64,password=b'development passphrase')
        self.assertEqual(b'save',read_private(self.root/'valuable'))


if __name__=='__main__':unittest.main()
