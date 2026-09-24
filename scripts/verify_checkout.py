#!/usr/bin/env python3
"""Detect an incomplete or altered checkout before running development gates.

This is an integrity check against a local manifest, not a signature, independent
security audit, or assertion that a blockchain network has been exercised.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath

MAX_MANIFEST_BYTES = 1_048_576
MAX_FILE_BYTES = 16_777_216
MAX_FILES = 2048


class CheckoutError(ValueError):
    pass


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CheckoutError('duplicate JSON field')
        result[key] = value
    return result


def _relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise CheckoutError('invalid manifest path')
    if '\\' in value or ':' in value or any(ord(c) < 32 for c in value):
        raise CheckoutError('invalid manifest path')
    parts = value.split('/')
    if any(p in ('', '.', '..') or p.casefold() == '.git' for p in parts):
        raise CheckoutError('unsafe manifest path')
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        raise CheckoutError('noncanonical manifest path')
    return path


def verify_checkout(root: Path, manifest_name: str = 'SOURCE_MANIFEST.json') -> dict:
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise CheckoutError('checkout root is not a directory')
    manifest_path = root / _relative_path(manifest_name)
    _regular_file(root, manifest_path)
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise CheckoutError('manifest too large')
    try:
        raw = manifest_path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise CheckoutError('manifest too large')
        manifest = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckoutError('unreadable source manifest') from exc
    if type(manifest) is not dict or set(manifest) != {'schema', 'project', 'scope', 'files'}:
        raise CheckoutError('invalid manifest fields')
    if type(manifest['schema']) is not int or manifest['schema'] != 1:
        raise CheckoutError('unsupported manifest schema')
    if manifest['project'] != '1soft' or manifest['scope'] != 'required-source-files':
        raise CheckoutError('wrong manifest project or scope')
    entries = manifest['files']
    if type(entries) is not list or not 1 <= len(entries) <= MAX_FILES:
        raise CheckoutError('empty or oversized source inventory')
    seen = set()
    # Validate every path and shape before inspecting any listed source file.
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'path', 'sha256', 'bytes'}:
            raise CheckoutError('invalid source entry')
        name = str(_relative_path(entry['path']))
        if name in seen or name == manifest_name:
            raise CheckoutError('duplicate or self-referential source entry')
        seen.add(name)
        if type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= MAX_FILE_BYTES:
            raise CheckoutError('invalid expected source size')
        if type(entry['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', entry['sha256']) is None:
            raise CheckoutError('invalid expected source digest')
    errors = []
    checked = 0
    for entry in entries:
        path = root / entry['path']
        try:
            _regular_file(root, path)
            if path.stat().st_size != entry['bytes']:
                raise CheckoutError('size differs')
            data = path.read_bytes()
            if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise CheckoutError('digest differs')
            checked += 1
        except (OSError, CheckoutError) as exc:
            errors.append({'path': entry['path'], 'error': str(exc)})
    return {'schema': 1, 'status': 'passed' if not errors else 'failed',
            'scope': 'required-source-files', 'required': len(entries), 'matched': checked,
            'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'errors': errors,
            'consensus_verified': False}


def _regular_file(root: Path, path: Path) -> None:
    current = root
    parts = path.relative_to(root).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise CheckoutError('missing file or directory') from exc
        if stat.S_ISLNK(mode):
            raise CheckoutError('symbolic links are not accepted')
        if index < len(parts) - 1:
            if not stat.S_ISDIR(mode):
                raise CheckoutError('parent is not a directory')
        elif not stat.S_ISREG(mode):
            raise CheckoutError('source is not a regular file')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        report = verify_checkout(args.root)
    except (OSError, CheckoutError) as exc:
        report = {'schema': 1, 'status': 'failed', 'scope': 'required-source-files',
                  'error': str(exc), 'consensus_verified': False}
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
