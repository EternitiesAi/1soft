"""Readonly local prerequisites; no application imports, downloads or engine execution."""
from __future__ import annotations
import hashlib
import importlib.metadata
import os
from pathlib import Path
import platform
import re
import shutil
import stat

ENGINE_SHA256 = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
MAX_ENGINE_BYTES = 256 * 1024 * 1024

def dependency_checks(root: Path):
    records = []
    try:
        with (root/'requirements.txt').open('rb') as file:
            raw=file.read(65537)
        if len(raw)>65536: raise ValueError('pin file bound')
        seen=set()
        for line in raw.decode('utf-8').splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]{0,127})==([0-9]+(?:\.[0-9]+){1,3})',line)
            if not match or len(records)>=32: raise ValueError('exact pins required')
            name,expected=match.groups();identity=re.sub(r'[-_.]+','-',name).lower()
            if identity in seen: raise ValueError('duplicate dependency pin')
            seen.add(identity)
            try:
                installed=importlib.metadata.version(name)
                status='passed' if installed==expected else 'mismatch'
            except importlib.metadata.PackageNotFoundError:
                installed=None;status='missing'
            records.append(dict(name=name,expected=expected,installed=installed,status=status))
        if not records: raise ValueError('empty dependency pins')
        return 'valid',records
    except (OSError,UnicodeError,ValueError):
        return 'invalid_pins',records

def engine_check(engine: Path | None):
    report=dict(status='not_provided',expected_sha256=ENGINE_SHA256,executed=False)
    if engine is None: return report
    engine=Path(engine)
    try:
        info=engine.lstat()
    except FileNotFoundError:
        return {**report,'status':'missing'}
    except OSError:
        return {**report,'status':'unreadable'}
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 0<info.st_size<=MAX_ENGINE_BYTES:
        return {**report,'status':'unsafe_file'}
    descriptor=None
    try:
        descriptor=os.open(engine,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        before=os.fstat(descriptor)
        if (before.st_dev,before.st_ino)!=(info.st_dev,info.st_ino):
            return {**report,'status':'file_changed'}
        digest=hashlib.sha256();total=0
        while True:
            raw=os.read(descriptor,1024*1024)
            if not raw: break
            total+=len(raw)
            if total>MAX_ENGINE_BYTES: return {**report,'status':'unsafe_file'}
            digest.update(raw)
        after=os.fstat(descriptor)
        observed=digest.hexdigest()
        report.update(observed_sha256=observed,bytes=total)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or total!=after.st_size:
            return {**report,'status':'file_changed'}
        if observed!=ENGINE_SHA256: return {**report,'status':'hash_mismatch'}
        if not os.access(engine,os.X_OK): return {**report,'status':'not_executable'}
        return {**report,'status':'passed'}
    except OSError:
        return {**report,'status':'unreadable'}
    finally:
        if descriptor is not None: os.close(descriptor)

def inspect_runtime(root: Path,engine: Path | None=None):
    pin_status,dependencies=dependency_checks(Path(root))
    tools={name:dict(status='available' if shutil.which(name) else 'missing') for name in ('git','node')}
    supported=os.name=='posix' and hasattr(os,'O_NOFOLLOW')
    engine_report=engine_check(engine) if supported else dict(status='unsupported_platform',expected_sha256=ENGINE_SHA256,executed=False)
    ready=(supported and pin_status=='valid' and all(row['status']=='passed' for row in dependencies)
           and all(row['status']=='available' for row in tools.values()) and engine_report['status']=='passed')
    return dict(schema='1soft-local-preflight-v1',status='ready' if ready else 'needs_attention',
        python=platform.python_version(),platform='posix' if supported else 'use_linux_or_wsl',
        dependency_pin_status=pin_status,dependencies=dependencies,tools=tools,engine=engine_report,
        source_qualified=False,production_qualified=False,network_started=False,files_modified=False,
        scope='Installed dependency versions, tool availability and pinned engine file only. No engine execution or source/consensus qualification.',
        next='Run check with a new output directory outside the checkout; then use new with a new private development workspace.' if ready else 'Use Linux/WSL and the pinned installed prerequisites; provide --engine. This command installs or starts nothing.')
