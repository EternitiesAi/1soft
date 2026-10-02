"""Test-only audit of a completed browser attachment in an owned DEV fixture.

No production path selector or authority. Never publish decrypted private bytes.
"""
import hashlib
from pathlib import Path
import stat
from unittest.mock import patch
from block_application import encode
from p4_custody import restore_backup, RecoveryArchive, _cell
from p4_custody_stream import capture_pair, stream_pair, TABLES
from p4_wallet import P4Wallet
from p4_delivery import P4Delivery

PASSWORD = b'fixture passphrase not for funds'


def _rows(pair):
    wdb, ddb = pair[:2]
    rows = []
    for source, table, _, _ in TABLES:
        db = wdb if source == 0 else ddb
        rows.append([[ _cell(v) for v in row ] for row in db.execute(f'SELECT * FROM {table} ORDER BY 1')])
    return rows


def _refuse(*_args, **_kwargs):
    raise AssertionError('history audit/export must not unlock, sign or submit')


def audit_download(service_factory, download_dir, filename, stage):
    root = Path(download_dir).resolve()
    assert root.is_dir() and not root.is_symlink() and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert type(filename) is str and filename == Path(filename).name
    assert filename in ('signed-pending.backup', 'receipt-complete.backup', 'historical.backup')
    assert stage in ('signed-pending', 'receipt-complete', 'historical')
    source = root / filename
    info = source.lstat()
    assert stat.S_ISREG(info.st_mode) and not source.is_symlink()
    source.chmod(0o600)  # Browser save API need not honor Linux umask through the UNC bridge.
    assert 0 < info.st_size <= 16 * 1024 * 1024
    archive_path = root / (filename + '.recovery.sqlite')
    assert not archive_path.exists()
    with patch('p4_wallet._load_vault', _refuse), patch.object(P4Wallet, 'approve', _refuse), patch.object(P4Delivery, 'send', _refuse):
        with service_factory() as svc:
            delivery = svc.delivery
            with capture_pair(delivery) as pair:
                before_rows = _rows(pair)
            before_digest = hashlib.sha256(encode(before_rows)).hexdigest()
            restored = restore_backup(source, archive_path, svc.genesis, svc.policy, PASSWORD)
            assert restored['backup_format_version'] == 3 and restored['status'] == 'restored-recovery-only'
            with RecoveryArchive(archive_path, svc.genesis, svc.policy) as archive:
                with stream_pair(archive._chunks) as pair:
                    archive_rows = _rows(pair)
                assert archive_rows == before_rows
                inspected = archive.inspect()
                assert inspected['current_spending_authority'] is False
                assert all(inspected[k] is False for k in ('signing_enabled','dispatch_enabled','automatic_resend','trust_policy_renewed','private_keys_restored','latestness_established','old_device_fenced'))
                _, _, _, decisions, _ = delivery.wallet._load(historical=True)
                recovered = []
                for d in decisions:
                    payer = d['review']['body']['sender']; grant = d['review']['body']['grant_id']
                    raw = bytes.fromhex(d['wire_hex'])
                    assert archive.recover(d['id'], payer=payer, grant_id=grant) == raw
                    recovered.append({'decision_id':d['id'],'wire_sha256':hashlib.sha256(raw).hexdigest()})
                live_receipts = delivery._audit(decisions)[2]
                for did, value in live_receipts.items():
                    d = next(d for d in decisions if d['id'] == did)
                    archived = archive.export_receipt(did,payer=d['review']['body']['sender'],grant_id=d['review']['body']['grant_id'])
                    assert encode(archived) == encode(value['evidence'])
                assert len(inspected['decisions']) == len(decisions)
                with capture_pair(delivery) as pair:
                    after_rows = _rows(pair)
                assert after_rows == before_rows
            return {'schema':1,'stage':stage,'passed':True,'backup_format_version':3,
                'ciphertext_bytes':info.st_size,'ciphertext_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                'snapshot_id':restored['snapshot_id'],'canonical_pair_rows_sha256':before_digest,
                'all_seven_tables_exact':True,'source_logical_rows_unchanged':True,
                'recovered_originals':recovered,'retained_delivery_receipts':len(live_receipts),
                'pending_debit_units':inspected['pending_debit_units'],
                'spending_authority':False,'keys_unlocked':False,'signing_or_submission_performed':False,
                'forbidden_key_sign_send_scope':'post-download audit phase only; generation is covered separately by service tests/static review and actual forbidden-vault historical launcher',
                'scope':'completed Chromium attachment decrypted by original canonical recovery-only decoder; exact seven-table and financial audit against the owned live fixture'}
