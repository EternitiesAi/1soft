"""Merchant route explicitly exports canonical global history without invoice decryption."""
import hashlib
import json
import unittest
from unittest.mock import patch

import test_merchant_browser as helpers
from payment_requests import new_request
from p4_custody import restore_backup, RecoveryArchive
from wallet_fixture import PASSWORD

SECRET=b'public merchant history passphrase'


class MerchantHistoryTests(unittest.TestCase):
    setUp=helpers.MerchantBrowserTests.setUp
    stop_web=helpers.MerchantBrowserTests.stop_web
    call=helpers.MerchantBrowserTests.call
    platform=helpers.MerchantBrowserTests.platform
    service=helpers.MerchantBrowserTests.service
    prepare=helpers.MerchantBrowserTests.prepare
    sign_body=helpers.MerchantBrowserTests.sign_body

    def test_global_download_retains_hidden_generic_other_role_and_excludes_invoice_keys(self):
        p=self.prepare();self.assertEqual(200,self.call('POST','/api/sign-invoice',self.sign_body(p))[0])
        with self.platform() as svc:
            value=new_request(self.chain.policy['genesis_sha256'],self.chain.merchant,'1',
                created_ns=self.chain.now,expires_ns=self.chain.now+600*10**9,note='HIDDEN_GENERIC_NOTE_SENTINEL')
            rid=svc.add_request(value)['request_id']
            review=svc.prepare(rid,'atlas',valid_until=30)
            did=svc.approve(rid,'atlas',review['review'],review['confirmation'],password=PASSWORD)['decision_id']
            wire=svc.recover(rid)
            before={name:tuple(getattr(svc,name).db.iterdump()) for name in ('wallet','delivery','store','book')}
        self.chain.now+=3700*10**9
        with (patch('p4_wallet._load_vault',side_effect=AssertionError('vault access')),
              patch('invoice_book.InvoiceBook.decrypt',side_effect=AssertionError('invoice decrypt'))):
            code,raw,_=self.call('POST','/api/backup-history',dict(passphrase=SECRET.decode(),repeat_passphrase=SECRET.decode(),scope_confirmed=True))
        self.assertEqual(200,code,raw)
        backup=self.root/'history.p4b3';backup.write_bytes(raw);backup.chmod(0o600)
        archive_path=self.root/'recovery.sqlite'
        restore_backup(backup,archive_path,self.chain.genesis,self.chain.policy,SECRET)
        with RecoveryArchive(archive_path,self.chain.genesis,self.chain.policy) as archive:
            view=archive.inspect();self.assertEqual(2,len(view['decisions']))
            self.assertEqual(wire,archive.recover(did,payer=self.chain.payer,grant_id='atlas'))
            self.assertFalse(view['signing_enabled']);self.assertFalse(view['current_spending_authority'])
            for sentinel in (b'SECRET_INVOICE_SENTINEL',b'HIDDEN_GENERIC_NOTE_SENTINEL',b'PRIVATE KEY'):
                self.assertNotIn(sentinel,archive_path.read_bytes())
        with self.platform() as svc:
            self.assertEqual(before,{name:tuple(getattr(svc,name).db.iterdump()) for name in ('wallet','delivery','store','book')})
        self.assertEqual(200,self.call('GET','/api/session')[0])
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))


if __name__=='__main__':unittest.main()
