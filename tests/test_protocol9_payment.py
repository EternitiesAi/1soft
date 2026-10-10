"""Single-attempt authority ordering; native wallet execution is a separate gate."""
import unittest
from unittest.mock import patch
from protocol9_wallet import RecipientWallet
import protocol8_transfer as n
try: from protocol9_payment import send_once
except ModuleNotFoundError: send_once=None

class CallerTests(unittest.TestCase):
    def test_missing_wallet_or_remote_endpoint_never_dispatches(self):
        self.assertIsNotNone(send_once,'P9 single-attempt caller is missing')
        with patch('protocol8_payment.dispatch',side_effect=AssertionError('unexpected I/O')):
            with self.assertRaises(ValueError):send_once(object(),'11'*32,'http://127.0.0.1:1234')
            wallet=object.__new__(RecipientWallet)
            for endpoint in ('https://example.com','http://localhost:1234','http://127.0.0.1:0'):
                with self.assertRaises(ValueError):send_once(wallet,'11'*32,endpoint)
    def test_failed_attempt_marker_never_reaches_transport(self):
        self.assertIsNotNone(send_once,'P9 single-attempt caller is missing')
        wallet=object.__new__(RecipientWallet)
        with patch.object(wallet,'export',return_value=b'original'),patch.object(wallet,'mark_attempt',side_effect=n.Invalid('original held')):
            with patch('protocol8_payment.dispatch',side_effect=AssertionError('attempt boundary bypassed')):
                with self.assertRaises(n.Invalid):send_once(wallet,'11'*32,'http://127.0.0.1:1234')

if __name__=='__main__':unittest.main()
