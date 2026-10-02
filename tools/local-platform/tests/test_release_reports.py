"""Regression envelopes for the actual runners' differing provenance schemas.

These fixtures exercise report attribution, not engine or consensus execution.
The recovery runner's full evidence is revalidated separately during qualification.
"""
import unittest

try:
    from release_check import engine_report_matches
except ImportError:
    engine_report_matches = None

PIN = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
SOURCE = {'commit': 'a'*40, 'tree': 'b'*40, 'source_id': 'c'*64}
COUNTS = {'p4-baseline': 27, 'p4-delivery': 42, 'p4-ledger-receipts': 44,
          'bootstrap-after-turnover': 7, 'commit-reply-loss-at-emission': 7}


def envelope(profile):
    q = {'schema': 1, 'status': 'passed',
         'checks': [{'name': 'observation-'+str(i), 'passed': True}
                    for i in range(COUNTS[profile])]}
    if profile.startswith('p4-'):
        q.update(source_commit=SOURCE['commit'], source_tree=SOURCE['tree'],
                 source_dirty_before=False, source_dirty_after=False,
                 source_qualified=True, engine_required_sha256=PIN,
                 engine_sha256_after=PIN)
        if profile == 'p4-ledger-receipts':
            q.update(source_commit_after=SOURCE['commit'], source_tree_after=SOURCE['tree'],
                     engine_unchanged=True)
        else:
            q.update(engine_sha256=PIN, engine_version='0.38.25')
    else:
        q.update(profile=profile, source=dict(SOURCE), engine_sha256=PIN,
                 engine_version='0.38.25', consensus_executed=True,
                 verification={'status': 'verified-local-acceptance', 'profile': profile,
                               'release_status': 'blocked', 'public_network': False,
                               'real_funds': False})
    return q


class RunnerReportRegressionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(engine_report_matches, 'runner provenance reader is missing')

    def test_observed_baseline_and_delivery_schema(self):
        for profile in ('p4-baseline', 'p4-delivery'):
            self.assertTrue(engine_report_matches(envelope(profile), SOURCE, profile))

    def test_observed_ledger_schema_without_initial_hash_field(self):
        q = envelope('p4-ledger-receipts')
        self.assertNotIn('engine_sha256', q)
        self.assertTrue(engine_report_matches(q, SOURCE, 'p4-ledger-receipts'))

    def test_recovery_source_is_nested_and_profile_bound(self):
        for profile in ('bootstrap-after-turnover', 'commit-reply-loss-at-emission'):
            self.assertTrue(engine_report_matches(envelope(profile), SOURCE, profile))

    def test_missing_or_mismatched_after_hash_refused_for_every_legacy_runner(self):
        for profile in ('p4-baseline', 'p4-delivery', 'p4-ledger-receipts'):
            for value in (None, '0'*64):
                q = envelope(profile);q['engine_sha256_after'] = value
                self.assertFalse(engine_report_matches(q, SOURCE, profile))

    def test_required_pin_alone_cannot_replace_observed_initial_hash(self):
        q = envelope('p4-delivery');q.pop('engine_sha256')
        self.assertFalse(engine_report_matches(q, SOURCE, 'p4-delivery'))

    def test_ledger_requires_unchanged_engine_and_final_source(self):
        for key, value in (('engine_unchanged', False), ('source_commit_after', 'd'*40),
                           ('source_tree_after', 'd'*40)):
            q = envelope('p4-ledger-receipts');q[key] = value
            self.assertFalse(engine_report_matches(q, SOURCE, 'p4-ledger-receipts'))

    def test_reports_from_other_source_cannot_be_reused(self):
        for profile in COUNTS:
            q = envelope(profile)
            if profile.startswith('p4-'):q['source_commit'] = 'd'*40
            else:q['source']['source_id'] = 'd'*64
            self.assertFalse(engine_report_matches(q, SOURCE, profile))

    def test_dirty_or_unqualified_source_is_refused(self):
        for key in ('source_dirty_before', 'source_dirty_after', 'source_qualified'):
            q = envelope('p4-baseline');q[key] = key != 'source_qualified'
            self.assertFalse(engine_report_matches(q, SOURCE, 'p4-baseline'))

    def test_failed_missing_or_duplicate_observations_are_refused(self):
        for profile in COUNTS:
            for change in ('failed', 'missing', 'duplicate', 'truthy'):
                q = envelope(profile)
                if change == 'failed':q['checks'][0]['passed'] = False
                elif change == 'missing':q['checks'].pop()
                elif change == 'duplicate':q['checks'][0]['name'] = q['checks'][1]['name']
                else:q['checks'][0]['passed'] = 1
                self.assertFalse(engine_report_matches(q, SOURCE, profile))

    def test_recovery_requires_correct_profile_and_verified_summary(self):
        profile = 'bootstrap-after-turnover'
        for key, value in (('profile', 'commit-reply-loss-at-emission'),
                           ('status', 'unassessed'), ('real_funds', True)):
            q = envelope(profile);q['verification'][key] = value
            self.assertFalse(engine_report_matches(q, SOURCE, profile))

    def test_failed_result_and_nonexecuted_recovery_are_refused(self):
        for profile in COUNTS:
            q = envelope(profile);q['status'] = 'failed'
            self.assertFalse(engine_report_matches(q, SOURCE, profile))
        q = envelope('bootstrap-after-turnover');q['consensus_executed'] = None
        self.assertFalse(engine_report_matches(q, SOURCE, 'bootstrap-after-turnover'))

    def test_unknown_profile_or_unexpected_version_is_refused(self):
        q = envelope('p4-delivery')
        self.assertFalse(engine_report_matches(q, SOURCE, 'unknown'))
        q['engine_version'] = '0.38.24'
        self.assertFalse(engine_report_matches(q, SOURCE, 'p4-delivery'))


if __name__ == '__main__':
    unittest.main()
