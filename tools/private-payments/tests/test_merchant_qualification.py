"""Qualification must refuse incomplete or misattributed merchant evidence."""
from copy import deepcopy
import unittest

from merchant_qualification import (MERCHANT_CHECKS, MERCHANT_CLI_COMMANDS,
    actual_report_matches, private_report_matches)

SOURCE = {'commit': 'a'*40, 'tree': 'b'*40, 'source_id': 'c'*64, 'tracked_files': 481}
RUN = 'd'*32
PIN = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'


def actual():
    return dict(schema=1, status='passed', run_id=RUN, source=SOURCE,
        source_after=SOURCE, source_unchanged=True, source_qualified=True,
        consensus_executed=True, validator_count=4, engine_version='0.38.25',
        engine_sha256=PIN, engine_sha256_after=PIN, pool_size=3,
        payer_roles=['owner','raven','atlas'], recipient_assignments_never_reused=True,
        single_financial_journal=True, native_genesis_unchanged=True,
        checks=[{'name': n, 'passed': True} for n in MERCHANT_CHECKS],
        cli_calls=[dict(interface=i, command=c, returncode=0, password_prompts=p,
            owned_processes_after_cleanup=0, stdout_sha256='e'*64,
            terminal_sha256='f'*64) for i,c,p in MERCHANT_CLI_COMMANDS],
        payments=[dict(role=role, recipient='lab_'+key*64, units=amount, fee='2',
            request_id=key*64, quote_sha256=key*64, wire_sha256=key*64,
            native_txid=key*64, capsule_sha256=key*64)
            for role,key,amount in [('owner','1','7'),('raven','2','11'),('atlas','3','13')]],
        final_balances={'payer':'957','merchants':['7','11','13'],'fees':'12','supply':'1000',
            'budget_spent':'28','pending_debit_units':'0'},
        owned_processes_after_cleanup=0, owned_threads_after_cleanup=0, cleanup_errors=[],
        real_funds=False, public_network=False, independent_hosts=False, onchain_privacy=False,
        native_signature_authenticates_resource=False, full_public_ledger_disclosed=True,
        globally_exactly_once_service_delivery=False)


def inherited():
    return dict(schema=1,status='passed',run_id='e'*32,source=SOURCE,source_after=SOURCE,
        source_unchanged=True,engine_version='0.38.25',engine_sha256=PIN,
        engine_sha256_after=PIN,engine_unchanged=True,local_automated_qualification=True,
        python_tests=2230,javascript_tests=38,go_response_vectors=4,consensus_executed=True,
        gates=[dict(name=n,status='passed',passed=True,result_path=n+'/result.json',
            result_sha256='f'*64) for n in ('baseline','private-components','private-consensus')],
        unassessed_gates=[],owned_processes_after_cleanup=0,owned_threads_after_cleanup=0,
        cleanup_errors=[],onchain_privacy=False,independent_security_review=False,
        production_custody=False,public_release_ready=False,real_funds_ready=False,
        spending_or_deployment_authorized=False)


class MerchantQualificationTests(unittest.TestCase):
    def test_complete_actual_source_attribution_is_accepted(self):
        self.assertTrue(actual_report_matches(actual(),SOURCE,RUN))

    def test_all_named_actual_checks_are_required(self):
        for transform in (lambda v:v['checks'].pop(),lambda v:v['checks'].append(v['checks'][0]),
            lambda v:v['checks'][0].update(passed=False),lambda v:v['checks'][0].update(name='unknown')):
            value=actual();transform(value);self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_source_run_engine_or_exploratory_mismatch_is_refused(self):
        for key,bad in [('run_id','0'*32),('source',None),('source_after',{}),
            ('source_qualified',False),('source_unchanged',False),('engine_sha256','0'*64),
            ('engine_sha256_after','0'*64),('engine_version','0.38.24')]:
            with self.subTest(key=key):
                value=actual();value[key]=bad;self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_cleanup_failures_and_boolean_counts_are_refused(self):
        for key,bad in [('owned_processes_after_cleanup',1),('owned_threads_after_cleanup',True),
            ('cleanup_errors',['lost ownership']),('validator_count',True),('pool_size',True)]:
            value=actual();value[key]=bad;self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_all_real_cli_calls_prompts_and_hashes_are_required(self):
        for transform in (lambda v:v['cli_calls'].pop(),
            lambda v:v['cli_calls'][0].update(returncode=1),
            lambda v:v['cli_calls'][0].update(password_prompts=0),
            lambda v:v['cli_calls'][0].update(interface='fake'),
            lambda v:v['cli_calls'][0].update(stdout_sha256='invalid'),
            lambda v:v['cli_calls'][0].update(owned_processes_after_cleanup=1)):
            value=actual();transform(value);self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_three_distinct_original_payments_are_required(self):
        for transform in (lambda v:v['payments'].pop(),
            lambda v:v['payments'][1].update(recipient=v['payments'][0]['recipient']),
            lambda v:v['payments'][1].update(wire_sha256=v['payments'][0]['wire_sha256']),
            lambda v:v['payments'][1].update(native_txid=v['payments'][0]['native_txid']),
            lambda v:v['payments'][1].update(capsule_sha256=v['payments'][0]['capsule_sha256']),
            lambda v:v['payments'][1].update(units='12'),lambda v:v['payments'][1].update(role='owner')):
            value=actual();transform(value);self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_conservation_fee_budget_and_final_hold_must_match(self):
        for key,bad in [('payer','958'),('merchants',['7','11','12']),('fees','11'),
            ('supply','999'),('budget_spent','27'),('pending_debit_units','37')]:
            value=actual();value['final_balances'][key]=bad
            self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_limits_and_journal_pool_semantics_cannot_be_claimed_away(self):
        for key,bad in [('recipient_assignments_never_reused',False),('single_financial_journal',False),
            ('native_genesis_unchanged',False),('onchain_privacy',True),('real_funds',True),
            ('native_signature_authenticates_resource',True),('full_public_ledger_disclosed',False),
            ('globally_exactly_once_service_delivery',True),('independent_hosts',True)]:
            value=actual();value[key]=bad;self.assertFalse(actual_report_matches(value,SOURCE,RUN))

    def test_complete_inherited_qualification_is_accepted(self):
        self.assertTrue(private_report_matches(inherited(),SOURCE))

    def test_partial_inherited_gates_are_refused(self):
        for transform in (lambda v:v['gates'].pop(),lambda v:v['gates'][1].update(passed=False),
            lambda v:v['gates'][0].update(result_sha256='x'),
            lambda v:v.update(unassessed_gates=['private-consensus'])):
            value=inherited();transform(value);self.assertFalse(private_report_matches(value,SOURCE))

    def test_inherited_totals_and_boolean_counts_are_refused(self):
        for key,bad in [('python_tests',2069),('python_tests',True),('javascript_tests',37),
            ('go_response_vectors',False),('source_after',{}),('cleanup_errors',['failed'])]:
            value=inherited();value[key]=bad;self.assertFalse(private_report_matches(value,SOURCE))

    def test_malformed_report_types_are_refused(self):
        for value in (None,[],True,{'schema':True},{'schema':1,'checks':None}):
            self.assertFalse(actual_report_matches(value,SOURCE,RUN))
            self.assertFalse(private_report_matches(value,SOURCE))

    def test_expected_source_and_run_shape_are_validated(self):
        for key,bad in [('commit','not-a-commit'),('tree','a'*39),('source_id','unknown'),
                        ('tracked_files',True),('tracked_files',0)]:
            source={**SOURCE,key:bad};value=actual();value['source']=value['source_after']=source
            self.assertFalse(actual_report_matches(value,source,RUN))
            parent=inherited();parent['source']=parent['source_after']=source
            self.assertFalse(private_report_matches(parent,source))
        value=actual();value['run_id']='not-a-run'
        self.assertFalse(actual_report_matches(value,SOURCE,'not-a-run'))


if __name__=='__main__': unittest.main()
