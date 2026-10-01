"""Exact report predicates for the finite local merchant journey."""
import re

PIN_SHA='218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
MERCHANT_CHECKS=(
    'real network CLI creates three immutable development recipients',
    'fresh P4 genesis preserves owner supply and zero recipient allocations',
    'four owned validators execute original three setup operations',
    'both grants share the original budget and full recipient allowlist',
    'merchant CLI initializes the sole key-free canonical book',
    'merchant CLI creates and exports three original public quotes',
    'three quote assignments use distinct pinned recipients',
    'fourth quote or recipient reassignment is refused',
    'merchant CLI serves fixed routes and stops within its bound',
    'actual authenticated HTTP returns each independently pinned quote',
    'three encrypted invoice imports create no spending authority',
    'private invoice content absent from public merchant and financial data',
    'three unsigned canonical requests remain distinct',
    'owner and both grants approve separate native and merchant terms',
    'three original signed wires and thirty-seven unit hold are retained',
    'merchant CLI independently enrolls all exact original wires',
    'each original claims only one submission attempt',
    'three exact native transfers actually commit',
    'three collected native receipt capsules independently replay',
    'receipt retention leaves all financial holds intact',
    'genuine payment proof cannot fulfill another quote route',
    'abandoned HTTP return follows durable first fulfillment',
    'all routes return their original immutable public resource',
    'one canonical merchant book consumes three unique native identities',
    'merchant responses never reconcile financial reservations',
    'owned runtime stops before cold restart',
    'cold runtime keeps original config policy keys and ciphertext',
    'cold journals keep original requests decisions attempts and receipts',
    'cold CLI recovers three exact original wires without unlocking',
    'cold CLI decrypts original invoices only into explicit private files',
    'cold merchant book preserves original fulfillment and assignments',
    'cold proof replay returns originals without extra consumption',
    'cold exhausted recipient pool stays exhausted',
    'explicit native reconciliation alone clears thirty-seven unit hold',
    'native balances fees overlapping budget and supply conserve',
    'exact source and pinned engine remain unchanged',
    'all owned processes and threads stop without cleanup errors',
)
MERCHANT_CLI_COMMANDS=(('network','init',2),('network','run',1),('private','init-invoices',2),('merchant','init-book',0))
MERCHANT_CLI_COMMANDS+=tuple(x for _ in range(3) for x in (('merchant','add-quote',0),('merchant','export-quote',0)))
MERCHANT_CLI_COMMANDS+=(('merchant','inspect',0),('merchant','serve',0))
MERCHANT_CLI_COMMANDS+=tuple(('private','import-invoice',1) for _ in range(3))
MERCHANT_CLI_COMMANDS+=tuple(x for _ in range(3) for x in (('private','prepare',0),('private','approve',1),
    ('private','recover',0),('merchant','enroll-wire',0),('private','export-receipt',0),('private','payment-header',0)))
MERCHANT_CLI_COMMANDS+=tuple(x for _ in range(3) for x in (('private','recover',0),('private','open-invoice',1)))
MERCHANT_CLI_COMMANDS+=(('merchant','inspect',0),)+tuple(('private','reconcile',0) for _ in range(3))


def actual_report_matches(report,source,run_id):
    try:
        if not _common(report,source): return False
        if (type(run_id) is not str or re.fullmatch('[0-9a-f]{32}',run_id) is None or
            report.get('run_id')!=run_id or report.get('source_qualified') is not True or
            not _int(report.get('validator_count'),4) or not _int(report.get('pool_size'),3) or
            report.get('payer_roles')!=['owner','raven','atlas'] or
            report.get('recipient_assignments_never_reused') is not True or
            report.get('single_financial_journal') is not True or
            report.get('native_genesis_unchanged') is not True or
            report.get('full_public_ledger_disclosed') is not True): return False
        if not all(report.get(k) is False for k in ('real_funds','public_network',
            'independent_hosts','onchain_privacy','native_signature_authenticates_resource',
            'globally_exactly_once_service_delivery')): return False
        rows=report.get('checks')
        if not (type(rows) is list and len(rows)==len(MERCHANT_CHECKS) and
            all(type(r) is dict and type(r.get('name')) is str and r.get('passed') is True for r in rows)
            and len({r['name'] for r in rows})==len(rows) and
            {r['name'] for r in rows}==set(MERCHANT_CHECKS)): return False
        calls=report.get('cli_calls')
        if type(calls) is not list or len(calls)!=len(MERCHANT_CLI_COMMANDS): return False
        for call,(interface,command,prompts) in zip(calls,MERCHANT_CLI_COMMANDS):
            if not (type(call) is dict and call.get('interface')==interface and call.get('command')==command
                and _int(call.get('password_prompts'),prompts) and _int(call.get('returncode'),0)
                and _int(call.get('owned_processes_after_cleanup'),0) and
                _hash(call.get('stdout_sha256')) and _hash(call.get('terminal_sha256'))): return False
        payments=report.get('payments')
        if type(payments) is not list or len(payments)!=3: return False
        for row,role,units in zip(payments,('owner','raven','atlas'),('7','11','13')):
            if not (type(row) is dict and row.get('role')==role and row.get('units')==units and
                row.get('fee')=='2' and type(row.get('recipient')) is str and
                re.fullmatch(r'lab_[0-9a-f]{64}',row['recipient']) and
                all(_hash(row.get(k)) for k in ('request_id','quote_sha256','wire_sha256','native_txid','capsule_sha256'))): return False
        if any(len({row[key] for row in payments})!=3 for key in
            ('recipient','request_id','quote_sha256','wire_sha256','native_txid','capsule_sha256')): return False
        return report.get('final_balances')=={'payer':'957','merchants':['7','11','13'],
            'fees':'12','supply':'1000','budget_spent':'28','pending_debit_units':'0'}
    except (KeyError,TypeError,ValueError,AttributeError): return False


def private_report_matches(report,source):
    try:
        if not _common(report,source) or report.get('local_automated_qualification') is not True:
            return False
        if not (type(report.get('run_id')) is str and re.fullmatch('[0-9a-f]{32}',report['run_id'])
            and type(report.get('python_tests')) is int and report['python_tests']>=2204 and
            _int(report.get('javascript_tests'),38) and _int(report.get('go_response_vectors'),4)
            and report.get('engine_unchanged') is True and report.get('unassessed_gates')==[]): return False
        gates=report.get('gates');names=('baseline','private-components','private-consensus')
        if not (type(gates) is list and len(gates)==3 and all(type(g) is dict for g in gates)
            and tuple(g.get('name') for g in gates)==names): return False
        for gate in gates:
            path=gate.get('result_path')
            if not (gate.get('passed') is True and gate.get('status')=='passed' and
                type(path) is str and path and not path.startswith('/') and '\\' not in path
                and ':' not in path and all(part not in ('','.','..') for part in path.split('/')) and
                _hash(gate.get('result_sha256'))): return False
        return all(report.get(k) is False for k in ('onchain_privacy','independent_security_review',
            'production_custody','public_release_ready','real_funds_ready','spending_or_deployment_authorized'))
    except (KeyError,TypeError,ValueError,AttributeError): return False


def _int(value,expected):
    return type(value) is int and value==expected


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _common(report,source):
    return (type(source) is dict and set(source)=={'commit','tree','source_id','tracked_files'} and
        all(type(source.get(k)) is str and re.fullmatch('[0-9a-f]{40}',source[k]) for k in ('commit','tree')) and
        _hash(source.get('source_id')) and type(source.get('tracked_files')) is int and source['tracked_files']>=474 and
        type(report) is dict and _int(report.get('schema'),1) and report.get('status')=='passed'
        and report.get('source')==source and report.get('source_after')==source
        and report.get('source_unchanged') is True and report.get('consensus_executed') is True
        and report.get('engine_version')=='0.38.25' and report.get('engine_sha256')==PIN_SHA
        and report.get('engine_sha256_after')==PIN_SHA and _int(report.get('owned_processes_after_cleanup'),0)
        and _int(report.get('owned_threads_after_cleanup'),0) and report.get('cleanup_errors')==[])
