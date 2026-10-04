"""Local operator adapter for explicit committed durable-alpha workspace."""
from contextlib import contextmanager
from pathlib import Path
from block_application import encode
from local_devnet import LocalNetwork, read_private, private_new, ALPHA_INVOICE_FORMAT
from merchant_alpha import AlphaMerchantBook
from merchant_ops import MerchantOps, ROOT, private_output
from p4_evidence import need, p4_genesis
from p4_incremental_evidence import policy_v2_checked
from p4_read_store import private_path

class AlphaMerchantOps(MerchantOps):
    def __init__(self,network):
        need(type(network) is LocalNetwork and network.config['format']==ALPHA_INVOICE_FORMAT and network.ready(),
             'original ready committed durable-alpha workspace required')
        self.network=network;self.root=Path(network.root).absolute()
        need(not self.root.is_relative_to(ROOT),'workspace outside source required')
        self.path=private_path(self.root/'merchant-alpha.sqlite');self.lock_path=private_path(self.root/'merchant-alpha-ops.lock')
        self._configuration=encode(network.config);self.genesis=read_private(self.root/'engine-genesis.json')
        self._policy=encode(policy_v2_checked(network.policy()))
        g,_=p4_genesis(self.genesis,network.config['genesis_sha256'])
        need(g.get('development_profile')=='durable-private-alpha-v1' and g.get('invoice_commitment_version')==1 and g['asset']=='DEV',
             'explicit original committed DEV alpha genesis required')
        self.invoice_capable=True;self.recipients=(network.config['merchant'],)
        self.network_id='1soft:local-'+network.config['genesis_sha256'][:24];self._context()
    def _context(self):
        need(Path(self.network.root).absolute()==self.root and self.network.ready() and
             read_private(self.root/'workspace.json')==self._configuration and encode(self.network.config)==self._configuration and
             read_private(self.root/'engine-genesis.json')==self.genesis and encode(policy_v2_checked(self.network.policy()))==self._policy,
             'original alpha merchant workspace/genesis/policy context changed')
    def inspect(self):
        report=super().inspect();report['profile']='durable-private-alpha-v1'
        report['assigned_quote_count']=len(report['quotes'])
        report['assigned_recipient_count']=len({r['expectation']['recipient'] for r in report['quotes']})
        return report
    def book(self,*,read_only=False):
        self._context();need(read_private(self.lock_path,1)==b'','canonical merchant operator lock differs')
        book=AlphaMerchantBook(self.path,self.genesis,self.network.policy(),clock=self.network.clock,read_only=read_only)
        try:self._rows(book)
        except BaseException:book.close();raise
        return book
    def init_book(self):
        self._context();private_output(self.path);private_output(self.lock_path);private_new(self.lock_path,b'')
        with self.operation(),AlphaMerchantBook(self.path,self.genesis,self.network.policy(),clock=self.network.clock,create=True):pass
        return dict(status='alpha_merchant_book_initialized',book=str(self.path),recipient_count=1,committed_quotes_required=True,spending_authority=False)


def ops_for_network(network):
    from merchant_devnet import MerchantNetwork
    if type(network) is MerchantNetwork:return MerchantOps(network)
    if type(network) is LocalNetwork and network.config['format']==ALPHA_INVOICE_FORMAT:return AlphaMerchantOps(network)
    raise ValueError('unsupported explicit merchant workspace')
