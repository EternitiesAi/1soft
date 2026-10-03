"""Public synthetic signatures over the existing real monetary/registry fixture."""
import copy
from p4_evidence import nanos

SEGMENT_FORMAT = '1soft/protocol4-incremental-segment/v1'

def policy(case):
    value = copy.deepcopy(case['policy'])
    value.update(schema=2, format='1soft/protocol4-read-policy/v2',
                 checkpoint_progression=True,
                 absolute_not_after_ns=nanos(value['anchor_time'])+86400*10**9)
    return value

def segment(case, height, *, start=0, parent=None):
    return copy.deepcopy({'schema':1, 'format':SEGMENT_FORMAT,
        'parent_checkpoint':parent, 'from_height':start,
        'state':case['states'][height],
        'history':case['history'][start:height],
        'headers':case['headers'][start:height+1]})


def build_alpha(count=80,rejected=True):
    """Select the explicit profile before original node fixture execution."""
    import hashlib
    from unittest.mock import patch
    import p4_fixture
    from protocol4_application import Protocol4Application
    from block_application import encode
    from commit_verifier import load_json
    class AlphaApplication(Protocol4Application):
        def __init__(self,*args,expected_genesis=None,**kwargs):
            if expected_genesis is not None:
                expected_genesis['development_profile']='durable-private-alpha-v1'
            super().__init__(*args,expected_genesis=expected_genesis,**kwargs)
    with patch.object(p4_fixture,'Protocol4Application',AlphaApplication):
        case=p4_fixture.build(count=count,rejected=rejected)
    engine=load_json(case['genesis'],max_bytes=1024*1024)
    engine['app_state']=case['g']
    case['genesis']=encode(engine)
    case['policy']['genesis_sha256']=hashlib.sha256(case['genesis']).hexdigest()
    return case
