"""Pinned, finite P4 development profiles. Metadata cannot choose a node limit."""
LEGACY_MAX_HEIGHT = 512
DURABLE_PROFILE = 'durable-private-alpha-v1'
DURABLE_MAX_HEIGHT = 4096

def max_height_for(genesis):
    from native_core import require
    require(type(genesis) is dict, 'development profile requires pinned genesis')
    if 'development_profile' not in genesis:
        return LEGACY_MAX_HEIGHT
    require(type(genesis.get('protocol_version')) is int and genesis['protocol_version'] == 4
            and type(genesis['development_profile']) is str
            and genesis['development_profile'] == DURABLE_PROFILE,
            'unsupported explicit development profile')
    return DURABLE_MAX_HEIGHT
