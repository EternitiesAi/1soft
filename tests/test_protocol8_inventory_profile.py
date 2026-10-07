"""Host phase extraction only; these tests do not exercise wallet authority."""
import cProfile,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import profile_protocol8_inventory as profiler

class First:
    def __init__(self):self.x=sum(range(12))
class Second:
    def __init__(self):self.x=sum(range(24))
def unused():pass

class ProfileTests(unittest.TestCase):
    def test_same_named_constructors_bind_to_exact_code_location(self):
        profile=cProfile.Profile()
        profile.runcall(lambda:(First(),First(),Second()))
        with patch.object(profiler,'FUNCTIONS',{'first':First.__init__,'second':Second.__init__}):
            measured=profiler.phases(profile)
        self.assertEqual(measured['first']['calls'],2);self.assertEqual(measured['second']['calls'],1)
        for phase in measured.values():self.assertGreaterEqual(phase['cumulative_seconds'],phase['self_seconds'])
    def test_unexecuted_phase_is_not_fabricated_as_zero(self):
        profile=cProfile.Profile();profile.runcall(First)
        with patch.object(profiler,'FUNCTIONS',{'missing':unused}),self.assertRaises(ValueError):
            profiler.phases(profile)

if __name__=='__main__':unittest.main()
