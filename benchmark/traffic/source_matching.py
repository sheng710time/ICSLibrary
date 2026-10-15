"""Uncapped supplied FMLCS, with reusable size/direction path plans.

On a new structural pair the unchanged supplied approximate_match is executed.
Its own return-frame path list is captured, not re-enumerated or truncated.
Times cannot affect that list. Repeated pairs execute the same NumPy temporal
operations over exactly those paths. No approximate fallback or path limit.
"""
import sys
from collections import OrderedDict
from math import ceil, inf
import numpy as np
from common import digest
from device_identification.wifinger.core import MatchResult, normalize_sequence
from device_identification.wifinger.source_adapter import _author_sequence
from device_identification.wifinger_fmlcs.fmlcs.lcs import approximate_match


class SourceFMLCS:
    def __init__(self, max_cached_plans=8192):
        self.plans = OrderedDict()
        self.max_cached_plans = max_cached_plans
        self.reference_calls = 0
        self.plan_reuses = 0
        self.witnesses = {}

    @staticmethod
    def temporal(plan, left, right):
        # Same ordering and arithmetic as supplied lcs.py lines 66-83.
        rt = np.asarray([p.time for p in right])
        lt = np.asarray([p.time for p in left])
        target_times = rt[plan[:, :, 0]] - rt[plan[:, 0, 0]][:, None]
        fingerprint_times = lt[plan[:, :, 1]] - lt[plan[:, 0, 1]][:, None]
        diff = target_times - fingerprint_times
        diff_mean = np.mean(diff, axis=1).reshape(-1, 1)
        distances = np.linalg.norm(diff - diff_mean, axis=1)
        index = np.argmin(distances)
        return float(np.min(distances)), plan[index]

    def match(self, fingerprint, target, config):
        assert config.epsilon == 1 and not config.advanced_matching
        left, right = normalize_sequence(fingerprint), normalize_sequence(target)
        if not left or not right:
            return MatchResult(False, 0, len(left), 0.0, inf, 0.0, (), 'SOURCE-FMLCS')
        key = (tuple((p.size, p.direction) for p in left),
               tuple((p.size, p.direction) for p in right))
        if key in self.plans:
            plan = self.plans.pop(key)
            self.plans[key] = plan
            self.plan_reuses += 1
            distance, author_pairs = self.temporal(plan, left, right)
        else:
            captured = {}
            previous_profile = sys.getprofile()
            def capture(frame, event, arg):
                if event == 'return' and frame.f_code is approximate_match.__code__:
                    captured['all_paths'] = frame.f_locals['all_paths']
            try:
                sys.setprofile(capture)
                reference_distance, reference_pairs = approximate_match(
                    _author_sequence(right), _author_sequence(left))
            finally:
                sys.setprofile(previous_profile)
            self.reference_calls += 1
            # Callers reject zero-overlap pairs before invoking the source.
            assert captured['all_paths'] and captured['all_paths'][0]
            plan = np.asarray(captured['all_paths'], dtype=np.int32)
            distance, author_pairs = self.temporal(plan, left, right)
            assert distance == float(reference_distance)
            assert author_pairs.tolist() == [list(p) for p in reference_pairs]
            self.plans[key] = plan
            if len(self.plans) > self.max_cached_plans:
                self.plans.popitem(last=False)  # Eviction changes cost, never paths.
            self.witnesses[digest(key)] = dict(
                structure=key, paths=int(plan.shape[0]), matched_packets=int(plan.shape[1]),
                paths_sha256=digest(plan.tolist()), reference_distance=distance,
                first_input_hash=digest(dict(left=[p.to_dict() for p in left],
                                            right=[p.to_dict() for p in right])),
                reference_and_cached_calculation_identical=True)
        pairs = tuple((int(j), int(i)) for i, j in author_pairs)
        ratio = len(pairs) / len(left)
        success = len(pairs) >= ceil(len(left) * config.gamma) and distance < config.beta
        return MatchResult(success, len(pairs), len(left), ratio, distance,
                           ratio / (1.0 + distance), pairs, 'SOURCE-FMLCS')
