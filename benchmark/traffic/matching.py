"""Native fingerprint judgment precedes the explicitly supplemental model rule."""
from common import digest, signature_from_dict
from fractions import Fraction
from collections import defaultdict
from device_identification.pingpong.core import ExtractionConfig, match_signature_flows
from device_identification.wifinger.core import Fingerprint, MatchConfig
from device_identification.wifinger.experiment import _overlap_upper_bound
from source_matching import SourceFMLCS


class Matcher:
    def __init__(self, method, artifact, config):
        self.method = method
        self.config = ExtractionConfig(**config) if method == 'PINGPONG' else MatchConfig(**config)
        ctor = signature_from_dict if method == 'PINGPONG' else Fingerprint.from_dict
        self.model = [ctor(r) for r in artifact['fingerprints']]
        grouped = {}
        for i, fp in enumerate(self.model):
            rep = {'components': [c.to_dict() for c in fp.components]} if method == 'PINGPONG' else {
                'port': fp.port, 'operation': fp.operation, 'packets': [p.to_dict() for p in fp.packets]}
            key = digest(rep)
            t = grouped.setdefault(key, dict(template_id=key, representative=i, member_indices=[], labels=[], representation=rep))
            t['member_indices'].append(i); t['labels'].append(fp.label)
        self.templates = sorted(grouped.values(), key=lambda t: t['template_id'])
        self.by_scope = defaultdict(list)
        for t in self.templates:
            t['labels'] = sorted(set(t['labels']))
            fp = self.model[t['representative']]
            self.by_scope[fp.port, fp.operation].append(t)
        self.memo = {}; self.queries = []; self.native_calls = 0
        self.source = SourceFMLCS() if method == 'WiFinger' else None

    def query(self, flows):
        assert flows
        if self.method == 'PINGPONG':
            query = dict(flows=[[p.to_dict() for p in f.packets] for f in flows]); candidates = self.templates
        else:
            assert len(flows) == 1
            flow = flows[0]
            query = dict(port=flow.port, operation=flow.operation, packets=[p.to_dict() for p in flow.packets])
            candidates = self.by_scope.get((flow.port, flow.operation), [])
        qid = digest(query)
        if qid in self.memo: return self.memo[qid]
        matched = []; labels = set(); raw = []
        for t in candidates:
            fp = self.model[t['representative']]
            if self.method == 'PINGPONG':
                result = match_signature_flows(fp, tuple(f.packets for f in flows), self.config)
            else:
                if _overlap_upper_bound(fp, flow, self.config) < self.config.gamma: continue
                result = self.source.match(fp.packets, flow.packets, self.config)
            self.native_calls += 1
            if result.success:
                matched.append(t['template_id']); labels.update(t['labels'])
                raw.append((qid, self.templates.index(t), result.matched_packets, result.distance if self.method == 'PINGPONG' else result.temporal_distance))
        out = dict(query_id=qid, candidate_labels=sorted(labels), successful_template_ids=matched, raw=raw)
        self.memo[qid] = out
        self.queries.append(dict(**out, input=query, candidate_templates=len(candidates)))
        return out

    def infer_units(self, sid, interactions, shared):
        by_op = defaultdict(list)
        for f in interactions:
            assert f.interaction_id in shared[f.operation]
            by_op[f.operation].append(f)
        units = []
        for op, ids in sorted(shared.items()):
            flows = sorted(by_op.get(op, []), key=lambda f: (f.packets[0].time if f.packets else float('inf'), f.interaction_id))
            assert len({f.port for f in flows}) <= 1
            qq = ([self.query(flows)] if self.method == 'PINGPONG' else [self.query([f]) for f in flows]) if flows else []
            labels = sorted({l for q in qq for l in q['candidate_labels']})
            units.append(dict(sample_id=sid, operation=op, shared_flow_ids=ids,
                effective_flow_ids=[f.interaction_id for f in flows], query_ids=[q['query_id'] for q in qq],
                candidate_labels=labels, candidate_count=len(labels), raw=[r for q in qq for r in q['raw']],
                native_unit_state='unique_model' if len(labels) == 1 else ('ambiguous_models' if labels else 'no_match'),
                vote_per_candidate=str(Fraction(1, len(labels))) if labels else '0'))
        return units
