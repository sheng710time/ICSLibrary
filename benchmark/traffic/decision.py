"""Method-specific evidence selection before the common residual fallback."""
from common import *
from fractions import Fraction
from collections import defaultdict
from statistics import mean
from device_identification.pingpong.experiment import _signature_evidence,_training_label_ranks

POLICIES=['min4','short_fallback','min2','all']

def decode_evidence(e):
    return tuple(Fraction(v) if isinstance(v,str) else v for v in e)

def model_context(method,artifact,templates):
    if method=='PINGPONG':
        model=[signature_from_dict(f) for f in artifact['fingerprints']]
        _,ranks,_=_training_label_ranks(model,artifact['training_support'])
        evidence={}
        for t in templates:
            by={}
            for i in t['member_indices']:
                fp=model[i];e=_signature_evidence(fp)
                value=(e.packet_count,e.validation_stability,e.component_stability,e.component_support)
                by[fp.label]=max(by.get(fp.label,value),value)
            evidence[t['template_id']]={l:[str(v) if isinstance(v,Fraction) else v for v in a] for l,a in by.items()}
        return dict(training_ranks={l:[str(v) if isinstance(v,Fraction) else v for v in a] for l,a in ranks.items()},evidence=evidence)
    return dict(training_ranks={},evidence={})

def choose_operation(method,raw,templates,context,policy):
    # raw entries: query ID, template index, native matched packet count, distance.
    incoming=[]
    for qid,index,count,distance in raw:
        t=templates[index]
        if method=='WiFinger':
            length=len(t['representation']['packets'])
            if policy=='min4' and length<4:continue
            if policy in ['min2','short_fallback'] and length<2:continue
            ratio=count/length;score=ratio/(1+distance)
            rank=(ratio,-distance,score)
        else:
            length=0;ratio=0.;score=0.;rank=(count,-distance)
        incoming.append(dict(query_id=qid,template_id=t['template_id'],labels=t['labels'],matched_packets=count,
            distance=distance,match_ratio=ratio,score=score,fingerprint_packets=length,rank=rank))
    if method=='WiFinger' and policy=='short_fallback' and any(r['fingerprint_packets']>=4 for r in incoming):
        incoming=[r for r in incoming if r['fingerprint_packets']>=4]
    if not incoming:return dict(candidate_labels=[],selected_matches=[],label_evidence={},matched_packets=0,distance=0.,score=0.,short_only=False)
    if method=='PINGPONG':
        count=max(r['matched_packets'] for r in incoming)
        distance=min(r['distance'] for r in incoming if r['matched_packets']==count)
        best=[r for r in incoming if r['matched_packets']==count and abs(r['distance']-distance)<=1e-12]
    else:
        highest=max(r['rank'] for r in incoming);best=[r for r in incoming if r['rank']==highest]
    labels=sorted({l for r in best for l in r['labels']});le={}
    if method=='PINGPONG':
        for l in labels:
            ee=[decode_evidence(context['evidence'][r['template_id']][l]) for r in best if l in r['labels']]
            le[l]=[str(v) if isinstance(v,Fraction) else v for v in max(ee)]
    return dict(candidate_labels=labels,selected_matches=[{k:v for k,v in r.items() if k!='rank'} for r in best],
        label_evidence=le,matched_packets=best[0]['matched_packets'],distance=min(r['distance'] for r in best),
        score=best[0]['score'],short_only=method=='WiFinger' and all(r['fingerprint_packets']<4 for r in best))

def decide(method,units,support,context):
    votes=defaultdict(Fraction);counts=defaultdict(int);packets=defaultdict(int);distances=defaultdict(list)
    val=defaultdict(Fraction);stability=defaultdict(Fraction);components=defaultdict(int);scores=defaultdict(list)
    for u in units:
        labels=u['candidate_labels']
        for l in labels:
            votes[l]+=Fraction(1,len(labels));counts[l]+=int(len(labels)==1)
            packets[l]+=u['matched_packets'];distances[l].append(u['distance']);scores[l].append(u['score'])
            if method=='PINGPONG':
                e=decode_evidence(u['label_evidence'][l]);val[l]+=e[1];stability[l]+=e[2];components[l]+=e[3]
    initial=sorted(l for l,v in votes.items() if v==max(votes.values())) if votes else sorted(support)
    finalists=initial;ranked={};quality_used=False
    if votes and len(initial)>1:
        if method=='PINGPONG':
            ranked={l:(counts[l],packets[l],-mean(distances[l]),val[l],stability[l],components[l],*decode_evidence(context['training_ranks'][l])) for l in initial}
        else:ranked={l:(mean(scores[l]),) for l in initial}
        high=max(ranked.values());finalists=[l for l in initial if ranked[l]==high];quality_used=True
    prior_used=not votes or len(finalists)>1
    if prior_used:
        high=max(support[l] for l in finalists);finalists=[l for l in finalists if support[l]==high]
    predicted=min(finalists);lexical=len(finalists)>1
    if not votes:stage='supplement_no_match';reason='no-match-training-support'+('-lexical' if lexical else '')
    elif prior_used:stage='supplement_residual_tie';reason='residual-evidence-tie-training-support'+('-lexical' if lexical else '')
    elif quality_used:stage='method_evidence';reason='method-evidence-breaks-vote-tie'
    else:stage='method_vote';reason='unique-selected-operation-vote'
    return dict(pred_label=predicted,votes={l:str(v) for l,v in sorted(votes.items())},decision_stage=stage,decision_reason=reason,
        native_candidate_models=sorted(votes),tied_models=initial if votes and len(initial)>1 else [],
        evidence_finalists=sorted(finalists),method_evidence_used=int(quality_used),supplement_used=int(prior_used),
        training_prior_used=int(prior_used),lexical_used=int(lexical),forced=int(prior_used),
        matched_operations=sum(bool(u['candidate_labels']) for u in units))
