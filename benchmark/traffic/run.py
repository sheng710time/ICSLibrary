"""Fit on released training traffic and evaluate; no saved predictions required."""
from common import *
import argparse
from collections import Counter

def scores(truth, predicted, labels):
    from sklearn.metrics import accuracy_score, f1_score
    return dict(accuracy=float(accuracy_score(truth,predicted)),
                macro_f1=float(f1_score(truth,predicted,labels=labels,average='macro',zero_division=0)),
                weighted_f1=float(f1_score(truth,predicted,labels=labels,average='weighted',zero_division=0)))

def run(args):
    import numpy as np
    from identifier_dataset_io import IdentifierDataset
    from extract import extract
    from models import IDTAIM,LSIF
    cfg=json.loads(Path(__file__).with_name('config.json').read_text())
    with IdentifierDataset(args.base,args.addon) as ds:
        mode='tabular' if args.method in ('IDT-AIM','XGB-IDI') else 'signatures'
        data=extract(ds,args.protocol,args.view,mode,Path(args.work)/'features')
        train=selection_for(ds,args.protocol,args.fold,'A','train')
        valid=selection_for(ds,args.protocol,args.fold,'A','validation')
        ids=sorted(train); classes=sorted({r['model_label'] for r in train.values()})
        labels={r['endpoint_id']:r['model_label'] for r in train.values()}
        support=Counter(labels.values()); fallback=min(support,key=lambda l:(-support[l],l))
        y=np.array([classes.index(train[s]['model_label']) for s in ids])
        seed=41+args.fold; method=args.method; policy=None
        if method=='XGB-IDI':
            from xgboost import XGBClassifier
            model=XGBClassifier(**cfg[method],random_state=seed).fit(np.array([data[s]['xgb'] for s in ids]),y)
            def predict(selected):
                ss=sorted(selected); p=model.predict_proba(np.array([data[s]['xgb'] for s in ss]))
                return {s:classes[int(v.argmax())] for s,v in zip(ss,p)}
        elif method=='IDT-AIM':
            X=np.concatenate([data[s]['idt'] for s in ids]); yy=np.concatenate([np.repeat(v,len(data[s]['idt'])) for s,v in zip(ids,y)])
            model=IDTAIM(seed,cfg[method]).fit(X,yy)
            def predict(selected):
                ss=sorted(selected); p=model.predict_proba(np.concatenate([data[s]['idt'] for s in ss])); out={}; at=0
                for s in ss:
                    n=len(data[s]['idt']);out[s]=classes[int(p[at:at+n].mean(axis=0).argmax())];at+=n
                return out
        elif method=='LSIF':
            model=LSIF().fit([(train[s]['endpoint_id'],data[s]['lsif']) for s in ids],labels)
            def predict(selected):
                ss=[s for s in sorted(selected) if data[s]['lsif'] is not None];out={s:fallback for s in selected}
                if model.endpoints:
                    for at in range(0,len(ss),512):
                        part=ss[at:at+512]; values=model.scores([data[s]['lsif'] for s in part])
                        for s,v in zip(part,values):
                            winners={model.labels[j] for j in np.flatnonzero(np.isclose(v,v.max(),atol=1e-12,rtol=0))}
                            out[s]=min(winners,key=lambda l:(-support[l],l))
                return out
        else:
            from matching import Matcher
            from decision import POLICIES,model_context,choose_operation,decide
            if method=='PINGPONG':
                from device_identification.pingpong.experiment import build_signatures
                from device_identification.pingpong.core import ExtractionConfig
                key='pingpong'; model=build_signatures([i for s in ids for i in data[s][key]],labels,ExtractionConfig(**cfg[method]))
            else:
                from device_identification.wifinger.experiment import build_fingerprints
                from device_identification.wifinger.core import MatchConfig
                key='wifinger';model=build_fingerprints([i for s in ids for i in data[s][key]],labels,MatchConfig(**cfg[method]),cfg['wifinger_max_samples'])
            artifact=dict(fingerprints=[f.to_dict() for f in model],training_support=dict(support))
            matcher=Matcher(method,artifact,cfg[method]);shared=shared_units(ds,args.protocol)
            context=model_context(method,artifact,matcher.templates)
            def predict(selected,choice=None):
                out={}
                for s in sorted(selected):
                    units=matcher.infer_units(s,data[s][key],shared.get(s,{}))
                    picked=[choose_operation(method,u['raw'],matcher.templates,context,choice or policy) for u in units]
                    out[s]=decide(method,picked,support,context)['pred_label']
                return out
            if method=='WiFinger':
                choices=[]
                for candidate in POLICIES:
                    pp=predict(valid,candidate);m=scores([valid[s]['model_label'] for s in sorted(valid)],[pp[s] for s in sorted(valid)],classes)
                    choices.append((m['macro_f1'],m['accuracy'],m['weighted_f1'],-POLICIES.index(candidate),candidate))
                policy=max(choices)[-1]
            else: policy='restored'
            print('fingerprints',len(model),'policy',policy,flush=True)
        metrics=[]
        for collection,role in [('A','validation')]+[(c,r) for c in ('A','B','C') for r in ('test_same','test_unseen')]:
            selected=selection_for(ds,args.protocol,args.fold,collection,role); pp=predict(selected); ss=sorted(selected)
            truth=[selected[s]['model_label'] for s in ss]
            supported=classes if collection=='A' else sorted(set(truth))
            metrics.append(dict(collection=collection,role=role,n_samples=len(ss),**scores(truth,[pp[s] for s in ss],supported)))
            print(collection,role,metrics[-1],flush=True)
        result=dict(method=method,protocol=args.protocol,fold=args.fold,view=args.view,seed=seed,policy=policy,metrics=metrics)
        write_json(args.output,result)
        return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',required=True);p.add_argument('--addon',required=True)
    p.add_argument('--work',required=True,help='Disposable directory for generated features')
    p.add_argument('--output',required=True,help='New evaluation metrics JSON')
    p.add_argument('--method',required=True,choices=['LSIF','IDT-AIM','XGB-IDI','PINGPONG','WiFinger'])
    p.add_argument('--protocol',required=True,choices=['modbus','enip','s7'])
    p.add_argument('--fold',type=int,required=True,choices=[1,2,3])
    p.add_argument('--view',required=True,choices=['raw','instance_controlled','identifier_masked'])
    args=p.parse_args()
    if os.environ.get('PYTHONHASHSEED')!='0':
        os.execve(sys.executable,[sys.executable,*sys.argv],dict(os.environ,PYTHONHASHSEED='0'))
    for target in [args.work,args.output]:
        if any(Path(target).resolve().is_relative_to(Path(d).resolve()) for d in [args.base,args.addon]):
            p.error('Write outputs outside the input datasets.')
    run(args)
