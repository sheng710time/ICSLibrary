from pathlib import Path
import csv, hashlib, json, os, sys
for key in ['OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS']:
    os.environ.setdefault(key,'4')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'data'))
def sha(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def selection_for(ds,protocol,fold,collection,role):
    return {s:dict(r,model_label=ds.labels[r['endpoint_id']]['model_label']) for s,r in ds.selection(protocol,fold,collection,role).items()}
def write_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False)+'\n')


def signature_from_dict(r):
    from methods.pingpong.core import PingPongSignature,SequenceComponent
    return PingPongSignature(endpoint=r['endpoint'],port=r['port'],operation=r['operation'],label=r['label'],
        components=tuple(SequenceComponent(tuple(c['directions']),tuple(tuple(v) for v in c['variants']),c['support']) for c in r['components']),
        training_events=r['training_events'],validation_matches=r['validation_matches'])


def operation_key(probes):
    return probes[0] if len(probes)==1 else 'probes:'+json.dumps(probes,separators=(',',':'))


def shared_units(ds, protocol):
    from collections import defaultdict
    out=defaultdict(lambda:defaultdict(list))
    for fid,r in ds.operations.items():
        if r['protocol'] != protocol: continue
        probes=json.loads(r['probe_operations'])
        if probes: out[r['sample_id']][operation_key(probes)].append(fid)
    return {s:{o:sorted(v) for o,v in sorted(ops.items())} for s,ops in out.items()}
