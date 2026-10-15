"""Run selected experimental conditions from data and summarize new metrics."""
import argparse,collections,json,os,statistics,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['base','addon','work','output']:p.add_argument('--'+key,required=True)
    p.add_argument('--methods',nargs='+',default=['LSIF','IDT-AIM','XGB-IDI','PINGPONG','WiFinger'],choices=['LSIF','IDT-AIM','XGB-IDI','PINGPONG','WiFinger','TrafficFormer'])
    p.add_argument('--protocols',nargs='+',default=['modbus','enip','s7'],choices=['modbus','enip','s7'])
    p.add_argument('--folds',type=int,nargs='+',default=[1,2,3],choices=[1,2,3])
    p.add_argument('--views',nargs='+',default=['raw','instance_controlled','identifier_masked'],choices=['raw','instance_controlled','identifier_masked'])
    p.add_argument('--author-source');p.add_argument('--weights');p.add_argument('--workers',type=int,default=4)
    a=p.parse_args();work=Path(a.work).resolve();records=[]
    if 'TrafficFormer' in a.methods and not (a.author_source and a.weights):p.error('TrafficFormer needs --author-source and --weights.')
    for target in [a.work,a.output]:
        if any(Path(target).resolve().is_relative_to(Path(d).resolve()) for d in [a.base,a.addon]):p.error('Write outputs outside input datasets.')
    for method in a.methods:
        for protocol in a.protocols:
            for fold in a.folds:
                for view in a.views:
                    name=f'{method}-{protocol}-f{fold}-{view}'
                    metricfile=work/'metrics'/(name+'.json');metricfile.parent.mkdir(parents=True,exist_ok=True)
                    cmd=[sys.executable,str(ROOT/('trafficformer' if method=='TrafficFormer' else 'traffic')/'run.py'),
                         '--base',a.base,'--addon',a.addon,'--work',str(work/('trafficformer' if method=='TrafficFormer' else 'traffic')),
                         '--output',str(metricfile),'--protocol',protocol,'--fold',str(fold),'--view',view]
                    if method=='TrafficFormer':cmd+=['--author-source',a.author_source,'--weights',a.weights,'--workers',str(a.workers)]
                    else:cmd+=['--method',method]
                    subprocess.run(cmd,check=True,env=dict(os.environ,PYTHONHASHSEED='0'))
                    result=json.loads(metricfile.read_text())
                    if method=='TrafficFormer':
                        merged={}
                        for r in result['metrics']:
                            cell=merged.setdefault((r['collection'],r['test_group']),dict(collection=r['collection'],role='test_'+r['test_group']))
                            cell[r['metric']]=r['value']
                        cells=merged.values()
                    else:cells=result['metrics']
                    for cell in cells:
                        if cell['role'].startswith('test_'):
                            records.append(dict(method='PingPong' if method=='PINGPONG' else method,protocol=protocol,fold=fold,view=view,**{k:cell[k] for k in ['collection','role','accuracy','macro_f1','weighted_f1']}))
    groups=collections.defaultdict(list)
    for r in records:
        for metric in ['accuracy','macro_f1','weighted_f1']:
            key=(r['method'],r['protocol'],r['view'],r['collection'],r['role'],metric)
            groups[key].append(r[metric])
    summary=[]
    for key,values in sorted(groups.items()):
        summary.append(dict(zip(['method','protocol','view','collection','role','metric'],key),n_folds=len(values),mean=statistics.mean(values),std=statistics.stdev(values) if len(values)>1 else None))
    paired=[];index={(r['method'],r['protocol'],r['fold'],r['view'],r['collection'],r['role']):r for r in records}
    changes=collections.defaultdict(list)
    for key,r in index.items():
        method,protocol,fold,view,collection,role=key
        if collection!='A':continue
        if role=='test_same':
            other=index.get((method,protocol,fold,view,collection,'test_unseen'))
            if other:changes[(method,protocol,view,'same_minus_unseen')].append(r['macro_f1']-other['macro_f1'])
        previous={'instance_controlled':'raw','identifier_masked':'instance_controlled'}.get(view)
        other=index.get((method,protocol,fold,previous,collection,role)) if previous else None
        if other:changes[(method,protocol,role,view+'_minus_'+previous)].append(r['macro_f1']-other['macro_f1'])
    for key,values in sorted(changes.items()):
        paired.append(dict(method=key[0],protocol=key[1],condition=key[2],contrast=key[3],n_folds=len(values),mean=statistics.mean(values),std=statistics.stdev(values) if len(values)>1 else None))
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(dict(fold_metrics=records,summary=summary,paired_macro_f1_changes=paired),indent=2)+'\n')
if __name__=='__main__':main()
