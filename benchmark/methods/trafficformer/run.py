"""Prepare inputs, fine-tune the official backbone, and score endpoint samples."""
import argparse,json,os,sys,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['base','addon','work','author-source','weights','output']:p.add_argument('--'+name,required=True)
    p.add_argument('--protocol',required=True,choices=['modbus','enip','s7'])
    p.add_argument('--fold',type=int,required=True,choices=[1,2,3])
    p.add_argument('--view',required=True,choices=['raw','instance_controlled','identifier_masked'])
    p.add_argument('--workers',type=int,default=4)
    p.add_argument('--prepare-only',action='store_true')
    p.add_argument('--smoke-samples-per-class',type=int,help='Small pipeline check, not a paper result')
    a=p.parse_args()
    for key,value in {'ICSLIBRARY_BASE':a.base,'ICSLIBRARY_ADDON':a.addon,'ICSLIBRARY_WORK':a.work,
                      'TRAFFICFORMER_SOURCE':a.author_source,'TRAFFICFORMER_WEIGHTS':a.weights}.items():
        os.environ[key]=str(Path(value).resolve())
    for target in [a.work,a.output]:
        if any(Path(target).resolve().is_relative_to(Path(d).resolve()) for d in [a.base,a.addon]):p.error('Write outputs outside input datasets.')
    commit=subprocess.check_output(['git','-C',a.author_source,'rev-parse','HEAD'],text=True).strip()
    if commit!='6d0ba64d82e74fb130c6c7301ef20885dbfbdf29':p.error('Use the TrafficFormer commit specified in README.md.')
    from common import digest
    if not a.prepare_only and digest(a.weights)!='be9dcc1e0c6b68db005e506adf13a2d937a2f3982539a2c8a58f78c55af0d5ce':
        p.error('Pretrained checkpoint SHA256 differs from the paper checkpoint.')
    from prepare import prepare
    conditions=[('A','train'),('A','validation')]+[(c,r) for c in ('A','B','C') for r in ('test_same','test_unseen')]
    caches={c+'/'+r:prepare(a.protocol,a.fold,a.view,c,r,a.workers,a.smoke_samples_per_class) for c,r in conditions}
    result={'prepared':{k:str(v) for k,v in caches.items()},'smoke_subset':a.smoke_samples_per_class}
    if not a.prepare_only:
        from train import train_run
        runid=f'{a.protocol}-f{a.fold}-{a.view}'+('-smoke' if a.smoke_samples_per_class else '')
        result=train_run(runid,a.protocol,a.fold,a.view,caches,epochs=1 if a.smoke_samples_per_class else 4,smoke=bool(a.smoke_samples_per_class))
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
