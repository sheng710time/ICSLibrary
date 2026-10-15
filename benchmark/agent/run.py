"""Run the paired response case study from released inputs and compute metrics."""
import argparse, collections, json, os, shutil, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'data'))
from dataset_io import Dataset,rows
from rules import rule_predict,present
from scoring import map_label,metrics_for


def runtime(source,work):
    source=Path(source).resolve();out=Path(work).resolve()/'runtime'
    commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if commit!='5d436706d48481e08e2109f83d06628d09c13e3a':
        raise ValueError('Use the NS-FirmID commit specified in README.md')
    for name in ['Knowledge_graph_construct/extract_info_from_database.py','Knowledge_graph_construct/result_verify.py',
                 'Knowledge_graph_construct/simlarity_calculate.py','discriminator_construct/analysis_token_logprobs.py',
                 'discriminator_construct/confidence_discriminator.py','tools/tool_global.py']:
        p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
        text=(source/name).read_text()
        if name=='tools/tool_global.py':
            text=text.replace('from tools.wrong_sample_record import recorrect_relabel_sample',
                              '# Optional author relabeling utility is not part of inference.')
        if name=='discriminator_construct/analysis_token_logprobs.py':
            # Upstream ends in an incomplete demonstration string, after all definitions.
            text=text.split('if __name__ == "__main__":')[0]
        if name=='discriminator_construct/confidence_discriminator.py':
            text=text.replace('from analysis_token_logprobs import AttributeConfidenceAnalyzer',
                              'from discriminator_construct.analysis_token_logprobs import AttributeConfidenceAnalyzer')
        compile(text,str(p),'exec')
        p.write_text(text);(p.parent/'__init__.py').touch()
    sys.path.insert(0,str(out))


def api_predict(banner,cfg):
    import urllib.request,urllib.error
    from discriminator_construct.analysis_token_logprobs import AttributeConfidenceAnalyzer
    key=os.environ.get(cfg['api_key_env'])
    if not key: raise RuntimeError('Set '+cfg['api_key_env']+' before invoking the API method.')
    prompt=(ROOT/'config/first_pass.txt').read_text().replace('{{BANNER}}',banner)
    payload={'model':cfg['model'],'messages':[{'role':'user','content':prompt}],
             'temperature':cfg['temperature'],'max_tokens':cfg['max_tokens'],'reasoning':cfg['reasoning']}
    for attempt in range(cfg['max_retries']+1):
        req=urllib.request.Request(cfg['base_url'].rstrip('/')+'/chat/completions',
             data=json.dumps(payload).encode(),method='POST',
             headers={'Authorization':'Bearer '+key,'Content-Type':'application/json','User-Agent':'icslibrary-agent-comparison/1.0','X-Title':'ICSLibrary Agent Comparison'})
        try:
            with urllib.request.urlopen(req,timeout=cfg['timeout_seconds']) as response:
                reply=json.loads(response.read())
            break
        except urllib.error.HTTPError as error:
            if attempt==cfg['max_retries'] or error.code not in {408,409,429,500,502,503,504}:
                raise RuntimeError('API HTTP '+str(error.code)) from None
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as error:
            if attempt==cfg['max_retries']:raise RuntimeError('API transport failure: '+type(error).__name__) from None
        time.sleep(cfg['retry_backoff_seconds']*(attempt+1))
    if reply.get('error') or reply.get('model')!=cfg['model']:raise ValueError('API model/error contract mismatch')
    choice=reply['choices'][0]
    if choice.get('finish_reason')!='stop':raise ValueError('Incomplete API response')
    parsed=AttributeConfidenceAnalyzer().extract_json_result(choice['message']['content'])
    for field in ['brand','model','firmware_version']:
        if not isinstance(parsed,dict) or not isinstance(parsed.get(field),dict):raise ValueError('Invalid extraction structure')
        value=parsed[field].get('value')
        if value is not None and not isinstance(value,str):raise ValueError('Invalid extraction value')
    value=parsed['model']['value']
    return dict(pred_model=value if present(value) else None,accepted=present(value))


def classification(selected):
    true=[(r['protocol'],r['true_label']) for r in selected]
    pred=[(r['protocol'],r['pred_label']) for r in selected]
    support=collections.Counter(true);positive=collections.Counter(pred)
    tp=collections.Counter(t for t,p in zip(true,pred) if t==p)
    f={c:2*tp[c]/(support[c]+positive[c]) for c in support}
    return dict(accuracy=sum(tp.values())/len(true),macro_f1=sum(f.values())/len(f),
                weighted_f1=sum(support[c]*f[c] for c in f)/len(true))


def run(args):
    from engine import banner_from_input,ModelTaskPipeline
    methods=args.methods
    if any(m!='rules' for m in methods):
        if not args.author_source:raise ValueError('--author-source is required for neural methods.')
        runtime(args.author_source,args.work)
    cfg=json.loads((ROOT/'config/local.json').read_text());cfg['author_source']=args.author_source
    pipeline=None
    if any(m in methods for m in ['ea_only','ns_firmid_full_model']):
        if not args.base_model:raise ValueError('--base-model is required for local inference.')
        cfg['base_model']=args.base_model
        cfg['adapter']=str(Path(args.author_source)/'Extractor_agent_construct/agent_sft_Qwen2___5_7B_Instruct')
        pipeline=ModelTaskPipeline(cfg)
    api=json.loads((ROOT/'config/api.json').read_text())
    aliases=json.loads((ROOT/'config/scoring_aliases.json').read_text())
    cases=list(rows(Path(args.base)/'agent_cases.csv'));results=[]
    with Dataset(args.base) as ds:
        for view in ['response_original','model_evidence_controlled']:
            inputs={r['sample_id']:r['input'] for r in ds.agent_inputs([c['sample_id'] for c in cases],view)}
            for index,c in enumerate(cases,1):
                evidence=inputs[c['sample_id']];banner=banner_from_input(evidence)
                first=pipeline.first(banner) if pipeline else None
                outputs={}
                if 'rules' in methods:outputs['rules']=rule_predict(evidence)
                if 'ea_only' in methods:
                    value=first['parsed']['model']['value'];outputs['ea_only']=dict(pred_model=value,accepted=present(value))
                if 'ns_firmid_full_model' in methods:outputs['ns_firmid_full_model']=pipeline.full(banner,first)
                if 'deepseek_flash' in methods:outputs['deepseek_flash']=api_predict(banner,api)
                for method,out in outputs.items():
                    truth=ds.labels[c['endpoint_id']]['model_label'];pred=''
                    if out['accepted']:
                        pred,_=map_label(out['pred_model'],c['fold_id'],c['protocol'],aliases)
                        outcome='correct_confirmation' if pred==truth else 'wrong_confirmation'
                    else:outcome='abstain'
                    results.append(dict(method=method,view=view,fold=c['fold_id'],protocol=c['protocol'],
                                        true_label=truth,pred_label=pred,outcome=outcome))
                print(view,index,'/',len(cases),flush=True)
    # Predictions remain in memory only; the output contains newly computed metrics.
    summary=[]
    for method in methods:
        for view in ['response_original','model_evidence_controlled']:
            for protocol in ['modbus','enip','s7','all']:
                for fold in ['1','2','3','pooled']:
                    selected=[r for r in results if r['method']==method and r['view']==view and (protocol=='all' or r['protocol']==protocol) and (fold=='pooled' or r['fold']==fold)]
                    summary.append(dict(method=method,view=view,protocol=protocol,fold=fold,n_samples=len(selected),**metrics_for(selected),**classification(selected)))
    out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps({'evaluation':'exploratory paired case study','metrics':summary},indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',required=True);p.add_argument('--work',required=True);p.add_argument('--output',required=True)
    p.add_argument('--author-source');p.add_argument('--base-model')
    p.add_argument('--methods',nargs='+',choices=['rules','ea_only','ns_firmid_full_model','deepseek_flash'],default=['rules'])
    a=p.parse_args()
    for target in [a.work,a.output]:
        if Path(target).resolve().is_relative_to(Path(a.base).resolve()):p.error('Write outputs outside the input dataset.')
    run(a)
