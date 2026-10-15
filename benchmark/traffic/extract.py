"""Release loader adapter. No splitting, fitting, or sample eligibility decisions."""
from common import *
import argparse, io, pickle, time, ipaddress, ast
from collections import defaultdict, Counter
import numpy as np
from nilsimsa import Nilsimsa
from methods.pingpong.data import Interaction as PI
from methods.pingpong.core import PacketPoint as PP
from methods.wifinger.data import Interaction as WI
from methods.wifinger.core import PacketPoint as WP

from methods.xgb_idi import features as xgb_features
from methods.xgb_idi.features import compute_entropy as entropy, compute_statistics as stats
IDT_FEATURES=['ttl','tos','df_flag','packet_length','ecn','mf_flag','protocol','src_port','dst_port','window_size','ics_protocol','num','av','var','max','min','mr']
XGB_FEATURES=['std_dev','coefficient_variation','skewness','range','iqr','std_dev_hex_sum','coefficient_variation_hex_sum','skewness_hex_sum','range_hex_sum','iqr_hex_sum']

EXTRACTOR_VERSION='identifier-v3-shared-probes-r2.1'
def shared_operation(row):
 # Keep the full probe list if a future release contains a mixed flow.
 probes=json.loads(row['probe_operations'])
 assert isinstance(probes,list) and all(isinstance(x,str) for x in probes)
 if not probes: return None
 return probes[0] if len(probes)==1 else 'probes:'+json.dumps(probes,separators=(',',':'))

def fingerprint_for(ds,protocol,view,mode):
 return {'base':sha(ds.root/'files.sha256.json'),'addon':sha(ds.addon/'files.sha256.json'),
         'extractor':sha(__file__), 'features':sha(xgb_features.__file__),
         'mode':mode,'protocol':protocol,'view':view}

def extract(ds,protocol,view,mode,work):
 from dataset_io import rows,index_file
 from pcap_views import read_pcap,parse_packet,u16,SERVER_IP,SERVER_PORTS
 fingerprint=fingerprint_for(ds,protocol,view,mode)
 dest=Path(work)/f'{protocol}_{view}_{mode}.pkl'
 dest.parent.mkdir(parents=True,exist_ok=True)
 if dest.exists():
  try:
   with dest.open('rb') as f: existing=pickle.load(f)
  except (ImportError, AttributeError):
   # A previous code layout may have serialized classes at different paths.
   existing=None
   print('rebuilding cache from an earlier code layout',dest,flush=True)
  if existing is not None and existing['fingerprint']==fingerprint: print('cache valid',dest,flush=True); return existing['data']
 wanted={s:r for s,r in ds.samples.items() if r['protocol']==protocol}
 flowrows=defaultdict(list)
 for r in rows(index_file(ds.addon,'flows.csv')):
  if r['sample_id'] in wanted: flowrows[r['sample_id']].append(r)
 output={}; audit=Counter(); flow_audit=[]; started=time.time()
 for ix,(sid,sample) in enumerate(wanted.items(),1):
  endpoint=sample['endpoint_id']; label=ds.labels[endpoint]
  address=SERVER_IP if view!='raw' else ipaddress.IPv4Address(label['anonymized_ip']).packed
  port=SERVER_PORTS[protocol] if view!='raw' else int(label['port'])
  allpack=[]; idt=[]; ents=[]; sums=[]; ping=[]; wifi=[]; lsif=[]
  origin=int(flowrows[sid][0]['sample_time_origin_ns']) if view=='raw' else 0
  for row in flowrows[sid]:
   packets=[parse_packet(*r) for r in read_pcap(io.BytesIO(ds.read_flow(row,view,verify_hash=True)))]
   assert all(p is not None for p in packets)
   for p in packets:
    p.server=(p.data[p.ip+12:p.ip+16]==address and u16(p.data,p.tcp)==port)
    client=(p.data[p.ip+16:p.ip+20]==address and u16(p.data,p.tcp+2)==port)
    assert p.server != client, (view,row['flow_id'],'ambiguous direction')
    audit['server_packets' if p.server else 'client_packets']+=1
    if view!='raw':
     assert u16(p.data,p.ip+10)==0 and u16(p.data,p.tcp+16)==0
   assert len(packets)==int(row['packet_count'])
   op_row=ds.operations[row['flow_id']]
   assert op_row['sample_id']==sid and op_row['protocol']==protocol
   op=shared_operation(op_row)
   audit['probe_flows' if op is not None else 'nonprobe_flows']+=1
   audit['flows']+=1; audit['packets']+=len(packets)
   if mode=='tabular':
    allpack.extend(packets)
    for p in packets:
     if p.server:
      flags=u16(p.data,p.ip+6); tos=p.data[p.ip+1]
      idt.append([p.data[p.ip+8],tos,int(bool(flags&0x4000)),len(p.data),tos&3,int(bool(flags&0x2000)),0,u16(p.data,p.tcp),u16(p.data,p.tcp+2),u16(p.data,p.tcp+14),int(u16(p.data,p.tcp+2) in ({502,503} if protocol=='modbus' else {port}))])
      if p.payload:
       ents.append(entropy(p.payload[:24])); sums.append(sum(p.payload[:48]))
    continue
   # All deduplication is connection-local. The source sequence methods use (direction,seq,payload).
   seen=set(); dedup=[]
   for p in packets:
    key=(p.server,p.seq,p.payload)
    if key not in seen: seen.add(key); dedup.append(p)
   req=[p.payload for p in dedup if not p.server and len(p.payload)>4]
   base=dict(endpoint=endpoint,port=port,source_file=sample['capture_id'],round_id=int(sample['round_index']),interaction_id=row['flow_id'])
   if req and op is not None:
    ps=tuple(PP((p.time_ns-origin)/1e9,len(p.data),-1 if p.server else 1) for p in dedup if p.payload)
    if ps: ping.append(PI(operation=op,packets=ps,**base))
   else: audit['ping_no_request_or_probe_flows']+=1
   if op is not None:
    start=dedup[0].time_ns
    ps=tuple(WP((p.time_ns-start)/1e9,len(p.data),-1 if p.server else 1) for p in dedup if p.time_ns-start<=15_000_000_000)
    if len(ps)>=2: wifi.append(WI(operation=op,packets=ps,**base))
    else: audit['wifi_short_flows']+=1
   else: audit['wifi_unrecognized_operation_flows']+=1
   # Primary LSIF ICS implementation: retransmission filter, handshake removal,
   # qualifying request, full IP bytes with addresses zero (checksums retained in raw).
   seen1=set(); seen2=set(); kept=[]; handshake={}
   for p in packets:
    k1=(p.server,p.ack,p.flags,p.payload); k2=(p.server,p.ack,p.seq,p.payload) if p.payload else None
    if k1 in seen1 or (k2 is not None and k2 in seen2): continue
    seen1.add(k1)
    if k2 is not None: seen2.add(k2)
    if p.flags==2: handshake[p.server]='S'
    elif p.flags==18: handshake[not p.server]='SA'
    elif p.flags==16 and handshake.get(p.server)=='SA': del handshake[p.server]
    elif p.flags in (4,20): continue
    else: kept.append(p)
   if any(not p.server and len(p.payload)>4 for p in kept):
    for p in kept:
     b=bytearray(p.data[p.ip:]); b[12:20]=b'\0'*8
     lsif.append((p.time_ns,int(row['source_packet_ordinals'].split()[p.ordinal-1]),bytes(b)))
  if mode=='tabular':
   lengths=np.array([len(p.data) for p in allpack],dtype=float)
   st=[len(lengths),float(lengths.mean()),float(lengths.var()),float(lengths.max()),float(lengths.min()),float(np.ptp(lengths))]
   assert idt and ents, f'Valid source lacks server packet/payload {sid}'
   es=stats(ents); hs=stats(sums)
   output[sid]={'idt':np.array([v+st for v in idt],dtype=np.float32),'xgb':np.array(list(es.values())+list(hs.values()),dtype=np.float64),'server_payload_count':len(ents)}
  else:
   material=b''.join(b for _,_,b in sorted(lsif,key=lambda r:(r[0],r[1])))
   output[sid]={'lsif':Nilsimsa(material).hexdigest() if material else None,'pingpong':ping,'wifinger':wifi}
   audit['lsif_empty_samples']+=not material; audit['ping_empty_samples']+=not ping; audit['wifi_empty_samples']+=not wifi
  if ix%1000==0: print(protocol,view,mode,ix,'/',len(wanted),round(time.time()-started,1),'s',flush=True)
 assert set(output)==set(wanted)
 temp=dest.with_suffix('.tmp')
 with temp.open('wb') as f: pickle.dump({'fingerprint':fingerprint,'data':output},f,protocol=5)
 temp.replace(dest)
 print('extraction complete',dest,flush=True)
 return output
