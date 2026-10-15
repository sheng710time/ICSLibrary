"""LSIF endpoint fingerprints and model similarity scores."""
import numpy as np
from collections import defaultdict

class LSIF:
 def fit(self,rows,labels):
  by=defaultdict(list)
  for endpoint,digest in rows:
   if digest is not None: by[endpoint].append(np.unpackbits(np.frombuffer(bytes.fromhex(digest),dtype=np.uint8)).astype(float)*2-1)
  self.endpoints=sorted(by); self.labels=[labels[e] for e in self.endpoints]
  self.mean_bits=np.array([np.mean(by[e],axis=0) for e in self.endpoints]); return self
 def scores(self,digests):
  bits=np.array([np.unpackbits(np.frombuffer(bytes.fromhex(d),dtype=np.uint8)).astype(float)*2-1 for d in digests])
  return bits@self.mean_bits.T/2
