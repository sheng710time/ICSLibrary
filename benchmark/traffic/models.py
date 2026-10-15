"""Method adapters. ICS model-identification adaptations."""
from common import *
import numpy as np
from collections import Counter,defaultdict
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import AdaBoostClassifier
from sklearn.preprocessing import StandardScaler

class FeatureWeightedTree(ClassifierMixin,BaseEstimator):
 """CART with a feature-weight multiplier on Gini reduction (not feature values)."""
 def __init__(self,feature_weights=None,max_depth=3,min_samples_leaf=10,random_state=42):
  self.feature_weights=feature_weights; self.max_depth=max_depth; self.min_samples_leaf=min_samples_leaf; self.random_state=random_state
 def fit(self,X,y,sample_weight=None):
  X=np.asarray(X,dtype=float); self.classes_,y=np.unique(y,return_inverse=True); self.n_classes_=len(self.classes_); self.n_features_in_=X.shape[1]
  sw=np.ones(len(y))/len(y) if sample_weight is None else np.asarray(sample_weight)
  fw=np.ones(X.shape[1]) if self.feature_weights is None else self.feature_weights
  def build(ids,features,depth):
   counts=np.bincount(y[ids],weights=sw[ids],minlength=self.n_classes_); total=counts.sum(); prob=counts/total
   if depth>=self.max_depth or (counts>0).sum()<=1 or len(ids)<2*self.min_samples_leaf: return (-1,prob)
   impurity=1-np.sum(prob**2); best=None
   for j in features:
    order=np.argsort(X[ids,j],kind='stable'); ix=ids[order]; v=X[ix,j]
    valid=np.flatnonzero(v[:-1]<v[1:]); valid=valid[(valid+1>=self.min_samples_leaf)&(len(ix)-valid-1>=self.min_samples_leaf)]
    if not len(valid): continue
    onehot=np.zeros((len(ix),self.n_classes_)); onehot[np.arange(len(ix)),y[ix]]=sw[ix]
    left=np.cumsum(onehot,axis=0)[valid]; right=counts-left; wl=left.sum(axis=1); wr=right.sum(axis=1)
    ok=(wl>1e-15)&(wr>1e-15)
    if not ok.any(): continue
    valid=valid[ok]; left=left[ok]; right=right[ok]; wl=wl[ok]; wr=wr[ok]
    reduction=impurity-(wl*(1-(left**2).sum(axis=1)/wl**2)+wr*(1-(right**2).sum(axis=1)/wr**2))/total
    scored=reduction*fw[j]; at=int(np.argmax(scored)); rank=(float(scored[at]),float(reduction[at]),-j)
    if reduction[at]>1e-12 and (best is None or rank>best[0]): best=(rank,j,int(valid[at]),ix,v)
   if best is None: return (-1,prob)
   _,j,k,ix,v=best; threshold=float(v[k]+(v[k+1]-v[k])/2); remaining=[f for f in features if f!=j]
   return (j,threshold,build(ix[:k+1],remaining,depth+1),build(ix[k+1:],remaining,depth+1))
  self.tree_=build(np.arange(len(y)),list(range(X.shape[1])),0); return self
 def predict_proba(self,X):
  X=np.asarray(X); out=np.empty((len(X),self.n_classes_))
  def visit(node,ix):
   if node[0]==-1: out[ix]=node[1]; return
   j,t,l,r=node; mask=X[ix,j]<=t; visit(l,ix[mask]); visit(r,ix[~mask])
  visit(self.tree_,np.arange(len(X))); return out
 def predict(self,X): return self.classes_[self.predict_proba(X).argmax(axis=1)]

class IDTAIM:
 def __init__(self,seed,config): self.seed=seed; self.config=config
 def fit(self,X,y):
  self.scaler=StandardScaler().fit(X); Z=self.scaler.transform(X)
  # Reuse the prior ICS Relief implementation's neighbor loop; all training
  # packets remain eligible. Numeric differences use its documented adaptation.
  from numeric_features import compute_feature_weights
  mn=Z.min(axis=0); span=np.ptp(Z,axis=0); span[span==0]=1
  raw,weight=compute_feature_weights((Z-mn)/span,y,np.array([i in (2,5,6,10) for i in range(X.shape[1])]),self.config['relief_iterations'],self.config['relief_neighbors'],len(X),self.seed)
  self.raw_weights=raw; self.feature_weights=weight
  base=FeatureWeightedTree(feature_weights=weight,max_depth=self.config['max_depth'],min_samples_leaf=self.config['min_samples_leaf'],random_state=self.seed)
  self.classifier=AdaBoostClassifier(estimator=base,n_estimators=self.config['n_estimators'],learning_rate=self.config['learning_rate'],random_state=self.seed)
  self.classifier.fit(Z,y); return self
 def predict_proba(self,X): return self.classifier.predict_proba(self.scaler.transform(X))

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
