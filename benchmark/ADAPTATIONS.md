# Method adaptations

All traffic methods use the released endpoint folds and endpoint-round samples.
Methods are trained separately by protocol, fold, and view. A model label is the
classification target; endpoint IDs are grouping metadata, not prediction inputs.

| Method | Released adaptation |
| --- | --- |
| LSIF | Nilsimsa fingerprints of filtered IP packet contents; mean fingerprint similarity by training endpoint; model decision from endpoint matches. |
| IDT-AIM | 17 TCP/IP features, no geography; training-only feature scaling and Relief weights; feature-weighted decision trees with AdaBoost; mean packet probabilities per sample. |
| XGB-IDI | Response-payload entropy over 24 bytes and byte sums over 48 bytes, each summarized by five statistics; XGBoost sample classification. |
| PingPong | Protocol interactions form events; signatures are built per training endpoint/port/operation. Native signature acceptance and packet-count/distance evidence precede model aggregation. Matching considers all trained signatures. |
| WiFinger | Fingerprints are built per training endpoint/port/operation from independent endpoint-round executions; full captured frame lengths, directions and relative times; native consensus/refinement and uncapped FMLCS matching. |
| TrafficFormer | Official pretrained backbone, five packets/64 IPv4 bytes per packet, 320-token input, training augmentation factor five; controlled fields remain controlled after augmentation. Mean connection probability gives the endpoint-round prediction. |

The sequence methods use native match evidence and one rational vote per
operation. Remaining ties and no-matches use the training endpoint-count prior,
then lexical label order. WiFinger chooses among `min4`, `short_fallback`, `min2`,
and `all` fingerprint eligibility policies using A validation, ranked by
Macro-F1, Accuracy, Weighted-F1, then that policy order. This is an ICS model-task
adaptation, not a claim that the original event-identification papers used this
cross-model decision rule. The revised design was motivated by prior experimental
observations; its final policy selection uses training-endpoint validation data.

The response study compares protocol-field rules, neural extraction, the adapted
NS-FirmID pipeline and a single-pass API extractor. NS-FirmID's original target
is firmware identification. This adaptation targets model confirmations, retains
its model verification/discrimination components, and allows abstention. Both
response views share the same cases. Exact scoring aliases derive from allowed
training labels and are kept separate from inference inputs.

## Sources

The CPU adapters implement the LSIF, IDT-AIM, XGB-IDI, PingPong and WiFinger
methods cited in the paper. `traffic/device_identification/wifinger_fmlcs/`
contains the supplied FMLCS implementation used by the WiFinger adapter;
`pingpong/` and `wifinger/` contain the ICS task adaptations. The distribution
retains only the functions used by this benchmark.

TrafficFormer source is obtained from [IDP-code/TrafficFormer](https://github.com/IDP-code/TrafficFormer),
commit `6d0ba64d82e74fb130c6c7301ef20885dbfbdf29`.
NS-FirmID source/assets are obtained from [lululu930/NS-FirmID](https://github.com/lululu930/NS-FirmID),
commit `5d436706d48481e08e2109f83d06628d09c13e3a`.
The Qwen base revision is recorded in `agent/config/local.json`. Third-party
models and assets remain subject to their publishers' terms and are not bundled.
