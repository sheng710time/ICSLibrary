# Paired response-interpretation cases

This directory contains the fixed **90-endpoint case study**, with 30 endpoints per protocol and two input conditions per endpoint.

| File | Contents |
| --- | --- |
| `agent_cases.csv` | Selected sample/endpoint IDs, protocol, collection, fold membership, reference model labels, and input file names. |
| `response_original.jsonl.gz` | 90 decoded protocol-response inputs with instance information controlled. |
| `model_evidence_controlled.jsonl.gz` | The same 90 cases with selected explicit model evidence additionally masked. |
| `files.sha256.json` | File checksums. |

Each compressed JSONL file contains one record per case, keyed by `sample_id`. Only a record's `input` field is passed to an identification method. Reference labels in the case table are used for scoring.

These are response inputs, not saved model outputs. They match the corresponding cases in the benchmark-data archive. The two response conditions are separate from the three packet-traffic views under [network_traffic/views](../../network_traffic/views/README.md).

Run the [paired case-study commands](../README.md#4-run-the-paired-response-case-study) to generate predictions and metrics. Rules require only Python's standard library; neural and API methods require the dependencies described there.
