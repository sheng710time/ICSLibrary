# ICSLibrary model-identification benchmark

This package contains data interfaces and runnable adaptations for six traffic
methods and the paired response case study. Experiments start from the released
PCAP/response inputs. Model predictions are computed during execution; they are
not supplied as inputs to evaluation.

## 1. Obtain the data

See [DATA.md](DATA.md) for the archives. Extract the benchmark-data and
identifier-masked ZIPs into `data/` at the repository root. The resulting paths
are `data/v4_threefold/` and `data/v4_identifier_addon_v3/`. Leave the inner TAR
files intact: the loader reads individual connection PCAPs by byte offset.
The full collection and scanning-log archives support broader measurement work
and are not required to execute the benchmark adapters.

## 2. Run the five CPU traffic methods

Use Python 3.13 and a separate environment for the pinned CPU dependencies:

```bash
python3.13 -m venv .venv-traffic
.venv-traffic/bin/python -m pip install -r benchmark/traffic/requirements.txt
.venv-traffic/bin/python benchmark/traffic/run.py \
  --base data/v4_threefold --addon data/v4_identifier_addon_v3 \
  --method XGB-IDI --protocol modbus --fold 1 --view instance_controlled \
  --work work/traffic --output outputs/xgb-modbus-f1-control.json
```

This command extracts features, fits using Collection A's training samples,
and evaluates validation plus the six A/B/C same/unseen test conditions.
It writes newly computed metrics. Change `--method` to `LSIF`, `IDT-AIM`,
`PINGPONG`, or `WiFinger`; protocols are `modbus`, `enip`, `s7`; folds are 1--3;
views are `raw`, `instance_controlled`, `identifier_masked`.

To run the complete five-method matrix and compute three-fold means, sample
standard deviations, and paired Macro-F1 differences:

```bash
.venv-traffic/bin/python benchmark/run_traffic.py \
  --base data/v4_threefold --addon data/v4_identifier_addon_v3 \
  --work work/cpu-matrix --output outputs/cpu-matrix.json
```

Use `--methods`, `--protocols`, `--folds`, and `--views` to select a smaller run.
Each condition fits from its training data. WiFinger's fingerprint eligibility
policy is selected on A validation before its test conditions are evaluated.
Fingerprint extraction and uncapped FMLCS matching can be substantially slower
than the tabular baselines.

## 3. Run TrafficFormer

Use Python 3.11 with a CUDA-capable PyTorch environment, separate from the CPU
baselines. The original runs used PyTorch 2.0.1 with CUDA 11.8 on an RTX 3090 Ti.
Obtain the upstream code and pretrained backbone from their original sources:

```bash
git clone https://github.com/IDP-code/TrafficFormer.git external/TrafficFormer
git -C external/TrafficFormer checkout 6d0ba64d82e74fb130c6c7301ef20885dbfbdf29
python3.11 -m venv .venv-tf
.venv-tf/bin/python -m pip install torch==2.0.1+cu118 --index-url https://download.pytorch.org/whl/cu118
.venv-tf/bin/python -m pip install -r benchmark/trafficformer/requirements.txt
```

Download and unpack the pretrained model linked by the
[upstream README](https://github.com/IDP-code/TrafficFormer/blob/6d0ba64d82e74fb130c6c7301ef20885dbfbdf29/README.md).
The expected `nomoe_bertflow_pre-trained_model.bin-120000` SHA-256 is
`be9dcc1e0c6b68db005e506adf13a2d937a2f3982539a2c8a58f78c55af0d5ce`.
Place it under `external/weights/` and run:

```bash
.venv-tf/bin/python benchmark/trafficformer/run.py \
  --base data/v4_threefold --addon data/v4_identifier_addon_v3 \
  --author-source external/TrafficFormer \
  --weights external/weights/nomoe_bertflow_pre-trained_model.bin-120000 \
  --protocol s7 --fold 1 --view instance_controlled \
  --work work/trafficformer --output outputs/tf-s7-f1-control.json
```

The runner prepares inputs, fine-tunes for four epochs, selects the checkpoint
by A-validation sample Macro-F1, and scores the six test conditions. Each
endpoint-round prediction averages its connection probabilities. For a
preprocessing check, add `--prepare-only --smoke-samples-per-class 1`; this is
not a formal benchmark result. For the full matrix, use `benchmark/run_traffic.py
--methods TrafficFormer` with the same source/weights arguments.

## 4. Run the paired response case study

Rules require only Python's standard library:

```bash
python benchmark/agent/run.py --base data/v4_threefold \
  --methods rules --work work/agent --output outputs/agent-rules.json
```

For neural extraction, obtain the upstream NS-FirmID components and the fixed
Qwen revision. Model weights and knowledge-base/classifier assets are fetched
from their publishers; they are not redistributed in this package.

```bash
git clone https://github.com/lululu930/NS-FirmID.git external/NS-FirmID
git -C external/NS-FirmID checkout 5d436706d48481e08e2109f83d06628d09c13e3a
python3.13 -m venv .venv-agent
.venv-agent/bin/python -m pip install -r benchmark/agent/requirements.txt
.venv-agent/bin/hf download Qwen/Qwen2.5-7B-Instruct \
  --revision a09a35458c702b33eeacc393d103063234e8bc28 \
  --local-dir external/Qwen2.5-7B-Instruct
.venv-agent/bin/python benchmark/agent/run.py \
  --base data/v4_threefold --author-source external/NS-FirmID \
  --base-model external/Qwen2.5-7B-Instruct \
  --methods rules ea_only ns_firmid_full_model \
  --work work/agent --output outputs/agent-local.json
```

Ensure the upstream LoRA adapter, two knowledge-base JSONs, and discriminator
checkpoint are downloaded, including Git LFS objects if applicable. The local
adapter uses NF4 quantization with FP16 computation and needs a CUDA GPU. The
runtime copies only the necessary upstream Python modules into `--work`, repairing
an import path and omitting an unavailable relabeling utility import and an
incomplete demonstration string. The inference definitions remain unchanged.

For the API extractor, set `OPENROUTER_API_KEY` in your environment and choose
`--methods deepseek_flash` with `--author-source external/NS-FirmID`. This option
sends the 180 response inputs to the configured provider and incurs API usage.
It uses the pinned prompt/settings in `agent/config/`; API availability and
responses can change. The script reads credentials only from the environment
and does not save prompts, API responses, token-level reasoning, or predictions.

The case study uses 90 endpoints under two evidence conditions. It is an
exploratory adaptation study, not a blind evaluation on newly acquired cases.
Scoring aliases are used only after inference and never enter model prompts.
Failures stop a run rather than being counted as abstentions.

## Data and evaluation conventions

- Training: A rounds 1--12; validation: A rounds 13--16, using training endpoints.
- Testing: rounds 17--20 in A/B/C, with same and held-out endpoints separated.
- Seeds: 42, 43, 44 for endpoint folds 1, 2, 3.
- A Macro-F1 uses all trained classes; B/C uses the classes present in each test
  condition. All available listed samples contribute, including method no-matches.
- Means/std are across folds; paired changes are computed within each fold
  before aggregation. Scores use decimals.

See [ADAPTATIONS.md](ADAPTATIONS.md) for the method inputs and task adaptations.
The collection scanner source is under [`scanners/`](../scanners/README.md); benchmark commands
operate on downloaded records and do not invoke them.

## Generated files

`work/` contains disposable feature/token caches and, for TrafficFormer, training
checkpoints. `outputs/` contains the metrics generated by your execution.
Neither directory belongs to the release. You can delete them after evaluation
and regenerate them from the same data, code and dependencies. No saved
per-sample predictions or original experiment logs are required.
