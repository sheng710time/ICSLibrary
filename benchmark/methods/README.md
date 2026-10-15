# Traffic-based methods

Each method has one implementation directory. The benchmark uses shared sample loading, endpoint splits, and evaluation conventions.

| Method | Implementation | Execution |
| --- | --- | --- |
| [LSIF](lsif/) | `model.py`: endpoint fingerprints and similarity scores | CPU runner with `--method LSIF` |
| [IDT-AIM](idt_aim/) | `features.py`: Relief weights; `model.py`: weighted decision trees and AdaBoost | CPU runner with `--method IDT-AIM` |
| [XGB-IDI](xgb_idi/) | `features.py`: payload entropy and statistics; `model.py`: XGBoost fitting | CPU runner with `--method XGB-IDI` |
| [PingPong](pingpong/) | `core.py`: signatures and matching; `experiment.py`: ICS signature construction | CPU runner with `--method PINGPONG` |
| [WiFinger](wifinger/README.md) | ICS fingerprint adaptation and the required `fmlcs/` extraction/matching algorithms | CPU runner with `--method WiFinger` |
| [TrafficFormer](trafficformer/) | `prepare.py`, `train.py`, and `run.py` use the upstream pretrained backbone | TrafficFormer runner |

The CPU runner is [`../traffic/run.py`](../traffic/run.py). Shared PCAP preparation is in [`../traffic/extract.py`](../traffic/extract.py), and the CPU settings are in [`../traffic/config.json`](../traffic/config.json). The full matrix runner is [`../run_traffic.py`](../run_traffic.py).

See the [run instructions](../README.md) for environments and commands, and the [adaptation notes](../ADAPTATIONS.md) for input representations and task-specific decisions.
