"""Local paths, frozen release loader, and the unmodified official classifier."""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import os
CODE_ROOT = Path(__file__).resolve().parent
RUN_ROOT = Path(os.environ['ICSLIBRARY_WORK']).resolve()
DATA_ROOT = Path(os.environ['ICSLIBRARY_BASE']).resolve()
ADDON_ROOT = Path(os.environ['ICSLIBRARY_ADDON']).resolve()
AUTHOR_ROOT = Path(os.environ['TRAFFICFORMER_SOURCE']).resolve()
WEIGHTS = Path(os.environ['TRAFFICFORMER_WEIGHTS']).resolve()
PLAN_VERSION = 'CSI-EXP-20260930-flow-identifier-v3'
ADAPTER_VERSION = 'ics-trafficformer-flow-identifier-v3.1'
sys.dont_write_bytecode = True
sys.path.insert(0, str(AUTHOR_ROOT))
sys.path.insert(0, str(CODE_ROOT.parents[1] / 'data'))

from dataset_io import rows, index_file
from identifier_dataset_io import IdentifierDataset


class Dataset(IdentifierDataset):
    def __init__(self, root=DATA_ROOT):
        super().__init__(root, ADDON_ROOT)


FEATURE_CONFIG = {'sequence_length': 320, 'packet_limit': 5, 'byte_hex_start': 28,
                  'byte_hex_stop': 156, 'augmentation_factor': 5,
                  'training_rifa': 'official_draws_v1_controlled_restore',
                  'aggregation': 'mean_connection_probability',
                  'operation_grouping': 'none_preserve_independent_connections',
                  'operation_features': False}


def input_binding():
    return {'release_manifest_sha256': digest(DATA_ROOT / 'files.sha256.json'),
            'addon_manifest_sha256': digest(ADDON_ROOT / 'files.sha256.json'),
            'operation_mapping_sha256': digest(index_file(ADDON_ROOT, 'flow_operations.csv')),
            'addon_flows_sha256': digest(index_file(ADDON_ROOT, 'flows.csv')),
            'sample_assignments_sha256': digest(index_file(DATA_ROOT, 'sample_assignments.csv')),
            'identifier_loader_sha256': digest(CODE_ROOT.parents[1] / 'data' / 'identifier_dataset_io.py'),
            'adapter_common_sha256': digest(__file__),
            'pcap_control_sha256': digest(CODE_ROOT.parents[1] / 'data' / 'pcap_views.py'),
            'official_serializer_sha256': digest(AUTHOR_ROOT / 'data_generation' / 'finetuning_data_gen.py'),
            'official_classifier_sha256': digest(AUTHOR_ROOT / 'fine-tuning' / 'run_classifier.py'),
            'official_config_sha256': digest(AUTHOR_ROOT / 'models' / 'bert' / 'base_config.json'),
            'extractor_sha256': digest(CODE_ROOT / 'prepare.py'),
            'feature_config': FEATURE_CONFIG}


def operations_for(dataset, row):
    value = dataset.operations[row['flow_id']]
    if value['sample_id'] != row['sample_id'] or value['protocol'] != row['protocol']:
        raise ValueError('Operation mapping does not match the independent flow')
    # Kept in a sidecar only. No operation or identifier audit column becomes a token.
    return {key: json.loads(value[key]) for key in
            ('probe_operations', 'setup_operations', 'unknown_operations')}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def author_module():
    spec = importlib.util.spec_from_file_location('trafficformer_official_classifier',
                                                AUTHOR_ROOT / 'fine-tuning' / 'run_classifier.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def model_args(n_classes, seed, total_updates, learning_rate=6e-5):
    from uer.opts import finetune_opts
    from uer.utils.config import load_hyperparam
    from uer.utils.tokenizers import BertTokenizer
    parser = argparse.ArgumentParser()
    finetune_opts(parser)
    args = parser.parse_args([])
    args.config_path = str(AUTHOR_ROOT / 'models' / 'bert' / 'base_config.json')
    args.vocab_path = str(AUTHOR_ROOT / 'models' / 'encryptd_vocab.txt')
    args = load_hyperparam(args)
    args.pooling = 'first'
    args.soft_targets = False
    args.soft_alpha = 0.5
    args.is_moe = False
    args.labels_num = n_classes
    args.seed = seed
    args.seq_length = 320
    args.learning_rate = learning_rate
    args.train_steps = total_updates
    args.tokenizer = BertTokenizer(args)
    return args


def load_pretrained(model):
    import torch
    state = torch.load(WEIGHTS, map_location='cpu', weights_only=True)
    incompatible = model.load_state_dict(state, strict=False)
    expected_missing = {'output_layer_1.weight', 'output_layer_1.bias',
                        'output_layer_2.weight', 'output_layer_2.bias'}
    if set(incompatible.missing_keys) != expected_missing:
        raise ValueError(f'Incomplete pretrained backbone: {incompatible.missing_keys}')
    if any(not name.startswith('target.') for name in incompatible.unexpected_keys):
        raise ValueError(f'Unexpected pretrained keys: {incompatible.unexpected_keys}')
    return {'missing_classifier_keys': incompatible.missing_keys,
            'unused_pretraining_keys': incompatible.unexpected_keys}


def class_labels(protocol):
    found = sorted((r for r in rows(index_file(DATA_ROOT, 'classes.csv')) if r['protocol'] == protocol),
                   key=lambda r: int(r['class_id']))
    assert [int(r['class_id']) for r in found] == list(range(len(found)))
    return [r['model_label'] for r in found]


def json_write(path, value):
    path = Path(path)
    pending = path.with_name(path.name + '.writing')
    pending.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
    pending.replace(path)
