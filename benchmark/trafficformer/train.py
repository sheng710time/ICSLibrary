"""Single-GPU official TrafficFormer fine-tuning and public-sample evaluation."""
import csv
import json
import math
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score

from common import (ADAPTER_VERSION, AUTHOR_ROOT, DATA_ROOT, PLAN_VERSION, RUN_ROOT,
                    WEIGHTS, Dataset, author_module, class_labels, digest, json_write,
                    input_binding, load_pretrained, model_args)


def now():
    return datetime.now(timezone.utc).isoformat()


def load_cache(directory):
    directory = Path(directory)
    return {'tokens': np.load(directory / 'tokens.npy', mmap_mode='r'),
            'targets': np.load(directory / 'targets.npy'),
            'sample_indices': np.load(directory / 'sample_indices.npy'),
            'sample_ids': json.loads((directory / 'sample_ids.json').read_text()),
            'metadata': json.loads((directory / 'metadata.json').read_text())}


def model_batch(cache, indices, device):
    src = torch.from_numpy(np.array(cache['tokens'][indices], dtype=np.int64)).to(device)
    target = torch.from_numpy(cache['targets'][indices]).to(device)
    seg = (src != 0).long()
    return src, target, seg


def update_window(model, optimizer, scheduler, scaler, cache, indices,
                  micro_batch, device, amp=True, max_grad_norm=0.0):
    """One effective batch, weighted by actual examples including every tail."""
    optimizer.zero_grad(set_to_none=True)
    total_loss = 0.0
    for start in range(0, len(indices), micro_batch):
        selected = indices[start:start + micro_batch]
        src, target, seg = model_batch(cache, selected, device)
        with torch.autocast(device_type=device.type,
                            dtype=torch.float16 if device.type == 'cuda' else torch.bfloat16,
                            enabled=amp):
            loss, _ = model(src, target, seg)
        if not torch.isfinite(loss):
            raise FloatingPointError('Non-finite training loss')
        total_loss += loss.item() * len(selected)
        scaler.scale(loss * (len(selected) / len(indices))).backward()
    scaler.unscale_(optimizer)
    if max_grad_norm:
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
    previous_scale = scaler.get_scale()
    scaler.step(optimizer)
    scaler.update()
    successful = scaler.get_scale() >= previous_scale
    if successful:
        scheduler.step()
    return total_loss / len(indices), successful


def predict(model, cache, n_classes, batch_size, device):
    """Mean connection probability per public sample, tie -> class_id order."""
    model.eval()
    sums = np.zeros((len(cache['sample_ids']), n_classes), dtype=np.float64)
    counts = np.zeros(len(cache['sample_ids']), dtype=np.int64)
    torch.cuda.reset_peak_memory_stats()
    start = time.monotonic()
    with torch.inference_mode():
        for index in range(0, len(cache['targets']), batch_size):
            indices = np.arange(index, min(index + batch_size, len(cache['targets'])))
            src, target, seg = model_batch(cache, indices, device)
            with torch.autocast(device_type='cuda', dtype=torch.float16):
                _, logits = model(src, None, seg)
            probabilities = torch.softmax(logits.float(), dim=-1).cpu().numpy()
            if not np.isfinite(probabilities).all():
                raise FloatingPointError('Non-finite predictions; retain inputs and rerun')
            np.add.at(sums, cache['sample_indices'][indices], probabilities)
            np.add.at(counts, cache['sample_indices'][indices], 1)
    assert (counts > 0).all(), 'Missing predictions for a public sample'
    probabilities = sums / counts[:, None]
    truth = np.full(len(counts), -1, dtype=np.int64)
    for internal, sample in enumerate(cache['sample_indices']):
        target = cache['targets'][internal]
        assert truth[sample] in (-1, target)
        truth[sample] = target
    return truth, probabilities, {'seconds': time.monotonic() - start,
                'peak_allocated_mib': torch.cuda.max_memory_allocated() / 2**20,
                'peak_reserved_mib': torch.cuda.max_memory_reserved() / 2**20}


def atomic_save(path, value):
    temporary = path.with_suffix(path.suffix + '.partial')
    torch.save(value, temporary)
    temporary.replace(path)


def train_run(run_id, protocol, fold, view, caches, epochs=4,
              micro_batch=8, accumulation=16, smoke=False):
    directory = RUN_ROOT / 'models' / run_id
    directory.mkdir(parents=True, exist_ok=True)
    completed = directory / 'run.json'
    if completed.exists():
        previous = json.loads(completed.read_text())
        if previous['config']['epochs'] != epochs or previous['config']['micro_batch'] != micro_batch:
            raise ValueError('Completed run has a different configuration')
        return previous
    labels = class_labels(protocol)
    seed = 41 + fold
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.set_num_threads(8)
    torch.backends.cudnn.benchmark = False
    train_cache, valid_cache = load_cache(caches['A/train']), load_cache(caches['A/validation'])
    effective_batch = micro_batch * accumulation
    n_updates = math.ceil(len(train_cache['targets']) / effective_batch) * epochs
    args = model_args(len(labels), seed, n_updates)
    official = author_module()
    model = official.Classifier(args)
    load_info = load_pretrained(model)
    device = torch.device('cuda:0')
    torch.cuda.reset_peak_memory_stats()
    model.to(device)
    loading_peak = torch.cuda.max_memory_allocated() / 2**20
    optimizer, scheduler = official.build_optimizer(args, model)
    scaler = torch.cuda.amp.GradScaler()
    config = {'protocol': protocol, 'fold_id': fold, 'view_id': view, 'train_seed': seed,
              'epochs': epochs, 'micro_batch': micro_batch, 'accumulation': accumulation,
              'effective_batch': effective_batch, 'seq_length': 320, 'learning_rate': 6e-5,
              'warmup': args.warmup, 'precision': 'native_amp_fp16', 'optimizer': 'official_adamw',
              'dropout': args.dropout, 'gradient_clipping': None, 'planned_updates': n_updates,
              'augmentation_factor': 5, 'aggregation': 'mean_connection_probability',
              'checkpoint_selection': 'A_validation_sample_macro_F1_then_earliest_epoch',
              'adapter_version': ADAPTER_VERSION, 'smoke_subset': smoke}
    config['input_binding'] = input_binding()
    config['input_cache_fingerprints'] = {key: digest(Path(path) / 'metadata.json')
                                          for key, path in caches.items()}
    # Validation fixes the aggregation rule before any test labels are evaluated.
    json_write(directory / 'config.json', config)
    start_epoch, best_score, best_epoch = 0, -1.0, None
    history = []
    successful_updates, skipped_updates = 0, 0
    started_at = now()
    state_path = directory / 'last.pt'
    if state_path.exists():
        state = torch.load(state_path, map_location='cpu', weights_only=False)
        if state['config'] != config:
            raise ValueError('Resume configuration mismatch')
        model.load_state_dict(state['model'])
        optimizer.load_state_dict(state['optimizer'])
        scheduler.load_state_dict(state['scheduler'])
        scaler.load_state_dict(state['scaler'])
        start_epoch, best_score, best_epoch = state['epoch'], state['best_score'], state['best_epoch']
        history = state['history']
        successful_updates, skipped_updates = state['successful_updates'], state['skipped_updates']
        started_at = state['started_at']
        random.setstate(state['python_rng'])
        np.random.set_state(state['numpy_rng'])
        torch.set_rng_state(state['torch_rng'])
        torch.cuda.set_rng_state_all(state['cuda_rng'])
        del state
    for epoch in range(start_epoch + 1, epochs + 1):
        model.train()
        torch.cuda.reset_peak_memory_stats()
        start = time.monotonic()
        indices = np.random.permutation(len(train_cache['targets']))
        loss_sum, seen = 0.0, 0
        for step, offset in enumerate(range(0, len(indices), effective_batch), 1):
            window = indices[offset:offset + effective_batch]
            loss, success = update_window(model, optimizer, scheduler, scaler, train_cache,
                                         window, micro_batch, device)
            successful_updates += int(success)
            skipped_updates += int(not success)
            loss_sum += loss * len(window)
            seen += len(window)
            if step == 1 or step % 25 == 0:
                print(f'{run_id} epoch={epoch} update={step}/{math.ceil(len(indices)/effective_batch)} '
                      f'loss={loss_sum/seen:.4f} elapsed={time.monotonic()-start:.1f}s', flush=True)
        torch.cuda.synchronize()
        training = {'seconds': time.monotonic() - start,
                    'peak_allocated_mib': torch.cuda.max_memory_allocated() / 2**20,
                    'peak_reserved_mib': torch.cuda.max_memory_reserved() / 2**20}
        truth, probabilities, validation_resources = predict(model, valid_cache, len(labels), micro_batch, device)
        score = f1_score(truth, probabilities.argmax(1), labels=list(range(len(labels))),
                         average='macro', zero_division=0)
        if score > best_score:
            best_score, best_epoch = float(score), epoch
            atomic_save(directory / 'best.pt', model.state_dict())
        history.append({'epoch': epoch, 'mean_loss': loss_sum / seen,
                        'validation_macro_f1': float(score), 'train': training,
                        'validation': validation_resources})
        atomic_save(state_path, {'config': config, 'epoch': epoch, 'model': model.state_dict(),
                    'optimizer': optimizer.state_dict(), 'scheduler': scheduler.state_dict(),
                    'scaler': scaler.state_dict(), 'best_score': best_score, 'best_epoch': best_epoch,
                    'history': history, 'successful_updates': successful_updates,
                    'skipped_updates': skipped_updates, 'started_at': started_at,
                    'python_rng': random.getstate(), 'numpy_rng': np.random.get_state(),
                    'torch_rng': torch.get_rng_state(), 'cuda_rng': torch.cuda.get_rng_state_all()})
        json_write(directory / 'training_progress.json', {'history': history, 'best_epoch': best_epoch,
                    'best_validation_macro_f1': best_score, 'successful_updates': successful_updates,
                    'skipped_updates': skipped_updates})
        print(f'{run_id} epoch={epoch} validation_macro_f1={score:.6f} best_epoch={best_epoch}', flush=True)
    model.load_state_dict(torch.load(directory / 'best.pt', map_location='cpu', weights_only=True))
    metrics = []
    tests = {}
    prediction_paths = []
    with Dataset(DATA_ROOT) as dataset:
        for condition in caches:
            collection, role = condition.split('/')
            if not role.startswith('test_'):
                continue
            cache = load_cache(caches[condition])
            truth, probabilities, resources = predict(model, cache, len(labels), micro_batch, device)
            predictions = probabilities.argmax(1)
            supported = list(range(len(labels))) if collection == 'A' else sorted(set(truth.tolist()))
            status = 'smoke_test' if smoke else 'complete'
            header = {'run_id': run_id, 'plan_version': PLAN_VERSION,
                      'release_id': dataset.release['release_id'], 'split_id': dataset.release['split_id'],
                      'fold_id': fold, 'method': 'TrafficFormer', 'protocol': protocol, 'view_id': view,
                      'collection': collection, 'test_group': role.removeprefix('test_'), 'train_seed': seed,
                      'n_train': train_cache['metadata']['n_samples'], 'n_test': len(truth),
                      'n_classes_train': len(labels), 'n_classes_test': len(set(truth.tolist())),
                      'status': status}
            for metric, value in [('macro_f1', f1_score(truth, predictions, labels=supported,
                                                       average='macro', zero_division=0)),
                                  ('accuracy', accuracy_score(truth, predictions)),
                                  ('weighted_f1', f1_score(truth, predictions, labels=supported, average='weighted', zero_division=0))]:
                metrics.append({**header, 'metric': metric, 'value': float(value)})
            tests[condition] = {'resources': resources, 'n_samples': len(truth),
                                'macro_f1_class_ids': supported}
            print(f'{run_id} {condition}: n={len(truth)} macro_f1={metrics[-3]["value"]:.6f} '
                  f'accuracy={metrics[-2]["value"]:.6f}', flush=True)
    record = {'method':'TrafficFormer','protocol':protocol,'fold':fold,'view':view,
              'seed':seed,'best_epoch':best_epoch,'config':config,'metrics':metrics}
    json_write(completed,record)
    del optimizer, scheduler, model, train_cache, valid_cache
    torch.cuda.empty_cache()
    return record
