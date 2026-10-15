"""Frozen manifests -> official bigrams/tokenizer, with training-only RIFA.

Each connection remains separate. Metadata is never passed into the classifier.
"""
import argparse
import copy
import hashlib
import io
import json
import multiprocessing as mp
import random
import struct
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

from common import (ADAPTER_VERSION, ADDON_ROOT, AUTHOR_ROOT, DATA_ROOT, RUN_ROOT, Dataset,
                    class_labels, digest, input_binding, json_write, operations_for, rows)
from pcap_views import (Flow, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORTS, control_flow, parse_packet, read_pcap,
                        tcp_options, u16, u32)


def worker_init():
    global _dataset, _author, _tokenizer
    sys.path.insert(1, str(AUTHOR_ROOT / 'data_generation'))
    import finetuning_data_gen
    from uer.utils.tokenizers import BertTokenizer
    from argparse import Namespace
    _author = finetuning_data_gen
    _dataset = Dataset(DATA_ROOT)
    _tokenizer = BertTokenizer(Namespace(vocab_path=str(AUTHOR_ROOT / 'models' / 'encryptd_vocab.txt'),
                                         spm_model_path=None))


def encode_packets(packets):
    # Same byte range and bigram function as the README: start_index 28 hex chars,
    # 64 bytes per packet, first five packets, followed by 320-token truncation.
    text = ''.join('[SEP] ' + _author.bigram_generation(bytes(p).hex()[28:156],
                   token_len=len(bytes(p).hex()[28:156])) for p in packets[:5])
    ids = _tokenizer.convert_tokens_to_ids(['[CLS]'] + _tokenizer.tokenize(text))[:320]
    return np.asarray(ids + [0] * (320 - len(ids)), dtype=np.uint16)


def rifa_fields(packets, consistent_controlled=False):
    """Apply author enhance_based_tsv field draws to full packets before encoding."""
    packets = copy.deepcopy(packets)
    first = packets[0]
    src = first['IP'].src
    reverse = next((p for p in packets if p['IP'].src != src), None)
    rsrc, rdst = _author.random_field(32), _author.random_field(32)
    rsrcid, rdstid = _author.random_field(16), _author.random_field(16)
    rsrcp, rdstp = _author.random_field(16), _author.random_field(16)
    rsrcseq, rdstseq = _author.random_field(32), _author.random_field(32)
    srcid = first['IP'].id
    dstid = reverse['IP'].id if reverse is not None else 0
    srcseq = first['TCP'].seq
    dstseq = reverse['TCP'].seq if reverse is not None else first['TCP'].ack
    result = []
    for packet in packets:
        forward = packet['IP'].src == src
        blob = bytearray(bytes(packet))
        p = parse_packet(0, 0, len(blob), bytes(blob))
        if p is None:
            raise ValueError('RIFA requires the verified IPv4/TCP input')
        struct.pack_into('!II', blob, p.ip + 12,
                         rsrc if forward else rdst, rdst if forward else rsrc)
        struct.pack_into('!HH', blob, p.tcp,
                         rsrcp if forward else rdstp, rdstp if forward else rsrcp)
        baseid, new_id = (srcid, rsrcid) if forward else (dstid, rdstid)
        if baseid:
            struct.pack_into('!H', blob, p.ip + 4, (u16(blob, p.ip + 4) - baseid + new_id) % 2**16)
        baseseq, new_seq = (srcseq, rsrcseq) if forward else (dstseq, rdstseq)
        if forward or dstseq:
            struct.pack_into('!I', blob, p.tcp + 4, (p.seq - baseseq + new_seq) % 2**32)
        otherbase, othernew = (dstseq, rdstseq) if forward else (srcseq, rsrcseq)
        if p.ack and (not forward or dstseq):
            struct.pack_into('!I', blob, p.tcp + 8, (p.ack - otherbase + othernew) % 2**32)
        if consistent_controlled:
            # Author RIFA does not shift SACK alongside sequence numbers and
            # skips zero ACKs. The controlled view requires these relations to
            # remain coherent so coordinator normalization can restore them.
            opposite_delta = ((rdstseq - dstseq) if dstseq else 0) if forward else (rsrcseq - srcseq)
            if p.flags & 16:
                struct.pack_into('!I', blob, p.tcp + 8, (p.ack + opposite_delta) % 2**32)
            for kind, position, length in tcp_options(p):
                if kind == 5 and length >= 10 and (length - 2) % 8 == 0:
                    for edge in range(position + 2, position + length, 4):
                        struct.pack_into('!I', blob, edge, (u32(p.data, edge) + opposite_delta) % 2**32)
        result.append(bytes(blob))
    return result


def restore_controls(blobs, original, protocol):
    flow = Flow('sidecar_only', 1)
    for blob, ref in zip(blobs, original):
        packet = parse_packet(ref.ordinal, ref.time_ns, ref.wirelen, blob)
        if packet is None:
            raise ValueError('RIFA serialization is not parseable')
        packet.server = ref.server
        flow.packets.append(packet)
    transformed, _, _ = control_flow(flow, protocol)
    for blob in transformed:
        packet = parse_packet(0, 0, len(blob), blob)
        assert blob[packet.ip + 10:packet.ip + 12] == b'\0\0'
        assert blob[packet.tcp + 16:packet.tcp + 18] == b'\0\0'
    return transformed


def prepare_one(task):
    import scapy.all as scapy
    row, view, train, seed = task
    operations_for(_dataset, row)
    sample = _dataset.samples[row['sample_id']]
    label = _dataset.labels[sample['endpoint_id']]
    blob = _dataset.read_flow(row, view, verify_hash=True)
    records = list(read_pcap(io.BytesIO(blob)))
    originals = [parse_packet(*record) for record in records]
    if any(p is None for p in originals) or not originals:
        raise ValueError(f'Invalid flow {row["flow_id"]}')
    for p in originals:
        if view in ('instance_controlled', 'identifier_masked'):
            p.server = p.data[p.ip + 12:p.ip + 16] == SERVER_IP
            addresses = (p.data[p.ip + 12:p.ip + 16], p.data[p.ip + 16:p.ip + 20])
            expected_addresses = (SERVER_IP, CLIENT_IP) if p.server else (CLIENT_IP, SERVER_IP)
            expected_ports = ((SERVER_PORTS[row['protocol']], CLIENT_PORT) if p.server
                              else (CLIENT_PORT, SERVER_PORTS[row['protocol']]))
            if addresses != expected_addresses or (u16(p.data, p.tcp), u16(p.data, p.tcp + 2)) != expected_ports:
                raise ValueError(f'Invalid controlled direction/address/ports: {row["flow_id"]}')
            if u16(p.data, p.ip + 10) or u16(p.data, p.tcp + 16):
                raise ValueError(f'Controlled input restored a nonzero checksum: {row["flow_id"]}')
        else:
            import ipaddress
            p.server = (p.data[p.ip + 12:p.ip + 16] == ipaddress.IPv4Address(label['anonymized_ip']).packed
                        and u16(p.data, p.tcp) == int(label['port']))
    if not train:
        # Test/validation use unchanged bytes of the requested release view.
        features = [encode_packets([p.data for p in originals])]
    else:
        flow_seed = int(hashlib.sha256(f'{seed}:{row["flow_id"]}'.encode()).hexdigest()[:16], 16)
        random.seed(flow_seed)
        packets = scapy.rdpcap(io.BytesIO(blob))
        packets = _author.random_ip_port(packets)
        # The author's timestamp code can overflow uint32 and fail for zero echoes.
        # Preserve relative timestamps, wrap modulo 2**32, and initialize both bases.
        packets = random_timestamps(packets)
        packets = _author.random_tls_randomtime(packets)
        features = []
        for _ in range(5):
            augmented = rifa_fields(packets, consistent_controlled=view in ('instance_controlled', 'identifier_masked'))
            if view in ('instance_controlled', 'identifier_masked'):
                augmented = restore_controls(augmented, originals, row['protocol'])
                # Existing coordinator controls must remain identical after identity RIFA.
                if augmented != [p.data for p in originals]:
                    raise ValueError(f'Controlled RIFA changed canonical input: {row["flow_id"]}')
            features.append(encode_packets(augmented))
    return row['flow_id'], row['sample_id'], np.stack(features), len(originals) < 3


def random_timestamps(packets):
    bases = {}
    first_src = packets[0]['IP'].src
    for p in packets:
        forward = p['IP'].src == first_src
        for name, value in p['TCP'].options:
            if name == 'Timestamp':
                bases.setdefault(forward, value[0])
                if value[1]:
                    bases.setdefault(not forward, value[1])
    random_base = {True: _author.random_field(32), False: _author.random_field(32)}
    for p in packets:
        forward = p['IP'].src == first_src
        p['TCP'].options = [(name, ((random_base[forward] + value[0] - bases.get(forward, 0)) % 2**32,
                              (random_base[not forward] + value[1] - bases.get(not forward, 0)) % 2**32
                              if value[1] else 0)) if name == 'Timestamp' else (name, value)
                             for name, value in p['TCP'].options]
    return packets


def prepare(protocol, fold, view, collection, role, workers=8, limit_samples=None):
    label_names = class_labels(protocol)
    with Dataset(DATA_ROOT) as dataset:
        selected = dataset.selection(protocol, fold, collection, role)
        if limit_samples:
            # Explicit smoke subset: stable, class-balanced, and never a formal result.
            by_class = {}
            for sample_id in sorted(selected):
                name = dataset.labels[selected[sample_id]['endpoint_id']]['model_label']
                by_class.setdefault(name, []).append(sample_id)
            ids = [s for name in sorted(by_class) for s in by_class[name][:limit_samples]]
            selected = {s: selected[s] for s in ids}
        train = role == 'train'
        seed = 41 + fold
        cache_name = f'{protocol}-f{fold}-{view}-{collection}-{role}'
        if limit_samples:
            cache_name += f'-smoke{limit_samples}'
        output = RUN_ROOT / 'cache' / cache_name
        expected = {'adapter_version': ADAPTER_VERSION, 'protocol': protocol, 'fold_id': fold,
                    'view_id': view, 'collection': collection, 'role': role, 'seed': seed,
                    'release_manifest_sha256': digest(DATA_ROOT / 'files.sha256.json'),
                    'sample_ids_sha256': hashlib.sha256('\n'.join(sorted(selected)).encode()).hexdigest(),
                    'limit_samples_per_class': limit_samples,
                    'vocab_sha256': digest(AUTHOR_ROOT / 'models' / 'encryptd_vocab.txt')}
        expected.update(input_binding())
        if (output / 'metadata.json').exists():
            previous = json.loads((output / 'metadata.json').read_text())
            if previous['config'] != expected:
                raise ValueError(f'Cache mismatch: {output}')
            return output
        if output.exists():
            raise ValueError(f'Incomplete cache requires inspection: {output}')
        pending = output.with_name(output.name + '.partial')
        pending.mkdir(parents=True, exist_ok=True)
        flows = [row for row in rows(ADDON_ROOT / 'flows.csv') if row['sample_id'] in selected]
        flows.sort(key=lambda row: (row[view + '_archive'], int(row[view + '_offset'])))
        repeats = 5 if train else 1
        nrows = len(flows) * repeats
        tokens = np.lib.format.open_memmap(pending / 'tokens.npy', mode='w+', dtype=np.uint16, shape=(nrows, 320))
        targets = np.zeros(nrows, dtype=np.int64)
        sample_ids = sorted(selected)
        sample_index = {s: i for i, s in enumerate(sample_ids)}
        sample_indices = np.zeros(nrows, dtype=np.int64)
        flow_ids = []
        operation_hash = hashlib.sha256()
        with (pending / 'flow_operations.jsonl').open('w') as audit:
            for row in flows:
                entry = {'flow_id': row['flow_id'], 'sample_id': row['sample_id'],
                         **operations_for(dataset, row)}
                line = json.dumps(entry, sort_keys=True, separators=(',', ':')) + '\n'
                audit.write(line)
                operation_hash.update(line.encode())
        t0 = time.monotonic()
        short_count, covered = 0, set()
        ctx = mp.get_context('spawn')
        with ctx.Pool(workers, initializer=worker_init) as pool:
            tasks = ((row, view, train, seed) for row in flows)
            for index, (fid, sid, features, short) in enumerate(pool.imap(prepare_one, tasks, chunksize=32)):
                start = index * repeats
                tokens[start:start + repeats] = features
                targets[start:start + repeats] = label_names.index(dataset.labels[selected[sid]['endpoint_id']]['model_label'])
                sample_indices[start:start + repeats] = sample_index[sid]
                flow_ids.extend([fid] * repeats)
                covered.add(sid)
                short_count += short
                if (index + 1) % 2000 == 0:
                    print(f'{cache_name}: {index+1}/{len(flows)} flows, {time.monotonic()-t0:.1f}s', flush=True)
        assert covered == set(selected), 'Missing public samples in model inputs'
        tokens.flush()
        del tokens
        np.save(pending / 'targets.npy', targets)
        np.save(pending / 'sample_indices.npy', sample_indices)
        json_write(pending / 'sample_ids.json', sample_ids)
        (pending / 'flow_ids.txt').write_text('\n'.join(flow_ids) + '\n')
        json_write(pending / 'metadata.json', {'config': expected, 'n_samples': len(selected),
                   'n_flows': len(flows), 'n_internal_rows': nrows, 'short_flows_retained': short_count,
                   'preprocess_seconds': time.monotonic() - t0, 'class_labels': label_names,
                   'operation_sidecar_sha256': operation_hash.hexdigest(),
                   'feature_hashes': {name: digest(pending / name) for name in
                                      ('tokens.npy', 'targets.npy', 'sample_indices.npy',
                                       'sample_ids.json', 'flow_ids.txt')},
                   'cache_bytes': sum(p.stat().st_size for p in pending.iterdir())})
        pending.rename(output)
        print(f'Prepared {output.name}: {len(selected)} public samples, {len(flows)} flows', flush=True)
        return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--protocol', required=True, choices=['modbus', 'enip', 's7'])
    parser.add_argument('--fold', type=int, choices=[1, 2, 3], required=True)
    parser.add_argument('--view', choices=['raw', 'instance_controlled', 'identifier_masked'], required=True)
    parser.add_argument('--collection', choices=['A', 'B', 'C'], default='A')
    parser.add_argument('--role', choices=['train', 'validation', 'test_same', 'test_unseen'], required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--limit-samples-per-class', type=int)
    args = parser.parse_args()
    prepare(args.protocol, args.fold, args.view, args.collection, args.role,
            args.workers, args.limit_samples_per_class)
