"""Portable loader/exporter for the shared release. Standard library only."""

import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path


def rows(path):
    path = Path(path)
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, mode="rt", newline="", encoding="utf-8-sig") as stream:
        yield from csv.DictReader(stream)


def index_file(root, name):
    """Locate an index in the repository layout or the archive layout."""
    root = Path(root)
    directory = root / 'indices' if (root / 'indices').is_dir() else root
    path = directory / name
    compressed = path.with_name(path.name + '.gz')
    return compressed if not path.exists() and compressed.exists() else path


class Dataset:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.release = json.loads((self.root / 'release.json').read_text())
        self.repository_layout = (self.root / 'indices').is_dir()
        self.labels = {r['endpoint_id']: r for r in rows(index_file(self.root, 'labels.csv'))}
        self.samples = {r['sample_id']: r for r in rows(index_file(self.root, 'samples.csv'))}
        self._handles = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()

    def path(self, relative_path):
        result = (self.root / relative_path).resolve()
        if not result.is_relative_to(self.root):
            raise ValueError('Input path escapes release directory')
        return result

    def selection(self, protocol, fold, collection, role):
        return {row['sample_id']: row for row in rows(index_file(self.root, 'sample_assignments.csv'))
                if row['protocol'] == protocol and int(row['fold_id']) == int(fold)
                and row['collection'] == collection and row['role'] == role}

    def read_flow(self, row, view, verify_hash=False):
        if view not in ('raw', 'instance_controlled'):
            raise ValueError('Traffic view must be raw or instance_controlled')
        name = row[view + '_archive']
        if name not in self._handles:
            self._handles[name] = self.path(name).open('rb')
        stream = self._handles[name]
        stream.seek(int(row[view + '_offset']))
        blob = stream.read(int(row[view + '_bytes']))
        if len(blob) != int(row[view + '_bytes']):
            raise ValueError('Truncated flow member')
        if verify_hash and hashlib.sha256(blob).hexdigest() != row[view + '_sha256']:
            raise ValueError('Flow member hash mismatch')
        return blob

    def iter_flows(self, protocol, fold, collection, role, view):
        selected = self.selection(protocol, fold, collection, role)
        for row in rows(index_file(self.root, 'flows.csv')):
            if row['sample_id'] in selected:
                yield row, self.read_flow(row, view)

    def case_root(self):
        if not self.repository_layout:
            return self.root
        path = (self.root / self.release['response_cases']).resolve()
        if not path.is_relative_to(self.root.parent.parent):
            raise ValueError('Response case path escapes the repository')
        expected = self.release['response_cases_manifest_sha256']
        if hashlib.sha256((path / 'files.sha256.json').read_bytes()).hexdigest() != expected:
            raise ValueError('Response cases do not match the dataset')
        return path

    def case_rows(self):
        return rows(self.case_root() / 'agent_cases.csv')

    def agent_inputs(self, sample_ids, view='response_original'):
        if view not in ('response_original', 'model_evidence_controlled'):
            raise ValueError('Unknown agent evidence view')
        wanted = set(sample_ids)
        if self.repository_layout:
            root = self.case_root()
            name = view + '.jsonl.gz'
            expected = json.loads((root / 'files.sha256.json').read_text())[name]
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
                raise ValueError('Response input file hash mismatch')
            found = set()
            with gzip.open(root / name, 'rt', encoding='utf-8') as stream:
                for line in stream:
                    row = json.loads(line)
                    if row['sample_id'] in wanted:
                        if row['sample_id'] in found:
                            raise ValueError('Duplicate response input')
                        found.add(row['sample_id'])
                        yield row
            if found != wanted:
                raise ValueError('Requested response inputs are not in the released cases')
            return
        key = 'agent_original_path' if view == 'response_original' else 'agent_controlled_path'
        for path in sorted({self.samples[s][key] for s in wanted}):
            with gzip.open(self.path(path), 'rt', encoding='utf-8') as stream:
                for line in stream:
                    row = json.loads(line)
                    if row['sample_id'] in wanted:
                        yield row  # Only row['input'] belongs in a model prompt.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--release', required=True, type=Path)
    parser.add_argument('--protocol', choices=('modbus', 'enip', 's7'), required=True)
    parser.add_argument('--fold', type=int, choices=(1, 2, 3), required=True)
    parser.add_argument('--collection', choices=('A', 'B', 'C'), default='A')
    parser.add_argument('--role', choices=('train', 'validation', 'test_same', 'test_unseen'), required=True)
    parser.add_argument('--view', choices=('raw', 'instance_controlled'), default='raw')
    parser.add_argument('--out', type=Path, help='Export individual connection PCAPs and index.csv; absent = list counts')
    args = parser.parse_args()
    with Dataset(args.release) as dataset:
        selected = dataset.selection(args.protocol, args.fold, args.collection, args.role)
        if not selected:
            raise SystemExit('Requested condition has no assigned observations')
        if args.out:
            output = args.out.resolve()
            if output.is_relative_to(dataset.root):
                raise SystemExit('Export outside the immutable release directory')
            output.mkdir(parents=True, exist_ok=False)
            report = []
            for row, blob in dataset.iter_flows(args.protocol, args.fold, args.collection, args.role, args.view):
                name = row['flow_id'] + '.pcap'
                (output / name).write_bytes(blob)
                sample = dataset.samples[row['sample_id']]
                label = dataset.labels[sample['endpoint_id']]
                report.append({'flow_id': row['flow_id'], 'sample_id': row['sample_id'],
                               'endpoint_id': sample['endpoint_id'], 'model_label': label['model_label'],
                               'pcap_path': name, 'packet_count': row['packet_count']})
            with (output / 'index.csv').open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(report[0]))
                writer.writeheader()
                writer.writerows(report)
            print(json.dumps({'exported_flows': len(report), 'public_samples': len(selected),
                              'output': str(output)}, ensure_ascii=False))
        else:
            print(json.dumps({'release_id': dataset.release['release_id'], 'protocol': args.protocol,
                              'fold': args.fold, 'collection': args.collection, 'role': args.role,
                              'view': args.view, 'public_samples': len(selected)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
