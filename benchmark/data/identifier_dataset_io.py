"""Three-view loader: immutable base v4 + separately verified identifier addon."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

from dataset_io import Dataset, rows
from identifier_policy import VIEW


class IdentifierDataset(Dataset):
    def __init__(self, base, addon):
        super().__init__(base)
        self.addon = Path(addon).resolve()
        self.addon_release = json.loads((self.addon / 'release.json').read_text())
        expected = self.addon_release['base_manifest_sha256']
        actual = hashlib.sha256((self.root / 'files.sha256.json').read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError('Addon does not match the base release')
        self.operations = {r['flow_id']: r for r in rows(self.addon / 'flow_operations.csv')}

    def read_flow(self, row, view, verify_hash=False):
        if view != VIEW:
            return super().read_flow(row, view, verify_hash)
        name = row[view + '_archive']
        path = (self.addon / name).resolve()
        if not path.is_relative_to(self.addon):
            raise ValueError('Invalid addon member path')
        key = ('addon', name)
        if key not in self._handles:
            self._handles[key] = path.open('rb')
        stream = self._handles[key]
        stream.seek(int(row[view + '_offset']))
        blob = stream.read(int(row[view + '_bytes']))
        if len(blob) != int(row[view + '_bytes']):
            raise ValueError('Truncated addon member')
        if verify_hash and hashlib.sha256(blob).hexdigest() != row[view + '_sha256']:
            raise ValueError('Addon member hash mismatch')
        return blob

    def iter_flows(self, protocol, fold, collection, role, view):
        selected = self.selection(protocol, fold, collection, role)
        for row in rows(self.addon / 'flows.csv'):
            if row['sample_id'] in selected:
                yield row, self.read_flow(row, view)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--base', required=True)
    p.add_argument('--addon', required=True)
    p.add_argument('--protocol', choices=('modbus', 'enip', 's7'), required=True)
    p.add_argument('--fold', type=int, choices=(1, 2, 3), required=True)
    p.add_argument('--collection', choices=('A', 'B', 'C'), default='A')
    p.add_argument('--role', choices=('train', 'validation', 'test_same', 'test_unseen'), required=True)
    p.add_argument('--view', choices=('raw', 'instance_controlled', VIEW), default=VIEW)
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    with IdentifierDataset(args.base, args.addon) as ds:
        if not args.out:
            print(json.dumps({'samples': len(ds.selection(args.protocol, args.fold, args.collection, args.role)), 'view': args.view}))
            return
        out = args.out.resolve()
        if out.is_relative_to(ds.root) or out.is_relative_to(ds.addon):
            raise SystemExit('Export outside both release directories')
        out.mkdir(parents=True, exist_ok=False)
        with (out / 'index.csv').open('w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['flow_id', 'sample_id', 'model_label', 'pcap_path', 'probe_operations'])
            w.writeheader()
            for row, blob in ds.iter_flows(args.protocol, args.fold, args.collection, args.role, args.view):
                name = row['flow_id'] + '.pcap'
                (out / name).write_bytes(blob)
                label = ds.labels[ds.samples[row['sample_id']]['endpoint_id']]['model_label']
                w.writerow({'flow_id': row['flow_id'], 'sample_id': row['sample_id'], 'model_label': label,
                            'pcap_path': name, 'probe_operations': ds.operations[row['flow_id']]['probe_operations']})


if __name__ == '__main__':
    main()
