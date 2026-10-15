"""Offline operation-first explicit model-identifier masking (v3).

Consumes the immutable v4 instance_controlled connection PCAPs. No labels,
network access, packet dropping, or heuristic string searches are used.
Operation semantics follow ICSTracker's probe set, decoded after TCP reassembly.
"""
from __future__ import annotations

import io
from collections import Counter, defaultdict, deque

from pcap_views import (SERVER_IP, frames, parse_packet, pcap_bytes, read_pcap,
                        reassembly, relative, u16, u32)

POLICY_ID = 'explicit-model-identifiers-v3'
VIEW = 'identifier_masked'
# key -> (description, identifier operation, role). Keys are not model features.
OPERATIONS = {
    'modbus.fc01': ('Read coils', False, 'probe'),
    'modbus.fc02': ('Read discrete inputs', False, 'probe'),
    'modbus.fc03': ('Read holding registers', False, 'probe'),
    'modbus.fc11': ('Report Server ID (17 decimal); no verified direct product identity decoder', False, 'probe'),
    'modbus.fc2b.mei0e': ('Read Device Identification (43/14 decimal)', True, 'probe'),
    'enip.list_identity': ('ListIdentity (0x0063)', True, 'probe'),
    'enip.list_interfaces': ('ListInterfaces (0x0064)', False, 'probe'),
    'enip.list_services': ('ListServices (0x0004)', False, 'probe'),
    'enip.identity_get_all': ('SendRRData/GetAttributesAll, class 0x01 instance 1', True, 'probe'),
    'enip.class64_get_all': ('SendRRData/GetAttributesAll, vendor class 0x64 instance 1', False, 'probe'),
    'enip.pressure_get_single': ('SendRRData/GetAttributeSingle, symbolic tag Pressure', False, 'probe'),
    'enip.register_session': ('RegisterSession', False, 'setup'),
    'enip.unregister_session': ('UnregisterSession', False, 'setup'),
    's7.szl0011': ('Read SZL 0x0011 index 0: module identification', True, 'probe'),
    's7.szl0012': ('Read SZL 0x0012 index 0: CPU characteristics', False, 'probe'),
    's7.szl0013': ('Read SZL 0x0013 index 0: user memory areas', False, 'probe'),
    's7.szl0014': ('Read SZL 0x0014 index 0: system areas', False, 'probe'),
    's7.szl0424': ('Read SZL 0x0424 index 0: CPU mode/status', False, 'probe'),
    's7.block_info': ('Userdata group 3 subfunction 3: block information', False, 'probe'),
    's7.read_clock': ('Userdata group 7 subfunction 1: read date/time', False, 'probe'),
    's7.read_variables': ('Job function 0x04: read variables', False, 'probe'),
    's7.setup_communication': ('Job function 0xf0: setup communication', False, 'setup'),
    's7.cotp_connect': ('COTP connection request', False, 'setup'),
}
WHITELIST = frozenset(k for k, v in OPERATIONS.items() if v[1])


def cpf(message):
    """Return bounded CPF item (type, start, end) spans, or no items if invalid."""
    if len(message) < 32:
        return []
    result, pos = [], 32
    for _ in range(u16(message, 30, '<')):
        if pos + 4 > len(message):
            return []
        typ, n = u16(message, pos, '<'), u16(message, pos + 2, '<')
        start, end = pos + 4, pos + 4 + n
        if end > len(message):
            return []
        result.append((typ, start, end))
        pos = end
    return result


def cip_operation(cip):
    if len(cip) < 2 or cip[0] & 128 or 2 + cip[1] * 2 > len(cip):
        return 'enip.unknown_cip'
    path = cip[2:2 + cip[1] * 2]
    if cip[0] == 0x0e and path == b'\x4c\x08Pressure':
        return 'enip.pressure_get_single'
    logical, pos = {}, 0
    while pos < len(path):
        segment = path[pos]
        if segment in (0x20, 0x24, 0x30) and pos + 2 <= len(path):
            logical[segment] = path[pos + 1]
            pos += 2
        elif segment in (0x21, 0x25, 0x31) and pos + 4 <= len(path):
            logical[segment & 0xfc] = u16(path, pos + 2, '<')
            pos += 4
        else:
            return 'enip.unknown_cip'
    if cip[0] == 1 and logical.get(0x24) == 1 and set(logical) == {0x20, 0x24}:
        return {1: 'enip.identity_get_all', 0x64: 'enip.class64_get_all'}.get(
            logical[0x20], 'enip.unknown_cip')
    return 'enip.unknown_cip'


def s7_parts(message):
    if len(message) < 7 or message[4] < 2:
        return None
    start = 5 + message[4]
    if message[5] & 0xf0 != 0xf0 or start + 10 > len(message) or message[start] != 0x32:
        return None
    ros = message[start + 1]
    plen, dlen = u16(message, start + 6), u16(message, start + 8)
    param = start + (12 if ros in (2, 3) else 10)
    data = param + plen
    if data + dlen > len(message):
        return None
    return ros, param, plen, data, dlen


class Decoder:
    def __init__(self):
        self.cip_requests = defaultdict(deque)
        self.issues = Counter()
        self.request_operations = set()

    def request(self, protocol, msg):
        operations = self._request(protocol, msg)
        self.request_operations.update(operations)
        return operations

    def selected_operation(self):
        """The current benchmark has at most one probe operation per flow.

        Setup does not affect selection. Unknown or mixed probes are retained
        unchanged, never selected by examining their response contents.
        """
        probes = {op for op in self.request_operations
                  if OPERATIONS.get(op, ('', False, 'unknown'))[2] != 'setup'}
        if len(probes) == 1:
            op = next(iter(probes))
            return op if op in WHITELIST else None
        return None

    def _request(self, protocol, msg):
        if protocol == 'modbus':
            if msg[7] == 0x2b:
                return ['modbus.fc2b.mei0e' if len(msg) >= 9 and msg[8] == 14
                        else 'modbus.unknown_mei']
            return [f'modbus.fc{msg[7]:02x}']
        if protocol == 'enip':
            cmd = u16(msg, 0, '<')
            known = {4: 'list_services', 0x63: 'list_identity', 0x64: 'list_interfaces',
                     0x65: 'register_session', 0x66: 'unregister_session'}
            if cmd in known:
                return ['enip.' + known[cmd]]
            ops = []
            if cmd == 0x6f:
                for typ, start, end in cpf(msg):
                    if typ != 0xb2 or end - start < 2:
                        continue
                    cip = msg[start:end]
                    op = cip_operation(cip)
                    self.cip_requests[(msg[4:8], msg[12:20], cip[0] & 127)].append(op)
                    ops.append(op)
            return ops or [f'enip.unknown_command_{cmd:04x}']
        if len(msg) >= 7 and msg[5] & 0xf0 == 0xe0:
            return ['s7.cotp_connect']
        parts = s7_parts(msg)
        if not parts:
            return ['s7.unknown']
        ros, p, plen, d, dlen = parts
        if ros == 1 and plen:
            return [{4: 's7.read_variables', 0xf0: 's7.setup_communication'}.get(msg[p], 's7.unknown_job')]
        if ros == 7 and plen >= 8:
            group, sub = msg[p + 5] & 15, msg[p + 6]
            if group == 4 and sub == 1 and dlen >= 8:
                szl, index = u16(msg, d + 4), u16(msg, d + 6)
                return [f's7.szl{szl:04x}' if index == 0 else f's7.szl{szl:04x}.index{index:04x}']
            return [{(3, 3): 's7.block_info', (7, 1): 's7.read_clock'}.get((group, sub), 's7.unknown_userdata')]
        return ['s7.unknown']

    def response(self, protocol, msg):
        """Locate fields only after the request operation has been selected.

        No response-based discovery or override of the operation whitelist.
        Each edit is (start, replacement bytes, field name).
        """
        edits, op, status = [], None, 'other'
        selected = self.selected_operation()
        if selected is None:
            return None, 'operation_not_selected', edits

        def mask(pos, n, field, numeric=False):
            if n:
                edits.append((pos, (b'\0' if numeric else b'X') * n, field))

        def identity(body, end):
            if body + 15 > end or body + 15 + msg[body + 14] > end:
                self.issues['malformed_cip_identity'] += 1
                return
            mask(body + 4, 2, 'enip.product_code', True)
            mask(body + 15, msg[body + 14], 'enip.product_name')

        if protocol == 'modbus':
            fc = msg[7]
            op = ('modbus.fc2b.mei0e' if fc & 127 == 0x2b else f'modbus.fc{fc & 127:02x}')
            if fc & 128:
                return op, 'exception', edits
            status = 'normal'
            # FC 0x11 remains untouched: the operation name and opaque
            # device-specific bytes do not establish a direct product identity.
            if selected == 'modbus.fc2b.mei0e' and fc == 0x2b and len(msg) >= 14 and msg[8] == 14:
                pos = 14
                for _ in range(msg[13]):
                    if pos + 2 > len(msg) or pos + 2 + msg[pos + 1] > len(msg):
                        self.issues['malformed_modbus_identity_object'] += 1
                        break
                    obj, n = msg[pos], msg[pos + 1]
                    if obj in (1, 4, 5):
                        mask(pos + 2, n, {1: 'modbus.product_code', 4: 'modbus.product_name', 5: 'modbus.model_name'}[obj])
                    pos += 2 + n
            elif fc == 0x2b:
                op = 'modbus.unknown_mei'
        elif protocol == 'enip':
            cmd = u16(msg, 0, '<')
            if cmd == 0x63 and selected == 'enip.list_identity':
                op = 'enip.list_identity'
                status = 'normal' if u32(msg, 8, '<') == 0 else 'exception'
                if status != 'normal' or len(msg) < 26:
                    return op, status, edits
                pos = 26
                for _ in range(u16(msg, 24, '<')):
                    if pos + 4 > len(msg):
                        self.issues['malformed_list_identity'] += 1
                        break
                    typ, n = u16(msg, pos, '<'), u16(msg, pos + 2, '<')
                    body, end = pos + 4, pos + 4 + n
                    if end > len(msg):
                        self.issues['malformed_list_identity'] += 1
                        break
                    if typ == 0x0c and n >= 33:
                        # ListIdentity prefixes the CIP fields with 18 bytes.
                        identity(body + 18, end)
                    pos = end
            elif cmd == 0x6f and selected == 'enip.identity_get_all':
                for typ, body, end in cpf(msg):
                    if typ != 0xb2 or end - body < 4 or not msg[body] & 128:
                        continue
                    key = (msg[4:8], msg[12:20], msg[body] & 127)
                    queue = self.cip_requests[key]
                    op = queue.popleft() if queue else 'enip.unmatched_cip_response'
                    status = 'normal' if msg[body + 2] == 0 and u32(msg, 8, '<') == 0 else 'exception'
                    if op == 'enip.identity_get_all' and status == 'normal':
                        identity(body + 4 + msg[body + 3] * 2, end)
        else:
            parts = s7_parts(msg)
            if parts:
                ros, p, plen, d, dlen = parts
                if ros == 7 and plen >= 8 and (msg[p + 5] & 15) == 4 and msg[p + 6] == 1:
                    if dlen >= 8:
                        op = f's7.szl{u16(msg, d + 4):04x}'
                    status = 'normal' if dlen >= 4 and msg[d] == 0xff else 'exception'
                    if selected == 's7.szl0011' and op == selected and status == 'normal' and dlen >= 12 and msg[d + 1] == 9:
                        size, count = u16(msg, d + 8), u16(msg, d + 10)
                        if size >= 28 and d + 12 + size * count <= d + dlen:
                            for i in range(count):
                                entry = d + 12 + i * size
                                # SZL 0x0011 identification record layout, including
                                # module, basic hardware and firmware records.
                                mask(entry + 2, 20, 's7.order_number')
                                mask(entry + 22, 2, 's7.module_type_id', True)
                        else:
                            self.issues['malformed_s7_module_entries'] += 1
        return op, status, edits


def process_flow(blob, protocol):
    """Return transformed PCAP, semantic metadata, and exact changed-byte spans.

    Spans use packet ordinal and frame-byte offset, suitable for independent
    checks. TCP retransmissions receive the same canonical field replacements.
    """
    packets = [parse_packet(*x) for x in read_pcap(io.BytesIO(blob))]
    if any(p is None for p in packets):
        raise ValueError('Expected v4 IPv4/TCP flow')
    for p in packets:
        p.server = p.data[p.ip + 12:p.ip + 16] == SERVER_IP
    dec, bases = Decoder(), {}
    operations, responses, fields = Counter(), Counter(), Counter()
    edits = {}
    for server in (False, True):
        if server and dec.selected_operation() is None:
            # Operation-first: do not inspect nonselected response payloads
            # looking for identifiers, even if they contain a recognizable SZL.
            continue
        direction = [p for p in packets if p.server == server]
        bases[server] = direction[0].seq if direction else 0
        chunks, conflicts = reassembly(packets, bases[server], server)
        dec.issues['tcp_overlap_conflicting_bytes'] += conflicts
        for start, chunk in chunks:
            used = 0
            for off, msg in frames(protocol, chunk):
                used += len(msg)
                if not server:
                    operations.update(dec.request(protocol, msg))
                else:
                    op, status, replacements = dec.response(protocol, msg)
                    if op:
                        responses[(op, status)] += 1
                    if replacements:
                        responses[(op, 'masked')] += 1
                    for pos, val, name in replacements:
                        fields[name] += 1
                        edits.update((start + off + pos + i, byte) for i, byte in enumerate(val))
            dec.issues['unframed_application_bytes'] += len(chunk) - used
    out, audit, changed_packets, changed_bytes = [], [], 0, 0
    for p in packets:
        data = bytearray(p.data)
        if p.server and edits:
            offset = relative(p.seq + bool(p.flags & 2), bases[True])
            if offset >= 2**31:
                offset -= 2**32
            positions = []
            for i in range(len(p.payload)):
                val = edits.get(offset + i)
                if val is not None:
                    pos = p.payload_start + i
                    if data[pos] != val:
                        positions.append(pos)
                    data[pos] = val
            if positions:
                changed_packets += 1
                changed_bytes += len(positions)
                # Encode changed ranges, not original or identifying values.
                ranges, begin, prior = [], positions[0], positions[0]
                for pos in positions[1:]:
                    if pos != prior + 1:
                        ranges.append([begin, prior + 1])
                        begin = pos
                    prior = pos
                ranges.append([begin, prior + 1])
                audit.append([p.ordinal, ranges])
        out.append(bytes(data))
    result = pcap_bytes(packets, out)
    assert len(result) == len(blob)
    return result, {'operations': operations, 'responses': responses, 'fields': fields,
                    'issues': dec.issues, 'changed_packets': changed_packets,
                    'changed_bytes': changed_bytes, 'packet_count': len(packets)}, audit
