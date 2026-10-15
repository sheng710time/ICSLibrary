"""Offline, length-preserving ICS instance controls. Standard library only.

PCAPs are parsed before any address rewriting. Connections stay separate and
retain a sidecar sample/flow mapping. No network sockets are used by this module.
"""

from __future__ import annotations

import copy
import io
import ipaddress
import struct
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

VIEW_VERSION = "instance-controls-v1-20260930"
SERVER_IP = ipaddress.IPv4Address("192.0.2.2").packed
CLIENT_IP = ipaddress.IPv4Address("192.0.2.1").packed
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_MAC = bytes.fromhex("020000000001")
CLIENT_PORT = 40000
SERVER_PORTS = {"modbus": 502, "enip": 44818, "s7": 102}
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 1)


def u16(data, pos=0, endian=">"):
    return struct.unpack_from(endian + "H", data, pos)[0]


def u32(data, pos=0, endian=">"):
    return struct.unpack_from(endian + "I", data, pos)[0]


def relative(value, base, bits=32):
    return (value - base) % (1 << bits)


@dataclass
class Packet:
    ordinal: int
    time_ns: int
    wirelen: int
    data: bytes
    ip: int
    tcp: int
    payload_start: int
    payload_end: int
    server: bool = False

    @property
    def seq(self):
        return u32(self.data, self.tcp + 4)

    @property
    def ack(self):
        return u32(self.data, self.tcp + 8)

    @property
    def flags(self):
        return self.data[self.tcp + 13]

    @property
    def payload(self):
        return self.data[self.payload_start:self.payload_end]


def read_pcap(source):
    """Yield (ordinal, integer nanoseconds, original wire length, raw bytes)."""
    close = isinstance(source, (str, Path))
    handle = Path(source).open("rb") if close else source
    try:
        header = handle.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000),
                   b"\xa1\xb2\xc3\xd4": (">", 1000),
                   b"\x4d\x3c\xb2\xa1": ("<", 1),
                   b"\xa1\xb2\x3c\x4d": (">", 1)}
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Expected classic PCAP")
        endian, multiplier = formats[header[:4]]
        if u32(header, 20, endian) & 0xFFFF != 1:
            raise ValueError("Expected Ethernet link type")
        ordinal = 0
        while chunk := handle.read(16):
            if len(chunk) != 16:
                raise ValueError("Truncated PCAP record header")
            sec, frac, caplen, wirelen = struct.unpack(endian + "IIII", chunk)
            data = handle.read(caplen)
            if len(data) != caplen:
                raise ValueError("Truncated PCAP record data")
            ordinal += 1
            yield ordinal, sec * 10**9 + frac * multiplier, wirelen, data
    finally:
        if close:
            handle.close()


def parse_packet(ordinal, time_ns, wirelen, data):
    if len(data) < 14:
        return None
    typ, ip = u16(data, 12), 14
    while typ in (0x8100, 0x88A8):
        if ip + 4 > len(data):
            return None
        typ, ip = u16(data, ip + 2), ip + 4
    if typ != 0x0800 or ip + 20 > len(data) or data[ip] >> 4 != 4:
        return None
    ihl, total = (data[ip] & 15) * 4, u16(data, ip + 2)
    tcp = ip + ihl
    if (ihl < 20 or total < ihl + 20 or data[ip + 9] != 6
            or tcp + 20 > len(data) or u16(data, ip + 6) & 0x3FFF):
        return None
    thl = (data[tcp + 12] >> 4) * 4
    if thl < 20 or tcp + thl > len(data) or tcp + thl > ip + total:
        return None
    return Packet(ordinal, time_ns, wirelen, data, ip, tcp,
                  tcp + thl, min(ip + total, len(data)))


@dataclass
class Flow:
    endpoint_id: str
    index: int
    packets: list[Packet] = field(default_factory=list)
    syn_seq: int | None = None


def extract_flows(path, lookup, allowed):
    """Group original 4-tuples before rewriting; handle new SYN incarnations."""
    flows, active, per_endpoint = [], {}, Counter()
    counts = Counter()
    for ordinal, stamp, wirelen, data in read_pcap(path):
        counts["source_packets"] += 1
        p = parse_packet(ordinal, stamp, wirelen, data)
        if p is None:
            counts["outside_ipv4_tcp_parser"] += 1
            continue
        sport, dport = u16(data, p.tcp), u16(data, p.tcp + 2)
        source, dest = data[p.ip + 12:p.ip + 16], data[p.ip + 16:p.ip + 20]
        server_id, client_id = lookup.get((source, sport)), lookup.get((dest, dport))
        if server_id and client_id and server_id != client_id:
            raise ValueError("Ambiguous labeled server at both ends")
        endpoint = server_id or client_id
        if endpoint not in allowed:
            continue
        p.server = bool(server_id)
        client = (dest, dport) if p.server else (source, sport)
        key = (endpoint, *client)
        flow = active.get(key)
        syn = not p.server and (p.flags & 0x12) == 0x02
        if flow is None or (syn and flow.syn_seq is not None and p.seq != flow.syn_seq):
            per_endpoint[endpoint] += 1
            flow = Flow(endpoint, per_endpoint[endpoint])
            flows.append(flow)
            active[key] = flow
        if syn:
            flow.syn_seq = p.seq
        flow.packets.append(p)
        counts["selected_packets"] += 1
    return flows, counts


def pcap_bytes(packets, transformed=None, time_origin=0):
    out = io.BytesIO()
    out.write(PCAP_HEADER)
    for i, p in enumerate(packets):
        stamp = p.time_ns - time_origin
        if stamp < 0:
            raise ValueError("Negative relative packet time")
        data = p.data if transformed is None else transformed[i]
        out.write(struct.pack("<IIII", stamp // 10**9, stamp % 10**9, len(data), p.wirelen))
        out.write(data)
    return out.getvalue()


class IdentifierMap:
    def __init__(self):
        self.values = defaultdict(dict)
        self.cip_requests = defaultdict(deque)

    def mapped(self, namespace, value, preserve_zero=True):
        if preserve_zero and value == 0:
            return 0
        mapping = self.values[namespace]
        if value not in mapping:
            mapping[value] = len(mapping) + 1
        return mapping[value]


def frames(protocol, data):
    """Parse framed messages at a contiguous TCP-run boundary, never guess bytes."""
    offset = 0
    while offset < len(data):
        remaining = len(data) - offset
        if protocol == "modbus":
            if remaining < 7 or u16(data, offset + 2) != 0:
                break
            size = 6 + u16(data, offset + 4)
            if size < 8 or size > 65541:
                break
        elif protocol == "enip":
            if remaining < 24 or u16(data, offset, "<") not in {0, 4, 0x63, 0x64, 0x65, 0x66, 0x6F, 0x70, 0x72, 0x73}:
                break
            size = 24 + u16(data, offset + 2, "<")
        else:
            if remaining < 4 or data[offset:offset + 2] != b"\x03\x00":
                break
            size = u16(data, offset + 2)
            if size < 7:
                break
        if size > remaining:
            break
        yield offset, data[offset:offset + size]
        offset += size


def text_value(raw):
    return raw.rstrip(b"\x00 ").decode("utf-8", errors="replace")


def transform_message(protocol, message, server, ids, edits_out=None):
    """Return same-length bytes, changed-field counts, and decoded server evidence.

    Evidence is protocol-decoded, never synthesized from endpoint labels. The
    third item is a structured response record, or None for client requests.
    """
    out, counts = bytearray(message), Counter()
    evidence = None

    def replace(pos, value, name):
        if pos < 0 or pos + len(value) > len(out):
            raise ValueError(f"Out-of-range {protocol} field {name}")
        counts["covered:" + name] += 1
        if out[pos:pos + len(value)] != value:
            counts["changed:" + name] += 1
        out[pos:pos + len(value)] = value
        if edits_out is not None:
            edits_out.update((pos + i, byte) for i, byte in enumerate(value))

    def remap(pos, size, name, endian="big", preserve_zero=True):
        old = int.from_bytes(out[pos:pos + size], endian)
        value = ids.mapped(name, old, preserve_zero)
        replace(pos, value.to_bytes(size, endian), name)

    if protocol == "modbus":
        remap(0, 2, "modbus.transaction", preserve_zero=False)
        remap(6, 1, "modbus.unit", preserve_zero=True)
        function = message[7]
        if server:
            evidence = {"kind": "modbus_response", "function_code": function,
                        "response_length": len(message) - 7}
            if function & 0x80 and len(message) >= 9:
                evidence["exception_code"] = message[8]
        if server and function == 0x2B and len(message) >= 14 and message[8] == 0x0E:
            objects, pos = [], 14
            for _ in range(message[13]):
                if pos + 2 > len(message):
                    counts["malformed:modbus_identity_objects"] += 1
                    break
                obj, length = message[pos:pos + 2]
                if pos + 2 + length > len(message):
                    counts["malformed:modbus_identity_objects"] += 1
                    break
                if obj == 6:  # UserApplicationName is instance-assigned, not model.
                    replace(pos + 2, b"X" * length, "modbus.user_application_name")
                names = {0: "vendor_name", 1: "product_code", 2: "revision",
                         3: "vendor_url", 4: "product_name", 5: "model_name",
                         6: "user_application_name"}
                objects.append({"object_id": obj, "field": names.get(obj, "other_object"),
                                "value": text_value(out[pos + 2:pos + 2 + length])})
                pos += 2 + length
            evidence.update(kind="modbus_device_identification", objects=objects)

    elif protocol == "enip":
        remap(4, 4, "enip.session", "little")
        remap(12, 8, "enip.sender_context", "little")
        command = u16(message, 0, "<")
        counts[f"enip_command:0x{command:04x}"] += 1
        if server:
            evidence = {"kind": "enip_response", "command": command,
                        "status": u32(message, 8, "<"), "response_length": len(message) - 24}
        if command == 0x63 and len(message) >= 26:
            pos, identities = 26, []
            for _ in range(u16(message, 24, "<")):
                if pos + 4 > len(message):
                    counts["malformed:enip_identity_item"] += 1
                    break
                typ, length = u16(message, pos, "<"), u16(message, pos + 2, "<")
                start, end = pos + 4, pos + 4 + length
                if end > len(message):
                    counts["malformed:enip_identity_item"] += 1
                    break
                if typ == 0x0C and length >= 33:
                    replace(start + 4, struct.pack("!H", 44818), "enip.identity_socket_port")
                    replace(start + 6, SERVER_IP, "enip.identity_socket_address")
                    replace(start + 28, b"\0" * 4, "enip.identity_serial")
                    name_length = message[start + 32]
                    if start + 33 + name_length <= end:
                        identities.append({"vendor_id": u16(message, start + 18, "<"),
                                           "device_type": u16(message, start + 20, "<"),
                                           "product_code": u16(message, start + 22, "<"),
                                           "revision": f"{message[start + 24]}.{message[start + 25]}",
                                           "status": u16(message, start + 26, "<"),
                                           "product_name": text_value(message[start + 33:start + 33 + name_length])})
                    else:
                        counts["malformed:enip_product_name"] += 1
                pos = end
            if server:
                evidence.update(kind="enip_list_identity", identities=identities)
        if command in (0x6F, 0x70) and len(message) >= 32:
            pos = 32
            for _ in range(u16(message, 30, "<")):
                if pos + 4 > len(message):
                    counts["malformed:enip_cpf"] += 1
                    break
                typ, length = u16(message, pos, "<"), u16(message, pos + 2, "<")
                start, end = pos + 4, pos + 4 + length
                if end > len(message):
                    counts["malformed:enip_cpf"] += 1
                    break
                if typ in (0xA1, 0x8002) and length >= 4:
                    remap(start, 4, "enip.connection_id", "little")
                if typ == 0x8002 and length >= 8:
                    remap(start + 4, 4, "enip.encapsulation_sequence", "little")
                if typ == 0xB1 and length >= 2:
                    remap(start, 2, "enip.connected_sequence", "little")
                    start += 2
                if typ in (0xB1, 0xB2) and end - start >= 2:
                    cip = message[start:end]
                    service = cip[0]
                    key = (message[4:8], message[12:20], service & 0x7F)
                    if not server and not service & 0x80:
                        path_end, cursor, logical = 2 + cip[1] * 2, 2, {}
                        while cursor < min(path_end, len(cip)):
                            segment = cip[cursor]
                            if segment in (0x20, 0x24, 0x30) and cursor + 2 <= path_end:
                                logical[segment & 0xFC] = cip[cursor + 1]
                                cursor += 2
                            elif segment in (0x21, 0x25, 0x31) and cursor + 4 <= min(path_end, len(cip)):
                                logical[segment & 0xFC] = u16(cip, cursor + 2, "<")
                                cursor += 4
                            else:
                                break
                        ids.cip_requests[key].append(logical)
                    elif server and service & 0x80 and len(cip) >= 4:
                        path = ids.cip_requests[key].popleft() if ids.cip_requests[key] else {}
                        evidence = {"kind": "cip_response", "service": service,
                                    "general_status": cip[2], "response_length": len(cip)}
                        body = start + 4 + cip[3] * 2
                        if path.get(0x20) == 1 and cip[2] == 0 and body <= end:
                            if service == 0x81 and body + 15 <= end:
                                replace(body + 10, b"\0" * 4, "enip.cip_identity_serial")
                                name_length = message[body + 14]
                                if body + 15 + name_length <= end:
                                    identity = {"vendor_id": u16(message, body, "<"),
                                                "device_type": u16(message, body + 2, "<"),
                                                "product_code": u16(message, body + 4, "<"),
                                                "revision": f"{message[body + 6]}.{message[body + 7]}",
                                                "status": u16(message, body + 8, "<"),
                                                "product_name": text_value(message[body + 15:body + 15 + name_length])}
                                    evidence.update(kind="enip_cip_identity", identities=[identity])
                            elif service == 0x8E and path.get(0x30) == 6 and body + 4 <= end:
                                replace(body, b"\0" * 4, "enip.cip_identity_serial")
                        elif not path:
                            counts["cip_response_without_matched_logical_path"] += 1
                pos = end

    else:  # ISO-on-TCP / S7comm
        li = message[4]
        if len(message) < 5 + li or li < 2:
            counts["malformed:cotp"] += 1
            return bytes(out), counts, evidence
        cotp_type = message[5] & 0xF0
        counts[f"cotp_type:0x{cotp_type:02x}"] += 1
        if cotp_type in (0xD0, 0xE0) and len(message) >= 11:
            for pos, name in ((6, "s7.cotp_destination_reference"), (8, "s7.cotp_source_reference")):
                replace(pos, b"\0\0" if u16(message, pos) == 0 else b"\0\1", name)
            if server:
                evidence = {"kind": "cotp_connection_response", "pdu_type": cotp_type,
                            "response_length": len(message)}
        start = 5 + li
        if cotp_type == 0xF0 and start + 10 <= len(message) and message[start] == 0x32:
            rosctr = message[start + 1]
            remap(start + 4, 2, "s7.pdu_reference")
            header = 12 if rosctr in (2, 3) else 10
            plen, dlen = u16(message, start + 6), u16(message, start + 8)
            param, data = start + header, start + header + plen
            if param + plen > len(message) or data + dlen > len(message):
                counts["malformed:s7_lengths"] += 1
            elif server:
                evidence = {"kind": "s7_response", "rosctr": rosctr,
                            "parameter_length": plen, "data_length": dlen}
                if rosctr in (2, 3):
                    evidence["error_class"] = message[start + 10]
                    evidence["error_code"] = message[start + 11]
            if rosctr == 7 and plen >= 8 and param + plen <= len(message):
                remap(param + 7, 1, "s7.userdata_sequence")
                if plen >= 12:
                    remap(param + 8, 1, "s7.userdata_reference")
                if server and evidence is not None:
                    evidence["function_group"] = message[param + 5] & 15
                    evidence["subfunction"] = message[param + 6]
                    if dlen >= 4 and data + dlen <= len(message):
                        evidence["return_code"] = message[data]
                    if (dlen >= 12 and data + dlen <= len(message)
                            and message[data] == 0xFF and message[data + 1] == 9
                            and (message[param + 5] & 15) == 4 and message[param + 6] == 1):
                        szl = u16(message, data + 4)
                        evidence["szl_id"] = szl
                        if szl == 0x11:
                            itemlen, nitems = u16(message, data + 8), u16(message, data + 10)
                            if itemlen >= 28 and data + 12 + nitems * itemlen <= data + dlen:
                                entries = []
                                for index in range(nitems):
                                    entry = data + 12 + index * itemlen
                                    entries.append({"index": u16(message, entry),
                                                    "order_number": text_value(message[entry + 2:entry + 22]),
                                                    "module_type_id": u16(message, entry + 22),
                                                    "version": u16(message, entry + 24),
                                                    "release": u16(message, entry + 26)})
                                evidence.update(kind="s7_module_identification", entries=entries)
                            else:
                                counts["malformed:s7_szl_entries"] += 1
    return bytes(out), counts, evidence


def control_model_evidence(record):
    """One schema-based text view; no label-dependent string matching."""
    result = copy.deepcopy(record)
    if result.get("kind") == "modbus_device_identification":
        for obj in result["objects"]:
            if obj["object_id"] in (1, 4, 5):
                obj["value"] = "[MASKED]"
    elif result.get("kind") in ("enip_list_identity", "enip_cip_identity"):
        for obj in result["identities"]:
            obj["product_code"] = "[MASKED]"
            obj["product_name"] = "[MASKED]"
    elif result.get("kind") == "s7_module_identification":
        for obj in result["entries"]:
            obj["order_number"] = "[MASKED]"
            obj["module_type_id"] = "[MASKED]"
    return result


def reassembly(packets, base, server):
    data, conflicts = {}, 0
    for p in packets:
        if p.server != server or not p.payload:
            continue
        offset = relative(p.seq + bool(p.flags & 2), base)
        # Signed offsets support captures beginning mid-connection.
        if offset >= 2**31:
            offset -= 2**32
        for i, byte in enumerate(p.payload, offset):
            if i in data and data[i] != byte:
                conflicts += 1
            data.setdefault(i, byte)
    chunks, positions, start, prior, buffer = [], sorted(data), None, None, bytearray()
    for pos in positions:
        if prior is not None and pos != prior + 1:
            chunks.append((start, bytes(buffer)))
            buffer = bytearray()
            start = None
        if start is None:
            start = pos
        buffer.append(data[pos])
        prior = pos
    if buffer:
        chunks.append((start, bytes(buffer)))
    return chunks, conflicts


def tcp_options(packet):
    data, pos = packet.data, packet.tcp + 20
    while pos < packet.payload_start:
        kind = data[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 2 > packet.payload_start:
            raise ValueError("Truncated TCP option")
        length = data[pos + 1]
        if length < 2 or pos + length > packet.payload_start:
            raise ValueError("Malformed TCP option")
        yield kind, pos, length
        pos += length


def control_flow(flow, protocol):
    packets, counts = flow.packets, Counter()
    seqbase, idbase, tsbase = {}, {}, {}
    for server in (False, True):
        direction = [p for p in packets if p.server == server]
        if direction:
            first = next((p for p in direction if p.flags & 2), direction[0])
            seqbase[server] = first.seq
            idbase[server] = u16(direction[0].data, direction[0].ip + 4)
            timestamps = [u32(p.data, pos + 2) for p in direction
                          for kind, pos, length in tcp_options(p) if kind == 8 and length == 10]
            tsbase[server] = timestamps[0] if timestamps else 0
        else:
            # No packet from this direction: normalize any observed ACK base.
            seqbase[server] = next((p.ack for p in packets if p.flags & 16), 0)
            idbase[server], tsbase[server] = 0, 0
    edits, responses, ids = {False: {}, True: {}}, [], IdentifierMap()
    for server in (False, True):
        chunks, conflicts = reassembly(packets, seqbase[server], server)
        counts["tcp_overlap_conflicting_bytes"] += conflicts
        for start, data in chunks:
            consumed = 0
            for offset, frame in frames(protocol, data):
                frame_edits = {}
                controlled, report, response = transform_message(protocol, frame, server, ids, frame_edits)
                counts.update(report)
                counts["application_frames"] += 1
                counts["server_application_frames" if server else "client_application_frames"] += 1
                # Include unchanged canonical field bytes too: a conflicting
                # retransmission must not reintroduce another identity value.
                edits[server].update((start + offset + i, value) for i, value in frame_edits.items())
                consumed += len(frame)
                if response is not None:
                    responses.append(response)
            counts["unframed_application_bytes"] += len(data) - consumed
    transformed = []
    for p in packets:
        data, server = bytearray(p.data), p.server
        data[:6], data[6:12] = (CLIENT_MAC, SERVER_MAC) if server else (SERVER_MAC, CLIENT_MAC)
        data[p.ip + 12:p.ip + 16], data[p.ip + 16:p.ip + 20] = (SERVER_IP, CLIENT_IP) if server else (CLIENT_IP, SERVER_IP)
        struct.pack_into("!H", data, p.ip + 4, relative(u16(p.data, p.ip + 4), idbase[server], 16))
        struct.pack_into("!HH", data, p.tcp,
                         SERVER_PORTS[protocol] if server else CLIENT_PORT,
                         CLIENT_PORT if server else SERVER_PORTS[protocol])
        struct.pack_into("!I", data, p.tcp + 4, relative(p.seq, seqbase[server]))
        struct.pack_into("!I", data, p.tcp + 8, relative(p.ack, seqbase[not server]) if p.flags & 16 else 0)
        for kind, pos, length in tcp_options(p):
            if kind == 8 and length == 10:
                struct.pack_into("!I", data, pos + 2, relative(u32(p.data, pos + 2), tsbase[server]))
                echo = u32(p.data, pos + 6)
                struct.pack_into("!I", data, pos + 6, relative(echo, tsbase[not server]) if echo else 0)
                counts["covered:tcp.timestamp"] += 1
            elif kind == 5 and length >= 10 and (length - 2) % 8 == 0:
                for edge in range(pos + 2, pos + length, 4):
                    struct.pack_into("!I", data, edge, relative(u32(p.data, edge), seqbase[not server]))
                counts["covered:tcp.sack"] += 1
        offset = relative(p.seq + bool(p.flags & 2), seqbase[server])
        if offset >= 2**31:
            offset -= 2**32
        for i in range(p.payload_end - p.payload_start):
            if offset + i in edits[server]:
                data[p.payload_start + i] = edits[server][offset + i]
        data[p.ip + 10:p.ip + 12] = b"\0\0"
        data[p.tcp + 16:p.tcp + 18] = b"\0\0"
        if len(data) != len(p.data):
            raise AssertionError("Transformation changed a packet length")
        transformed.append(bytes(data))
    counts["packets_controlled"] = len(packets)
    return transformed, counts, responses
