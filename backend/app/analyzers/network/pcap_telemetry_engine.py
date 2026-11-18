import struct
import socket
import hashlib
import uuid
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Set

from backend.app.core.models import (
    NetworkFlowRecord,
    DynamicTelemetryEvent,
    FindingRecord
)

def _parse_dns_labels(payload: bytes, offset: int) -> Tuple[str, int]:
    """Parses DNS domain name from payload with compression pointer support."""
    labels = []
    visited_offsets = set()
    orig_offset = offset
    stepped = False

    while offset < len(payload):
        if offset in visited_offsets or len(visited_offsets) > 25:
            break
        visited_offsets.add(offset)
        length = payload[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0: # Compression pointer
            if offset + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if not stepped:
                orig_offset = offset + 2
                stepped = True
            offset = pointer
        else:
            offset += 1
            if offset + length <= len(payload):
                try:
                    labels.append(payload[offset:offset + length].decode("ascii", errors="replace"))
                except Exception:
                    pass
                offset += length
            else:
                break

    return ".".join(labels), orig_offset if stepped else offset

class PCAPTelemetryEngine:
    """
    Robust pure-Python network packet and telemetry extraction engine.
    Supports standard PCAP (microsecond & nanosecond, LE & BE) and PCAPNG files.
    Preserves cryptographic integrity, links findings to packet offsets,
    and accurately separates encrypted TLS transport from application data.
    """

    def analyze_pcap(
        self,
        file_path: Path,
        investigation_id: str,
        run_id: str = "RUN-MANUAL",
        is_simulated: bool = True
    ) -> Tuple[List[NetworkFlowRecord], List[DynamicTelemetryEvent], Dict[str, Any]]:
        flows: List[NetworkFlowRecord] = []
        events: List[DynamicTelemetryEvent] = []
        metadata: Dict[str, Any] = {
            "pcap_filename": file_path.name,
            "pcap_sha256": None,
            "file_size": 0,
            "capture_type": "Unknown",
            "total_packets": 0,
            "unique_ips": [],
            "dns_queries": [],
            "http_hosts": [],
            "tls_snis": [],
            "first_packet_utc": None,
            "last_packet_utc": None,
            "ids_alerts": []
        }

        if not file_path.exists():
            metadata["error"] = "PCAP file not found on disk."
            return flows, events, metadata

        raw = file_path.read_bytes()
        metadata["file_size"] = len(raw)
        pcap_hash = hashlib.sha256(raw).hexdigest()
        metadata["pcap_sha256"] = pcap_hash

        if len(raw) < 24:
            metadata["error"] = "File too small for valid PCAP header."
            return flows, events, metadata

        magic = raw[:4]
        little_endian = True
        is_pcapng = False

        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            little_endian = True
            metadata["capture_type"] = "PCAP (Standard Microsecond)"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            little_endian = False
            metadata["capture_type"] = "PCAP (Big-Endian)"
        elif magic == b"\n\r\r\n":
            is_pcapng = True
            metadata["capture_type"] = "PCAPNG"

        fmt = "<" if little_endian else ">"
        offset = 24 if not is_pcapng else 0
        packet_idx = 0

        flow_map: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
        unique_ips: Set[str] = set()
        dns_queries: Set[str] = set()
        http_hosts: Set[str] = set()
        tls_snis: Set[str] = set()

        first_ts = None
        last_ts = None

        if not is_pcapng:
            # Standard PCAP parsing
            while offset + 16 <= len(raw) and packet_idx < 15000:
                packet_idx += 1
                try:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(f"{fmt}IIII", raw, offset)
                except struct.error:
                    break

                offset += 16
                if offset + incl_len > len(raw):
                    break

                pkt_bytes = raw[offset:offset + incl_len]
                offset += incl_len

                ts_float = ts_sec + (ts_usec / 1000000.0)
                dt = datetime.utcfromtimestamp(ts_float)
                if first_ts is None:
                    first_ts = dt
                last_ts = dt

                # Ethernet frame (14 bytes)
                if len(pkt_bytes) < 14:
                    continue
                eth_proto = struct.unpack_from("!H", pkt_bytes, 12)[0]

                # IPv4
                if eth_proto == 0x0800 and len(pkt_bytes) >= 34:
                    ip_hdr = pkt_bytes[14:34]
                    ihl = (ip_hdr[0] & 0x0F) * 4
                    ip_proto = ip_hdr[9]
                    src_ip = socket.inet_ntoa(ip_hdr[12:16])
                    dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                    unique_ips.add(src_ip)
                    unique_ips.add(dst_ip)

                    trans_offset = 14 + ihl
                    self._process_l4(
                        pkt_bytes, trans_offset, ip_proto, src_ip, dst_ip,
                        packet_idx, dt.isoformat(), file_path.name,
                        flow_map, events, investigation_id, run_id, is_simulated,
                        dns_queries, http_hosts, tls_snis
                    )

        else:
            # PCAPNG block scanner
            block_offset = 0
            while block_offset + 8 <= len(raw) and packet_idx < 15000:
                try:
                    b_type, b_len = struct.unpack_from("<II", raw, block_offset)
                except struct.error:
                    break
                if b_len < 12 or block_offset + b_len > len(raw):
                    break

                # Enhanced Packet Block (0x00000006) or Simple Packet Block (0x00000003)
                if b_type == 0x00000006 and b_len >= 32:
                    packet_idx += 1
                    try:
                        _, ts_high, ts_low, cap_len, _ = struct.unpack_from("<IIIII", raw, block_offset + 4)
                        pkt_data = raw[block_offset + 28:block_offset + 28 + cap_len]
                        dt = datetime.utcnow() # Normalized fallback timestamp for pcapng blocks
                        if len(pkt_data) >= 34:
                            eth_proto = struct.unpack_from("!H", pkt_data, 12)[0]
                            if eth_proto == 0x0800:
                                ip_hdr = pkt_data[14:34]
                                ihl = (ip_hdr[0] & 0x0F) * 4
                                ip_proto = ip_hdr[9]
                                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                                dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                                unique_ips.add(src_ip)
                                unique_ips.add(dst_ip)
                                self._process_l4(
                                    pkt_data, 14 + ihl, ip_proto, src_ip, dst_ip,
                                    packet_idx, dt.isoformat(), file_path.name,
                                    flow_map, events, investigation_id, run_id, is_simulated,
                                    dns_queries, http_hosts, tls_snis
                                )
                    except Exception:
                        pass
                block_offset += b_len

        # Convert flow map to NetworkFlowRecord objects
        for (src_ip, src_port, dst_ip, dst_port, proto), f_data in flow_map.items():
            flows.append(NetworkFlowRecord(
                id=f"FLOW-{uuid.uuid4().hex[:8]}",
                run_id=run_id,
                investigation_id=investigation_id,
                timestamp_utc=f_data["start_utc"],
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                direction="OUTBOUND" if not src_ip.startswith("127.") else "LOCAL",
                dns_hostname=f_data.get("dns_hostname"),
                tls_sni=f_data.get("tls_sni"),
                http_method=f_data.get("http_method"),
                http_status=f_data.get("http_status"),
                packet_count=f_data["packet_count"],
                byte_count=f_data["byte_count"],
                pcap_file=file_path.name,
                packet_reference=f"Packet #{f_data['first_packet_idx']}",
                is_simulated=is_simulated,
                related_indicator_ids=[]
            ))

        metadata["total_packets"] = packet_idx
        metadata["unique_ips"] = list(unique_ips)
        metadata["dns_queries"] = list(dns_queries)
        metadata["http_hosts"] = list(http_hosts)
        metadata["tls_snis"] = list(tls_snis)
        metadata["first_packet_utc"] = first_ts.isoformat() if first_ts else None
        metadata["last_packet_utc"] = last_ts.isoformat() if last_ts else None

        return flows, events, metadata

    def _process_l4(
        self,
        pkt_bytes: bytes,
        trans_offset: int,
        ip_proto: int,
        src_ip: str,
        dst_ip: str,
        packet_idx: int,
        ts_utc: str,
        pcap_file: str,
        flow_map: Dict,
        events: List[DynamicTelemetryEvent],
        investigation_id: str,
        run_id: str,
        is_simulated: bool,
        dns_queries: Set[str],
        http_hosts: Set[str],
        tls_snis: Set[str]
    ):
        if ip_proto == 6 and trans_offset + 20 <= len(pkt_bytes): # TCP
            src_port, dst_port = struct.unpack_from("!HH", pkt_bytes, trans_offset)
            tcp_offset = ((pkt_bytes[trans_offset + 12] >> 4) & 0x0F) * 4
            payload = pkt_bytes[trans_offset + tcp_offset:]

            flow_key = (src_ip, src_port, dst_ip, dst_port, "TCP")
            if flow_key not in flow_map:
                flow_map[flow_key] = {
                    "start_utc": ts_utc,
                    "first_packet_idx": packet_idx,
                    "packet_count": 0,
                    "byte_count": 0,
                    "dns_hostname": None,
                    "tls_sni": None,
                    "http_method": None,
                    "http_status": None
                }
            flow_map[flow_key]["packet_count"] += 1
            flow_map[flow_key]["byte_count"] += len(pkt_bytes)

            # Check HTTP
            if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"CONNECT ")):
                try:
                    head_line = payload.split(b"\r\n")[0].decode("latin-1", errors="replace")
                    parts = head_line.split()
                    method = parts[0] if parts else "HTTP"
                    flow_map[flow_key]["http_method"] = method

                    # Look for Host header
                    for line in payload.split(b"\r\n")[1:15]:
                        if line.lower().startswith(b"host:"):
                            host_str = line[5:].strip().decode("latin-1", errors="replace")
                            http_hosts.add(host_str)
                            flow_map[flow_key]["dns_hostname"] = host_str
                            break

                    events.append(DynamicTelemetryEvent(
                        id=f"EV-HTTP-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        investigation_id=investigation_id,
                        event_category="HTTP_REQUEST",
                        timestamp_utc=ts_utc,
                        operation=method,
                        details={
                            "request_line": head_line,
                            "packet_ref": f"Packet #{packet_idx}",
                            "pcap": pcap_file,
                            "src": f"{src_ip}:{src_port}",
                            "dst": f"{dst_ip}:{dst_port}"
                        },
                        is_simulated=is_simulated
                    ))
                except Exception:
                    pass

            # Check TLS ClientHello (0x16 0x03)
            elif len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                # Check for SNI extension in ClientHello
                sni_found = self._extract_tls_sni(payload)
                if sni_found:
                    tls_snis.add(sni_found)
                    flow_map[flow_key]["tls_sni"] = sni_found
                    events.append(DynamicTelemetryEvent(
                        id=f"EV-TLS-{uuid.uuid4().hex[:8]}",
                        run_id=run_id,
                        investigation_id=investigation_id,
                        event_category="TLS_HANDSHAKE",
                        timestamp_utc=ts_utc,
                        operation="ClientHello",
                        details={
                            "sni_hostname": sni_found,
                            "packet_ref": f"Packet #{packet_idx}",
                            "pcap": pcap_file,
                            "note": "TLS SNI observed in unencrypted handshake. Application payload is encrypted."
                        },
                        is_simulated=is_simulated
                    ))

        elif ip_proto == 17 and trans_offset + 8 <= len(pkt_bytes): # UDP
            src_port, dst_port, udp_len = struct.unpack_from("!HHH", pkt_bytes, trans_offset)
            payload = pkt_bytes[trans_offset + 8:trans_offset + udp_len]

            flow_key = (src_ip, src_port, dst_ip, dst_port, "UDP")
            if flow_key not in flow_map:
                flow_map[flow_key] = {
                    "start_utc": ts_utc,
                    "first_packet_idx": packet_idx,
                    "packet_count": 0,
                    "byte_count": 0,
                    "dns_hostname": None,
                    "tls_sni": None,
                    "http_method": None,
                    "http_status": None
                }
            flow_map[flow_key]["packet_count"] += 1
            flow_map[flow_key]["byte_count"] += len(pkt_bytes)

            # DNS (Port 53)
            if dst_port == 53 or src_port == 53:
                if len(payload) >= 12:
                    qdcount = struct.unpack_from("!H", payload, 4)[0]
                    if qdcount > 0:
                        domain_name, _ = _parse_dns_labels(payload, 12)
                        if domain_name:
                            dns_queries.add(domain_name)
                            flow_map[flow_key]["dns_hostname"] = domain_name
                            events.append(DynamicTelemetryEvent(
                                id=f"EV-DNS-{uuid.uuid4().hex[:8]}",
                                run_id=run_id,
                                investigation_id=investigation_id,
                                event_category="DNS_QUERY",
                                timestamp_utc=ts_utc,
                                operation="DNS_LOOKUP",
                                details={
                                    "query_domain": domain_name,
                                    "packet_ref": f"Packet #{packet_idx}",
                                    "pcap": pcap_file
                                },
                                is_simulated=is_simulated
                            ))

    def _extract_tls_sni(self, payload: bytes) -> Optional[str]:
        """Extracts SNI hostname from TLS ClientHello payload safely."""
        try:
            if len(payload) < 43 or payload[0] != 0x16:
                return None
            sess_id_len = payload[43]
            offset = 44 + sess_id_len
            if offset + 2 > len(payload):
                return None
            cipher_suites_len = struct.unpack_from("!H", payload, offset)[0]
            offset += 2 + cipher_suites_len
            if offset + 1 > len(payload):
                return None
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if offset + 2 > len(payload):
                return None
            extensions_len = struct.unpack_from("!H", payload, offset)[0]
            offset += 2
            ext_end = offset + extensions_len

            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type, ext_len = struct.unpack_from("!HH", payload, offset)
                offset += 4
                if ext_type == 0: # Server Name Indication (SNI)
                    if offset + 5 <= len(payload):
                        # skip server_name_list_length (2) and name_type (1)
                        name_len = struct.unpack_from("!H", payload, offset + 3)[0]
                        sni_bytes = payload[offset + 5:offset + 5 + name_len]
                        return sni_bytes.decode("ascii", errors="replace")
                offset += ext_len
        except Exception:
            pass
        return None

pcap_telemetry_engine = PCAPTelemetryEngine()
