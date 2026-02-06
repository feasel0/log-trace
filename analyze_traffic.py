#!/usr/bin/env python3
"""
Matter Log and PCAP Traffic Analyzer

This script analyzes Matter controller and DUT logs along with PCAP files to create
a structured representation of network traffic between controller and device under test.
"""

import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path


@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: str
    line_number: int
    raw_line: str
    message_type: Optional[str] = None
    direction: Optional[str] = None  # 'sent' or 'received'
    is_ack: bool = False
    exchange_id: Optional[str] = None
    message_counter: Optional[str] = None


@dataclass
class PcapPacket:
    """Represents a PCAP packet"""
    packet_number: int
    timestamp: str
    src: str
    dst: str
    protocol: str
    info: str
    raw_data: Any = None


@dataclass
class Message:
    """Represents a correlated message between controller and DUT"""
    message_id: int
    message_type: str
    # New: provide exchange-level detail so a single exchange section can list all message ids.
    exchange_id: Optional[str] = None
    # message_counter -> list of line numbers (retries) seen in each log
    controller_message_ids: Dict[str, List[int]] = None
    dut_message_ids: Dict[str, List[int]] = None
    # message_counter -> (pcap_packet_number, pcap_timestamp)
    controller_pcap_by_message_id: Dict[str, List[PcapPacket]] = None
    dut_pcap_by_message_id: Dict[str, List[PcapPacket]] = None
    controller_sent: Optional[LogEntry] = None
    controller_received: Optional[LogEntry] = None
    dut_sent: Optional[LogEntry] = None
    dut_received: Optional[LogEntry] = None
    controller_ack_sent: Optional[LogEntry] = None
    controller_ack_received: Optional[LogEntry] = None
    dut_ack_sent: Optional[LogEntry] = None
    dut_ack_received: Optional[LogEntry] = None
    controller_pcap_packets: List[PcapPacket] = None
    dut_pcap_packets: List[PcapPacket] = None

    def __post_init__(self):
        if self.controller_pcap_packets is None:
            self.controller_pcap_packets = []
        if self.dut_pcap_packets is None:
            self.dut_pcap_packets = []
        if self.controller_message_ids is None:
            self.controller_message_ids = {}
        if self.dut_message_ids is None:
            self.dut_message_ids = {}
        if self.controller_pcap_by_message_id is None:
            self.controller_pcap_by_message_id = {}
        if self.dut_pcap_by_message_id is None:
            self.dut_pcap_by_message_id = {}


class LogParser:
    """Parser for Matter controller and DUT logs"""

    # Patterns for common Matter log formats.
    # This repo commonly consumes two syntaxes:
    # 1) Python controller logs with standard timestamps: 2026-01-30 15:58:22,956 - ... - <<< [E:6862i S:0 M:30758095] ... Type 0001:02 (IM:ReadRequest)
    # 2) DUT logs with monotonic timestamps: [1769806702.974] ... [EM] >>> [E:6862r S:0 M:30758095] ... Type 0000:20 (SecureChannel:PBKDFParamRequest)
    TIMESTAMP_PATTERN = r'(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+)|(?:\[\d+\.\d+\])'

    # EM packet lines are the primary signal for message-level traffic.
    # Match EM packet lines both in DUT format ("[EM] >>> ...") and controller python logging
    # format ("matter.native.EM - ... - <<< ...").
    EM_LINE_PATTERN = (
        r'(?:\[EM\]|\bmatter\.native\.EM\b).*'
        r'(<<<|>>>).*'
        r'\[E:(?P<exchange>\d+)[ir].*?\bM:(?P<msg_counter>\d+)'
        r'(?:\s*\(Ack:(?P<ack_for>\d+)\))?.*?'
        r'\bType\s+\d{4}:\d{2}\s+\((?P<type>[^)]+)\)'
    )

    # Ack-only messages can appear explicitly as SecureChannel:StandaloneAck (type parsing covers this)
    # but in some older logs they may appear as text “ACK”. Keep a soft fallback.
    ACK_TEXT_PATTERN = r'\bACK\b'

    # Legacy/simple pattern used by tests/examples in this repo.
    SIMPLE_MESSAGE_PATTERN = r'\b(Sending|Sent|Received|Receiving)\b.*\b(InvokeRequest|InvokeResponse|ReadRequest|ReadResponse|WriteRequest|WriteResponse|SubscribeRequest|SubscribeResponse|ReportData|StatusResponse|TimedRequest)\b'
    SIMPLE_ACK_PATTERN = r'\b(Sending|Sent|Received|Receiving)\b\s+ACK\b'
    SIMPLE_EXCHANGE_ID_PATTERN = r'exchange[:\s]+(0x[0-9a-fA-F]+|\w+)'
    SIMPLE_MESSAGE_COUNTER_PATTERN = r'message counter[:\s]+(\w+)'

    @staticmethod
    def parse_log_file(file_path: str) -> List[LogEntry]:
        """Parse a log file and extract relevant entries"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = LogParser._parse_line(line, line_num)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"Warning: Log file not found: {file_path}")
        except Exception as e:
            print(f"Error parsing log file {file_path}: {e}")
        
        return entries

    @staticmethod
    def _parse_line(line: str, line_num: int) -> Optional[LogEntry]:
        """Parse a single log line"""
        line = line.strip()
        if not line:
            return None
        
        # Extract timestamp
        timestamp_match = re.search(LogParser.TIMESTAMP_PATTERN, line)
        timestamp = timestamp_match.group(0) if timestamp_match else ""

        # Prefer parsing true Matter EM packet lines.
        em_match = re.search(LogParser.EM_LINE_PATTERN, line)
        if em_match:
            arrow = em_match.group(1)
            direction = 'sent' if arrow == '<<<' else 'received'

            exchange_id = em_match.group('exchange')
            msg_counter = em_match.group('msg_counter')
            msg_type = em_match.group('type')

            # Normalize message type. We mostly care about the protocol message name.
            # Examples in logs: "IM:ReadRequest", "IM:InvokeCommandRequest", "SecureChannel:StandaloneAck".
            message_type = msg_type.split(':', 1)[-1] if ':' in msg_type else msg_type

            # ACK detection: StandaloneAck or explicit Ack field / ACK text.
            is_ack = (
                'StandaloneAck' in msg_type
                or em_match.group('ack_for') is not None
                or re.search(LogParser.ACK_TEXT_PATTERN, line) is not None
            )

            return LogEntry(
                timestamp=timestamp,
                line_number=line_num,
                raw_line=line,
                message_type=message_type,
                direction=direction,
                is_ack=is_ack,
                exchange_id=exchange_id,
                message_counter=msg_counter
            )

        # Fallback: support the simplified "Sending message InvokeRequest ... exchange: ..." format.
        msg_match = re.search(LogParser.SIMPLE_MESSAGE_PATTERN, line)
        ack_match = re.search(LogParser.SIMPLE_ACK_PATTERN, line)
        if not msg_match and not ack_match:
            return None

        if ack_match:
            verb = ack_match.group(1).lower()
            direction = 'sent' if verb in ('sending', 'sent') else 'received'
            message_type = 'ACK'
            is_ack = True
        else:
            verb = msg_match.group(1).lower()
            direction = 'sent' if verb in ('sending', 'sent') else 'received'
            message_type = msg_match.group(2)
            is_ack = re.search(LogParser.ACK_TEXT_PATTERN, line) is not None

        exchange_id_match = re.search(LogParser.SIMPLE_EXCHANGE_ID_PATTERN, line, re.IGNORECASE)
        exchange_id = exchange_id_match.group(1) if exchange_id_match else None

        msg_counter_match = re.search(LogParser.SIMPLE_MESSAGE_COUNTER_PATTERN, line, re.IGNORECASE)
        msg_counter = msg_counter_match.group(1) if msg_counter_match else None

        return LogEntry(
            timestamp=timestamp,
            line_number=line_num,
            raw_line=line,
            message_type=message_type,
            direction=direction,
            is_ack=is_ack,
            exchange_id=exchange_id,
            message_counter=msg_counter
        )

    @staticmethod
    def _extract_message_type(line: str) -> Optional[str]:
        """Extract the message type from a log line"""
        # Look for common Matter message types
        matter_types = [
            'InvokeRequest', 'InvokeResponse',
            'ReadRequest', 'ReadResponse',
            'WriteRequest', 'WriteResponse',
            'SubscribeRequest', 'SubscribeResponse',
            'ReportData', 'TimedRequest',
            'StatusResponse', 'MRP'
        ]
        
        for msg_type in matter_types:
            if msg_type in line:
                return msg_type
        
        return None


class PcapParser:
    """Parser for PCAP files"""

    @staticmethod
    def parse_pcap_file(file_path: str) -> List[PcapPacket]:
        """Parse a PCAP file and extract packets"""
        packets: List[PcapPacket] = []

        # Prefer tshark over scapy so we can select the Matter devkeys profile.
        # Requires Wireshark/tshark installed and a profile named "matter-devkeys".
        try:
            import subprocess
            import tempfile
            import bz2
            import os

            pcap_path = file_path
            tmp_path = None

            # Support bz2-compressed pcaps (common for DUT captures).
            if str(file_path).endswith('.bz2'):
                with bz2.open(file_path, 'rb') as src:
                    fd, tmp_path = tempfile.mkstemp(prefix='dut_', suffix='.pcap')
                    with os.fdopen(fd, 'wb') as dst:
                        dst.write(src.read())
                pcap_path = tmp_path

            # Field list:
            # - frame.number / frame.time_epoch: stable numeric timestamp for correlation
            # - ip.src/ip.dst + udp ports when present
            # - _ws.col.Protocol + _ws.col.Info: user-friendly summary
            cmd = [
                'tshark',
                '-C', 'matter-devkeys',
                '-r', pcap_path,
                '-T', 'fields',
                '-E', 'separator=\t',
                '-E', 'quote=n',
                '-E', 'occurrence=f',
                '-e', 'frame.number',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'udp.srcport',
                '-e', 'ip.dst',
                '-e', 'udp.dstport',
                '-e', '_ws.col.Protocol',
                '-e', '_ws.col.Info',
            ]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                # Make the failure actionable.
                err = proc.stderr.strip() or 'unknown tshark error'
                print(f"Warning: tshark failed to parse PCAP {file_path}: {err}")
                return packets

            for line in proc.stdout.splitlines():
                parts = line.split('\t')
                # tshark may omit fields; pad to expected length
                while len(parts) < 8:
                    parts.append('')

                frame_no, t_epoch, ip_src, udp_sport, ip_dst, udp_dport, proto, info = parts[:8]

                try:
                    pkt_no = int(frame_no)
                except Exception:
                    continue

                try:
                    ts = datetime.fromtimestamp(float(t_epoch)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                except Exception:
                    ts = "Invalid timestamp"

                src = ip_src
                dst = ip_dst
                if udp_sport:
                    src = f"{src}:{udp_sport}" if src else ''
                if udp_dport:
                    dst = f"{dst}:{udp_dport}" if dst else ''

                packets.append(
                    PcapPacket(
                        packet_number=pkt_no,
                        timestamp=ts,
                        src=src,
                        dst=dst,
                        protocol=proto or '',
                        info=info or '',
                        raw_data=None,
                    )
                )

            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        except FileNotFoundError:
            print("Warning: tshark not found. PCAP parsing disabled.")
        except Exception as e:
            print(f"Error parsing PCAP file {file_path}: {e}")

        return packets

    @staticmethod
    def build_message_id_index(file_path: str) -> Dict[str, List[PcapPacket]]:
        """Return mapping of Matter message counter -> packets.

        This uses tshark with the matter-devkeys profile and tries multiple common field
        names depending on Wireshark version / dissectors.
        """
        index: Dict[str, List[PcapPacket]] = {}

        try:
            import subprocess
            import tempfile
            import bz2
            import os

            pcap_path = file_path
            tmp_path = None
            if str(file_path).endswith('.bz2'):
                with bz2.open(file_path, 'rb') as src:
                    fd, tmp_path = tempfile.mkstemp(prefix='dut_', suffix='.pcap')
                    with os.fdopen(fd, 'wb') as dst:
                        dst.write(src.read())
                pcap_path = tmp_path

            # In Wireshark 3.6.x, Matter's message counter often appears in the Info column
            # as something like: "MsgCntr=01D554CF" (hex).
            # We'll parse UDP/5540 packets and extract MsgCntr=... and (optionally) AckMsgCntr=...
            cmd = [
                'tshark',
                '-C', 'matter-devkeys',
                '-r', pcap_path,
                '-Y', 'udp.port==5540',
                '-T', 'fields',
                '-E', 'separator=\t',
                '-E', 'quote=n',
                '-E', 'occurrence=f',
                '-e', 'frame.number',
                '-e', 'frame.time_epoch',
                # Prefer IPv4 but also include IPv6. tshark will only populate
                # the one that applies for a given frame.
                '-e', 'ip.src',
                '-e', 'ipv6.src',
                '-e', 'udp.srcport',
                '-e', 'ip.dst',
                '-e', 'ipv6.dst',
                '-e', 'udp.dstport',
                '-e', '_ws.col.Protocol',
                '-e', '_ws.col.Info',
            ]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                return index

            msg_re = re.compile(r'\bMsgCntr=([0-9A-Fa-f]+)\b')
            ack_re = re.compile(r'\bAckMsgCntr=([0-9A-Fa-f]+)\b')
            # Fallback: when the Matter dissector doesn't add MsgCntr=/AckMsgCntr= tokens,
            # some builds still include the raw 32-bit message counter in the Info text.
            # We'll conservatively harvest 8-hex-digit tokens as candidates.
            hex32_re = re.compile(r'\b([0-9A-Fa-f]{8})\b')

            for line in proc.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) < 3:
                    continue
                # tshark may omit some fields; pad for safety.
                while len(parts) < 10:
                    parts.append('')

                frame_no, t_epoch = parts[0], parts[1]
                ip_src, ip6_src, udp_sport = parts[2], parts[3], parts[4]
                ip_dst, ip6_dst, udp_dport = parts[5], parts[6], parts[7]
                proto = parts[8]
                info = parts[9]

                m = msg_re.search(info)
                msg_hex = m.group(1) if m else None

                # Convert hex message counter to decimal to match logs.
                msg_ids = []
                if msg_hex:
                    try:
                        msg_ids.append(str(int(msg_hex, 16)))
                    except Exception:
                        pass
                else:
                    # No explicit MsgCntr token; try conservative fallback candidates.
                    for tok in hex32_re.findall(info or ''):
                        try:
                            msg_ids.append(str(int(tok, 16)))
                        except Exception:
                            continue

                if not msg_ids:
                    continue

                try:
                    pkt_no = int(frame_no)
                except Exception:
                    continue
                try:
                    ts = datetime.fromtimestamp(float(t_epoch)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                except Exception:
                    ts = "Invalid timestamp"

                src_ip = ip_src or ip6_src or ''
                dst_ip = ip_dst or ip6_dst or ''
                src = f"{src_ip}:{udp_sport}" if src_ip and udp_sport else src_ip
                dst = f"{dst_ip}:{udp_dport}" if dst_ip and udp_dport else dst_ip

                pkt = PcapPacket(packet_number=pkt_no, timestamp=ts, src=src, dst=dst, protocol=proto or '', info=info, raw_data=None)
                for msg_id in msg_ids:
                    index.setdefault(msg_id, []).append(pkt)

                # Also index the acked message counter to the same packet (useful for mapping StandAloneACK).
                a = ack_re.search(info)
                if a:
                    try:
                        ack_id = str(int(a.group(1), 16))
                        index.setdefault(ack_id, []).append(pkt)
                    except Exception:
                        pass

            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        except Exception:
            return index

        return index


class MessageCorrelator:
    """Correlates messages across controller logs, DUT logs, and PCAP files"""

    @staticmethod
    def correlate_messages(
        controller_logs: List[LogEntry],
        dut_logs: List[LogEntry],
        controller_pcap: List[PcapPacket],
        dut_pcap: List[PcapPacket]
    ) -> List[Message]:
        """Correlate messages across all sources"""
        messages = []
        message_id = 1

        # Group entries by exchange ID (not message counter)
        controller_groups = MessageCorrelator._group_by_exchange(controller_logs)
        dut_groups = MessageCorrelator._group_by_exchange(dut_logs)
        
        # Combine all exchange IDs
        all_exchanges = set(controller_groups.keys()) | set(dut_groups.keys())

        def exchange_sort_key(ex_id: str):
            # Sort by earliest occurrence line number across controller+dut logs.
            # This approximates chronological order without having to normalize
            # different timestamp formats.
            entries = controller_groups.get(ex_id, []) + dut_groups.get(ex_id, [])
            if not entries:
                return (10**18, str(ex_id))
            earliest_line = min(e.line_number for e in entries)
            return (earliest_line, str(ex_id))

        for exchange_id in sorted(all_exchanges, key=exchange_sort_key):
            controller_entries = controller_groups.get(exchange_id, [])
            dut_entries = dut_groups.get(exchange_id, [])
            
            # Determine message type - prefer non-ACK messages
            message_type = "Unknown"
            for entry in controller_entries + dut_entries:
                if entry.message_type and not entry.is_ack:
                    message_type = entry.message_type
                    break
            
            message = Message(
                message_id=message_id,
                message_type=message_type,
                exchange_id=exchange_id,
            )

            # Populate message-id inventories for this exchange, preserving retries.
            message.controller_message_ids = MessageCorrelator._message_ids_for_exchange(controller_entries)
            message.dut_message_ids = MessageCorrelator._message_ids_for_exchange(dut_entries)
            
            # Assign controller log entries
            for entry in controller_entries:
                if entry.is_ack:
                    if entry.direction == 'sent':
                        message.controller_ack_sent = entry
                    else:
                        message.controller_ack_received = entry
                else:
                    if entry.direction == 'sent':
                        message.controller_sent = entry
                    else:
                        message.controller_received = entry
            
            # Assign DUT log entries
            for entry in dut_entries:
                if entry.is_ack:
                    if entry.direction == 'sent':
                        message.dut_ack_sent = entry
                    else:
                        message.dut_ack_received = entry
                else:
                    if entry.direction == 'sent':
                        message.dut_sent = entry
                    else:
                        message.dut_received = entry
            
            # Correlate PCAP packets (basic time-based correlation)
            all_entries = controller_entries + dut_entries
            message.controller_pcap_packets = MessageCorrelator._find_related_packets(
                all_entries, controller_pcap
            )
            message.dut_pcap_packets = MessageCorrelator._find_related_packets(
                all_entries, dut_pcap
            )
            
            messages.append(message)
            message_id += 1
        
        return messages

    @staticmethod
    def _message_ids_for_exchange(entries: List[LogEntry]) -> Dict[str, List[int]]:
        out: Dict[str, List[int]] = {}
        for e in entries:
            if not e.message_counter:
                continue
            out.setdefault(str(e.message_counter), []).append(e.line_number)
        # Keep line numbers sorted for nicer reporting
        for k in out:
            out[k] = sorted(out[k])
        return out

    @staticmethod
    def _build_pcap_message_id_index(packets: List[PcapPacket]) -> Dict[str, List[PcapPacket]]:
        """Placeholder for now.

        We no longer have access to dissector fields in the already-parsed packet objects.
        This method is kept for compatibility but will return an empty index.

        The richer index is built in main() when we have the pcap file path.
        """
        return {}

    @staticmethod
    def _group_by_exchange(entries: List[LogEntry]) -> Dict[str, List[LogEntry]]:
        """Group log entries by exchange ID only"""
        groups = {}
        
        for entry in entries:
            # Use exchange ID as the key
            if entry.exchange_id:
                key = entry.exchange_id
            else:
                # Fallback to timestamp and line number for uniqueness
                key = f"time_{entry.timestamp}_line_{entry.line_number}"
            
            if key not in groups:
                groups[key] = []
            groups[key].append(entry)
        
        return groups

    @staticmethod
    def _find_related_packets(
        log_entries: List[LogEntry],
        packets: List[PcapPacket]
    ) -> List[PcapPacket]:
        """Find PCAP packets related to log entries (basic time-based)"""
        # Simple implementation: return packets within time window
        # In a real implementation, this would use more sophisticated matching
        related = []
        
        if not log_entries or not packets:
            return related
        
        # For now, just return a subset of packets as a placeholder
        # A full implementation would match based on timestamps, addresses, etc.
        return packets[:min(5, len(packets))]


class ReportGenerator:
    """Generates markdown reports from correlated messages"""

    @staticmethod
    def generate_report(messages: List[Message], output_file: str):
        """Generate a markdown report"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Matter Traffic Analysis Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total Messages: {len(messages)}\n\n")

            ReportGenerator._write_visibility_summary(f, messages)

            f.write("---\n\n")
            
            for message in messages:
                ReportGenerator._write_message_section(f, message)

    @staticmethod
    def _write_visibility_summary(f, messages: List[Message]):
        """Write a summary of what we can/can't observe across logs and pcaps.

        The main question this answers: for message counters (MsgCntr / M:<...>),
        do we see them in controller log/pcap and also on the DUT side? And if not,
        do we at least see DUT ACKs for them?
        """

        controller_log_ids = set()
        dut_log_ids = set()
        controller_pcap_ids = set()
        dut_pcap_ids = set()

        # For ACK visibility: collect which message counters appear as AckMsgCntr in DUT packets.
        dut_ack_for_ids = set()

        for m in messages:
            controller_log_ids.update(m.controller_message_ids.keys())
            dut_log_ids.update(m.dut_message_ids.keys())
            controller_pcap_ids.update(m.controller_pcap_by_message_id.keys())
            dut_pcap_ids.update(m.dut_pcap_by_message_id.keys())

            # Heuristic: if a packet's Info column contains AckMsgCntr, it is an ACK for that ID.
            for mid, pkts in (m.dut_pcap_by_message_id or {}).items():
                for pkt in pkts:
                    if 'AckMsgCntr=' in (pkt.info or ''):
                        dut_ack_for_ids.add(str(mid))

        # Approximation: IDs that the controller "sent" are those that appear in controller logs as sent.
        controller_sent_ids = set()
        for m in messages:
            # Find message counters from controller entries where direction == sent.
            if m.controller_sent and m.controller_sent.message_counter:
                controller_sent_ids.add(str(m.controller_sent.message_counter))
            # Also include any message counters that appear in controller_message_ids but not necessarily bound
            # to controller_sent (retries/other entries). We'll keep controller_sent_ids strict.

        def pct(n, d):
            return (100.0 * n / d) if d else 0.0

        f.write("## Visibility summary\n\n")
        f.write("These stats are computed from the per-exchange message-id tables.\n\n")

        total_ids = len(controller_log_ids | dut_log_ids)
        f.write(f"- Unique message counters (logs): **{total_ids}**\n")
        f.write(f"- Unique message counters in controller log: **{len(controller_log_ids)}**\n")
        f.write(f"- Unique message counters in DUT log: **{len(dut_log_ids)}**\n")
        f.write(f"- Unique message counters in controller PCAP index: **{len(controller_pcap_ids)}**\n")
        f.write(f"- Unique message counters in DUT PCAP index: **{len(dut_pcap_ids)}**\n\n")

        # Controller-sent visibility on DUT side.
        sent_total = len(controller_sent_ids)
        sent_seen_dut_log = len([i for i in controller_sent_ids if i in dut_log_ids])
        sent_seen_dut_pcap = len([i for i in controller_sent_ids if i in dut_pcap_ids])
        sent_acked_by_dut = len([i for i in controller_sent_ids if i in dut_ack_for_ids])

        f.write("### Controller → DUT visibility (message counters)\n\n")
        f.write(f"Using controller *sent* message counters (n={sent_total}):\n\n")
        f.write("| Metric | Count | Percent |\n")
        f.write("|--------|-------|---------|\n")
        f.write(f"| Seen in DUT log | {sent_seen_dut_log} | {pct(sent_seen_dut_log, sent_total):.1f}% |\n")
        f.write(f"| Seen in DUT PCAP | {sent_seen_dut_pcap} | {pct(sent_seen_dut_pcap, sent_total):.1f}% |\n")
        f.write(f"| ACKed by DUT (via DUT PCAP AckMsgCntr) | {sent_acked_by_dut} | {pct(sent_acked_by_dut, sent_total):.1f}% |\n\n")

        # Missing sets (small samples only)
        missing_dut_everywhere = sorted([i for i in controller_sent_ids if (i not in dut_log_ids and i not in dut_pcap_ids)])
        if missing_dut_everywhere:
            show = ', '.join(missing_dut_everywhere[:10])
            suffix = "" if len(missing_dut_everywhere) <= 10 else f" (+{len(missing_dut_everywhere)-10} more)"
            f.write(f"Controller-sent IDs missing on DUT (neither log nor pcap): {show}{suffix}\n\n")


    @staticmethod
    def _write_message_section(f, message: Message):
        """Write a section for a single message"""
        f.write(f"## Message {message.message_id}: {message.message_type}\n\n")
        if message.exchange_id is not None:
            f.write(f"**Exchange:** `{message.exchange_id}`\n\n")

        # Exchange message-id inventory
        if message.controller_message_ids or message.dut_message_ids:
            f.write("### Message IDs in this exchange\n\n")
            f.write("Message-id here means the Matter message counter (the `M:<...>` field).\n\n")
            f.write("| Message ID | Controller log line(s) | DUT log line(s) | Controller PCAP (pkt@time) | DUT PCAP (pkt@time) |\n")
            f.write("|------------|------------------------|-----------------|-----------------------------|----------------------|\n")

            all_ids = set(message.controller_message_ids.keys()) | set(message.dut_message_ids.keys())
            for mid in sorted(all_ids, key=lambda x: int(x) if str(x).isdigit() else str(x)):
                c_lines = message.controller_message_ids.get(mid, [])
                d_lines = message.dut_message_ids.get(mid, [])

                def fmt_lines(lines):
                    if not lines:
                        return "-"
                    if len(lines) == 1:
                        return str(lines[0])
                    return f"{lines[0]} (+{len(lines)-1} more)"

                def fmt_pkt(pkts):
                    if not pkts:
                        return "-"
                    # show first match + count; timestamps can be identical across retries / reassembly
                    p0 = pkts[0]
                    if len(pkts) == 1:
                        return f"{p0.packet_number}@{p0.timestamp}"
                    return f"{p0.packet_number}@{p0.timestamp} (+{len(pkts)-1} more)"

                c_pcap = message.controller_pcap_by_message_id.get(mid, [])
                d_pcap = message.dut_pcap_by_message_id.get(mid, [])
                f.write(
                    f"| {mid} | {fmt_lines(c_lines)} | {fmt_lines(d_lines)} | {fmt_pkt(c_pcap)} | {fmt_pkt(d_pcap)} |\n"
                )
            f.write("\n")
        
        # Controller logs
        f.write("### Controller Logs\n\n")
        
        if message.controller_sent:
            f.write("**Message Sent:**\n")
            f.write(f"- Line {message.controller_sent.line_number}: ")
            f.write(f"`{message.controller_sent.raw_line}`\n\n")
        
        if message.controller_received:
            f.write("**Message Received:**\n")
            f.write(f"- Line {message.controller_received.line_number}: ")
            f.write(f"`{message.controller_received.raw_line}`\n\n")
        
        if message.controller_ack_sent:
            f.write("**ACK Sent:**\n")
            f.write(f"- Line {message.controller_ack_sent.line_number}: ")
            f.write(f"`{message.controller_ack_sent.raw_line}`\n\n")
        
        if message.controller_ack_received:
            f.write("**ACK Received:**\n")
            f.write(f"- Line {message.controller_ack_received.line_number}: ")
            f.write(f"`{message.controller_ack_received.raw_line}`\n\n")
        
        if not any([message.controller_sent, message.controller_received,
                    message.controller_ack_sent, message.controller_ack_received]):
            f.write("*No controller log entries found*\n\n")
        
        # DUT logs
        f.write("### DUT Logs\n\n")
        
        if message.dut_sent:
            f.write("**Message Sent:**\n")
            f.write(f"- Line {message.dut_sent.line_number}: ")
            f.write(f"`{message.dut_sent.raw_line}`\n\n")
        
        if message.dut_received:
            f.write("**Message Received:**\n")
            f.write(f"- Line {message.dut_received.line_number}: ")
            f.write(f"`{message.dut_received.raw_line}`\n\n")
        
        if message.dut_ack_sent:
            f.write("**ACK Sent:**\n")
            f.write(f"- Line {message.dut_ack_sent.line_number}: ")
            f.write(f"`{message.dut_ack_sent.raw_line}`\n\n")
        
        if message.dut_ack_received:
            f.write("**ACK Received:**\n")
            f.write(f"- Line {message.dut_ack_received.line_number}: ")
            f.write(f"`{message.dut_ack_received.raw_line}`\n\n")
        
        if not any([message.dut_sent, message.dut_received,
                    message.dut_ack_sent, message.dut_ack_received]):
            f.write("*No DUT log entries found*\n\n")
        
        # Controller PCAP
        f.write("### Controller PCAP Packets\n\n")

        # Prefer the message-id based mapping (built via tshark) since the older
        # time-window packet list is just a placeholder.
        controller_pkts: List[PcapPacket] = []
        if message.controller_pcap_by_message_id:
            seen = set()
            for pkts in message.controller_pcap_by_message_id.values():
                for pkt in pkts:
                    if pkt.packet_number in seen:
                        continue
                    seen.add(pkt.packet_number)
                    controller_pkts.append(pkt)
            controller_pkts.sort(key=lambda p: p.packet_number)
        else:
            controller_pkts = list(message.controller_pcap_packets or [])

        if controller_pkts:
            f.write("| Packet # | Timestamp | Source | Destination | Protocol | Info |\n")
            f.write("|----------|-----------|--------|-------------|----------|------|\n")
            for pkt in controller_pkts:
                f.write(f"| {pkt.packet_number} | {pkt.timestamp} | {pkt.src} | ")
                f.write(f"{pkt.dst} | {pkt.protocol} | {pkt.info} |\n")
            f.write("\n")
        else:
            f.write("*No controller PCAP packets found*\n\n")
        
        # DUT PCAP
        f.write("### DUT PCAP Packets\n\n")

        # Prefer the message-id based mapping (built via tshark) since the older
        # time-window packet list is just a placeholder.
        dut_pkts: List[PcapPacket] = []
        if message.dut_pcap_by_message_id:
            seen = set()
            for pkts in message.dut_pcap_by_message_id.values():
                for pkt in pkts:
                    if pkt.packet_number in seen:
                        continue
                    seen.add(pkt.packet_number)
                    dut_pkts.append(pkt)
            dut_pkts.sort(key=lambda p: p.packet_number)
        else:
            dut_pkts = list(message.dut_pcap_packets or [])

        if dut_pkts:
            f.write("| Packet # | Timestamp | Source | Destination | Protocol | Info |\n")
            f.write("|----------|-----------|--------|-------------|----------|------|\n")
            for pkt in dut_pkts:
                f.write(f"| {pkt.packet_number} | {pkt.timestamp} | {pkt.src} | ")
                f.write(f"{pkt.dst} | {pkt.protocol} | {pkt.info} |\n")
            f.write("\n")
        else:
            f.write("*No DUT PCAP packets found*\n\n")
        
        f.write("---\n\n")


def main():
    """Main entry point"""
    import argparse
    import os
    import json
    
    parser = argparse.ArgumentParser(
        description=(
            'Analyze Matter controller and DUT logs with PCAP files.\n\n'
            'Modes:\n'
            '  1) Iteration directory mode: analyze exactly one iteration dir and always (re)generate the report.\n'
            '  2) Summary mode: point at a MatterTest summary.json to generate reports for failed iterations only.\n'
            '     In summary mode, existing per-iteration reports are skipped unless --force is provided.'
        )
    )

    parser.add_argument(
        'input_path',
        nargs='?',
        help=(
            'Optional input path. If this points to a file named summary.json, the script runs in summary mode. '
            'Otherwise, if it is a directory, it is treated like --iteration-dir.'
        ),
    )
    parser.add_argument(
        '--iteration-dir',
        help=(
            'Path to a MatterTest iteration directory (e.g. '
            'logs/.../<testcase>/<iteration>/). When provided, the script will '
            'auto-detect controller/DUT log + pcap files inside it and write an '
            'output report named with the iteration number (no timestamps).'
        )
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help=(
            'Summary mode only: regenerate per-iteration reports even if the expected '
            'traffic_report_iteration_<n>.md already exists.'
        ),
    )
    parser.add_argument(
        '--controller-log',
        help='Path to controller log file'
    )
    parser.add_argument(
        '--dut-log',
        help='Path to DUT log file'
    )
    parser.add_argument(
        '--controller-pcap',
        help='Path to controller PCAP file (optional)'
    )
    parser.add_argument(
        '--dut-pcap',
        help='Path to DUT PCAP file (optional)'
    )
    parser.add_argument(
        '--output',
        help='Output markdown file (default depends on mode)'
    )
    
    args = parser.parse_args()

    # Positional input is a convenience alias:
    # - summary.json => summary mode
    # - directory => iteration-dir mode
    if args.input_path and not args.iteration_dir:
        p = Path(args.input_path).expanduser().resolve()
        if p.is_file() and p.name == 'summary.json':
            # handled later
            pass
        elif p.is_dir():
            args.iteration_dir = str(p)
        else:
            parser.error(
                f"input_path must be an iteration directory or a summary.json file. Got: {p}"
            )

    def _detect_iteration_inputs(iteration_dir: str) -> Dict[str, Optional[str]]:
        """Detect input files inside an iteration directory.

        Expected filenames include timestamps, and log filenames include the iteration number.
        Output is stable: we generate a report that includes the iteration number only.
        """
        p = Path(iteration_dir).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            raise FileNotFoundError(f"Iteration dir not found or not a directory: {iteration_dir}")

        iteration = p.name
        if not iteration.isdigit():
            raise ValueError(
                f"Iteration dir must end with an integer directory name (e.g. .../208). Got: {p}"
            )

        # Prefer the most recently modified matching file if multiple exist.
        def pick_latest(pattern: str) -> Optional[str]:
            matches = list(p.glob(pattern))
            matches = [m for m in matches if m.is_file()]
            if not matches:
                return None
            matches.sort(key=lambda m: m.stat().st_mtime)
            return str(matches[-1])

        controller_log = pick_latest(f"controller_log_iteration_{iteration}_*.log")
        dut_log = pick_latest(f"Dut_log_iteration_{iteration}_*.log")

        # Your example iteration dir has only controller tcpdump pcaps.
        controller_pcap = pick_latest("controller_tcpdump_*.pcap")
        dut_pcap = pick_latest("dut_tcpdump_*.pcap")
        if dut_pcap is None:
            # some setups use dut_tcpdump / DUT_tcpdump naming, try a couple variants
            dut_pcap = pick_latest("Dut_tcpdump_*.pcap") or pick_latest("DUT_tcpdump_*.pcap")
        if dut_pcap is None:
            # common: DUT capture is named with a device prefix and bzip2-compressed
            dut_pcap = pick_latest("RPI-DUT_tcpdump_*.pcap") or pick_latest("RPI-DUT_tcpdump_*.pcap.bz2")
        if dut_pcap is None:
            # generic: any *DUT* tcpdump pcap (including compressed)
            dut_pcap = pick_latest("*DUT*_tcpdump_*.pcap") or pick_latest("*DUT*_tcpdump_*.pcap.bz2")

        output = args.output
        if not output:
            # Put the report next to the iteration data, stable name.
            output = str(p / f"traffic_report_iteration_{iteration}.md")

        return {
            "iteration": iteration,
            "iteration_dir": str(p),
            "controller_log": controller_log,
            "dut_log": dut_log,
            "controller_pcap": controller_pcap,
            "dut_pcap": dut_pcap,
            "output": output,
        }

    def _failed_iteration_dirs_from_summary(summary_path: str) -> List[Path]:
        """Return iteration directories for iterations listed in summary.json's list_of_iterations_failed."""
        sp = Path(summary_path).expanduser().resolve()
        if not sp.exists() or not sp.is_file():
            raise FileNotFoundError(f"summary.json not found: {summary_path}")

        with open(sp, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        try:
            failed = data['test_summary_record']['list_of_iterations_failed']
        except Exception as e:
            raise ValueError(
                'summary.json missing test_summary_record.list_of_iterations_failed'
            ) from e

        if not isinstance(failed, list):
            raise ValueError('summary.json list_of_iterations_failed is not a list')

        # summary.json lives in .../<testcase>/summary.json, and iteration dirs are siblings
        base = sp.parent
        out: List[Path] = []
        for it in failed:
            it_str = str(it)
            if not it_str.isdigit():
                continue
            d = base / it_str
            if d.exists() and d.is_dir():
                out.append(d)
            else:
                print(f"Warning: failed iteration directory not found: {d}")
        return out

    def _run_single_iteration(iter_dir: str, *, allow_skip_if_report_exists: bool) -> int:
        """Run analyzer for one iteration directory.

        Returns 0 on success, non-zero on failure.
        """
        detected_local = _detect_iteration_inputs(iter_dir)
        controller_log = detected_local["controller_log"]
        dut_log = detected_local["dut_log"]
        if not controller_log or not dut_log:
            print(
                f"Warning: could not auto-detect required logs in {detected_local['iteration_dir']} "
                f"(controller_log={controller_log}, dut_log={dut_log}); skipping."
            )
            return 2

        output_path = Path(detected_local['output'])
        if allow_skip_if_report_exists and output_path.exists() and not args.force:
            print(f"Skipping (report exists): {output_path}")
            return 0

        print("Matter Traffic Analyzer")
        print("=" * 50)
        print(f"Iteration dir: {detected_local['iteration_dir']}")
        print(f"Iteration: {detected_local['iteration']}")
        print(f"Controller log: {controller_log}")
        print(f"DUT log: {dut_log}")
        print(f"Controller PCAP: {detected_local['controller_pcap'] or 'N/A'}")
        print(f"DUT PCAP: {detected_local['dut_pcap'] or 'N/A'}")
        print(f"Output file: {detected_local['output']}")
        print("=" * 50)

        # Parse logs
        print("\nParsing controller log...")
        controller_logs = LogParser.parse_log_file(controller_log)
        print(f"Found {len(controller_logs)} relevant controller log entries")

        print("\nParsing DUT log...")
        dut_logs = LogParser.parse_log_file(dut_log)
        print(f"Found {len(dut_logs)} relevant DUT log entries")

        # Parse PCAP files
        controller_pcap = []
        dut_pcap = []
        controller_pcap_index = {}
        dut_pcap_index = {}

        if detected_local['controller_pcap']:
            print("\nParsing controller PCAP...")
            controller_pcap = PcapParser.parse_pcap_file(detected_local['controller_pcap'])
            controller_pcap_index = PcapParser.build_message_id_index(detected_local['controller_pcap'])
            print(f"Found {len(controller_pcap)} controller packets")

        if detected_local['dut_pcap']:
            print("\nParsing DUT PCAP...")
            dut_pcap = PcapParser.parse_pcap_file(detected_local['dut_pcap'])
            dut_pcap_index = PcapParser.build_message_id_index(detected_local['dut_pcap'])
            print(f"Found {len(dut_pcap)} DUT packets")

        # Correlate messages
        print("\nCorrelating messages...")
        messages = MessageCorrelator.correlate_messages(
            controller_logs,
            dut_logs,
            controller_pcap,
            dut_pcap,
        )

        # Attach the pcap indexes so the report can show per-message-id packet mapping.
        for m in messages:
            all_mids = set(m.controller_message_ids.keys()) | set(m.dut_message_ids.keys())
            for mid in sorted(all_mids):
                if mid in controller_pcap_index:
                    m.controller_pcap_by_message_id[mid] = controller_pcap_index[mid]
                if mid in dut_pcap_index:
                    m.dut_pcap_by_message_id[mid] = dut_pcap_index[mid]
        print(f"Identified {len(messages)} messages")

        # Generate report
        print(f"\nGenerating report: {detected_local['output']}")
        ReportGenerator.generate_report(messages, detected_local['output'])
        print("\nAnalysis complete!")
        return 0

    # Summary mode: input_path points to summary.json
    if args.input_path and Path(args.input_path).expanduser().resolve().is_file() and Path(args.input_path).name == 'summary.json':
        summary_path = str(Path(args.input_path).expanduser().resolve())
        it_dirs = _failed_iteration_dirs_from_summary(summary_path)
        if not it_dirs:
            print("No failed iterations found (or their directories are missing).")
            return 0

        print(f"Summary mode: {summary_path}")
        print(f"Failed iterations: {', '.join([d.name for d in it_dirs])}")

        # In summary mode we skip existing reports unless --force.
        rc = 0
        for d in it_dirs:
            r = _run_single_iteration(str(d), allow_skip_if_report_exists=True)
            if r != 0:
                rc = r
        return rc

    # Iteration-dir mode
    if args.iteration_dir:
        # Per requirement: when given an iteration directory, always (re)generate the report.
        return _run_single_iteration(args.iteration_dir, allow_skip_if_report_exists=False)

    # Manual file mode (explicit logs)
    if not args.controller_log or not args.dut_log:
        parser.error(
            'Missing required inputs. Provide --controller-log and --dut-log, '
            'or provide --iteration-dir, or pass a summary.json as input_path.'
        )

    # Make output deterministic in manual mode.
    if not args.output:
        args.output = 'traffic_analysis.md'

    # Reuse the single-iteration runner logic by treating manual inputs as a one-off.
    print("Matter Traffic Analyzer")
    print("=" * 50)
    print(f"Controller log: {args.controller_log}")
    print(f"DUT log: {args.dut_log}")
    print(f"Controller PCAP: {args.controller_pcap or 'N/A'}")
    print(f"DUT PCAP: {args.dut_pcap or 'N/A'}")
    print(f"Output file: {args.output}")
    print("=" * 50)

    print("\nParsing controller log...")
    controller_logs = LogParser.parse_log_file(args.controller_log)
    print(f"Found {len(controller_logs)} relevant controller log entries")

    print("\nParsing DUT log...")
    dut_logs = LogParser.parse_log_file(args.dut_log)
    print(f"Found {len(dut_logs)} relevant DUT log entries")

    controller_pcap = []
    dut_pcap = []
    controller_pcap_index = {}
    dut_pcap_index = {}

    if args.controller_pcap:
        print("\nParsing controller PCAP...")
        controller_pcap = PcapParser.parse_pcap_file(args.controller_pcap)
        controller_pcap_index = PcapParser.build_message_id_index(args.controller_pcap)
        print(f"Found {len(controller_pcap)} controller packets")

    if args.dut_pcap:
        print("\nParsing DUT PCAP...")
        dut_pcap = PcapParser.parse_pcap_file(args.dut_pcap)
        dut_pcap_index = PcapParser.build_message_id_index(args.dut_pcap)
        print(f"Found {len(dut_pcap)} DUT packets")

    print("\nCorrelating messages...")
    messages = MessageCorrelator.correlate_messages(
        controller_logs,
        dut_logs,
        controller_pcap,
        dut_pcap,
    )
    for m in messages:
        all_mids = set(m.controller_message_ids.keys()) | set(m.dut_message_ids.keys())
        for mid in sorted(all_mids):
            if mid in controller_pcap_index:
                m.controller_pcap_by_message_id[mid] = controller_pcap_index[mid]
            if mid in dut_pcap_index:
                m.dut_pcap_by_message_id[mid] = dut_pcap_index[mid]
    print(f"Identified {len(messages)} messages")

    print(f"\nGenerating report: {args.output}")
    ReportGenerator.generate_report(messages, args.output)
    print("\nAnalysis complete!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
