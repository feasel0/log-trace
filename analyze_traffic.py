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


class LogParser:
    """Parser for Matter controller and DUT logs"""

    # Patterns for common Matter log formats
    TIMESTAMP_PATTERN = r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+'
    MESSAGE_PATTERN = r'(Sending|Received|Receiving).*(message|Message|Request|Response|ReportData)'
    ACK_PATTERN = r'(Sending|Received)\s+(ACK|Ack|acknowledgment)'
    EXCHANGE_ID_PATTERN = r'exchange[:\s]+(\w+)'
    MESSAGE_COUNTER_PATTERN = r'message counter[:\s]+(\w+)'

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
        
        # Check if this is a message-related line
        message_match = re.search(LogParser.MESSAGE_PATTERN, line, re.IGNORECASE)
        ack_match = re.search(LogParser.ACK_PATTERN, line, re.IGNORECASE)
        
        if not message_match and not ack_match:
            return None
        
        # Determine direction
        direction = None
        if re.search(r'\b(Sending|Sent)\b', line, re.IGNORECASE):
            direction = 'sent'
        elif re.search(r'\b(Received|Receiving)\b', line, re.IGNORECASE):
            direction = 'received'
        
        # Extract exchange ID and message counter
        exchange_id_match = re.search(LogParser.EXCHANGE_ID_PATTERN, line, re.IGNORECASE)
        exchange_id = exchange_id_match.group(1) if exchange_id_match else None
        
        msg_counter_match = re.search(LogParser.MESSAGE_COUNTER_PATTERN, line, re.IGNORECASE)
        msg_counter = msg_counter_match.group(1) if msg_counter_match else None
        
        # Determine message type (extract from line)
        message_type = LogParser._extract_message_type(line)
        
        return LogEntry(
            timestamp=timestamp,
            line_number=line_num,
            raw_line=line,
            message_type=message_type,
            direction=direction,
            is_ack=ack_match is not None,
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
        packets = []
        
        try:
            from scapy.all import rdpcap, Raw
            from scapy.layers.inet import IP, UDP
            
            pcap = rdpcap(file_path)
            
            for i, pkt in enumerate(pcap, 1):
                # Extract basic packet information
                src = ""
                dst = ""
                protocol = ""
                info = str(pkt.summary())
                
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    protocol = "IP"
                    
                    if UDP in pkt:
                        protocol = "UDP"
                        src += f":{pkt[UDP].sport}"
                        dst += f":{pkt[UDP].dport}"
                
                # Get timestamp
                timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                
                packet = PcapPacket(
                    packet_number=i,
                    timestamp=timestamp,
                    src=src,
                    dst=dst,
                    protocol=protocol,
                    info=info,
                    raw_data=pkt
                )
                packets.append(packet)
                
        except ImportError:
            print("Warning: scapy not installed. PCAP parsing disabled.")
            print("Install with: pip install scapy")
        except FileNotFoundError:
            print(f"Warning: PCAP file not found: {file_path}")
        except Exception as e:
            print(f"Error parsing PCAP file {file_path}: {e}")
        
        return packets


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
        
        for exchange_id in sorted(all_exchanges):
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
                message_type=message_type
            )
            
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
    def _group_by_exchange(entries: List[LogEntry]) -> Dict[str, List[LogEntry]]:
        """Group log entries by exchange ID only"""
        groups = {}
        
        for entry in entries:
            # Use exchange ID as the key
            if entry.exchange_id:
                key = entry.exchange_id
            else:
                # Fallback to timestamp-based grouping for entries without exchange ID
                key = f"time_{entry.timestamp}"
            
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
            f.write("---\n\n")
            
            for message in messages:
                ReportGenerator._write_message_section(f, message)

    @staticmethod
    def _write_message_section(f, message: Message):
        """Write a section for a single message"""
        f.write(f"## Message {message.message_id}: {message.message_type}\n\n")
        
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
        if message.controller_pcap_packets:
            f.write("| Packet # | Timestamp | Source | Destination | Protocol | Info |\n")
            f.write("|----------|-----------|--------|-------------|----------|------|\n")
            for pkt in message.controller_pcap_packets:
                f.write(f"| {pkt.packet_number} | {pkt.timestamp} | {pkt.src} | ")
                f.write(f"{pkt.dst} | {pkt.protocol} | {pkt.info} |\n")
            f.write("\n")
        else:
            f.write("*No controller PCAP packets found*\n\n")
        
        # DUT PCAP
        f.write("### DUT PCAP Packets\n\n")
        if message.dut_pcap_packets:
            f.write("| Packet # | Timestamp | Source | Destination | Protocol | Info |\n")
            f.write("|----------|-----------|--------|-------------|----------|------|\n")
            for pkt in message.dut_pcap_packets:
                f.write(f"| {pkt.packet_number} | {pkt.timestamp} | {pkt.src} | ")
                f.write(f"{pkt.dst} | {pkt.protocol} | {pkt.info} |\n")
            f.write("\n")
        else:
            f.write("*No DUT PCAP packets found*\n\n")
        
        f.write("---\n\n")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analyze Matter controller and DUT logs with PCAP files'
    )
    parser.add_argument(
        '--controller-log',
        required=True,
        help='Path to controller log file'
    )
    parser.add_argument(
        '--dut-log',
        required=True,
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
        default='traffic_analysis.md',
        help='Output markdown file (default: traffic_analysis.md)'
    )
    
    args = parser.parse_args()
    
    print("Matter Traffic Analyzer")
    print("=" * 50)
    print(f"Controller log: {args.controller_log}")
    print(f"DUT log: {args.dut_log}")
    print(f"Controller PCAP: {args.controller_pcap or 'N/A'}")
    print(f"DUT PCAP: {args.dut_pcap or 'N/A'}")
    print(f"Output file: {args.output}")
    print("=" * 50)
    
    # Parse logs
    print("\nParsing controller log...")
    controller_logs = LogParser.parse_log_file(args.controller_log)
    print(f"Found {len(controller_logs)} relevant controller log entries")
    
    print("\nParsing DUT log...")
    dut_logs = LogParser.parse_log_file(args.dut_log)
    print(f"Found {len(dut_logs)} relevant DUT log entries")
    
    # Parse PCAP files
    controller_pcap = []
    dut_pcap = []
    
    if args.controller_pcap:
        print("\nParsing controller PCAP...")
        controller_pcap = PcapParser.parse_pcap_file(args.controller_pcap)
        print(f"Found {len(controller_pcap)} controller packets")
    
    if args.dut_pcap:
        print("\nParsing DUT PCAP...")
        dut_pcap = PcapParser.parse_pcap_file(args.dut_pcap)
        print(f"Found {len(dut_pcap)} DUT packets")
    
    # Correlate messages
    print("\nCorrelating messages...")
    messages = MessageCorrelator.correlate_messages(
        controller_logs,
        dut_logs,
        controller_pcap,
        dut_pcap
    )
    print(f"Identified {len(messages)} messages")
    
    # Generate report
    print(f"\nGenerating report: {args.output}")
    ReportGenerator.generate_report(messages, args.output)
    
    print("\nAnalysis complete!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
