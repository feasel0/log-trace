# Matter Log and Traffic Analyzer

A tool for analyzing Matter controller and DUT (Device Under Test) logs along with PCAP files to create a structured representation of network traffic.

## Overview

This tool reads logs from a Matter controller and DUT, correlates messages between them, and generates a comprehensive markdown report showing:
- Message exchanges between controller and DUT
- Log entries for sent/received messages
- ACK (acknowledgment) messages
- Related PCAP packets (when PCAP files are provided)

## Features

- **Log Parsing**: Extracts relevant message entries from controller and DUT logs
- **Message Correlation**: Matches messages across controller and DUT using exchange IDs and message counters
- **ACK Tracking**: Identifies acknowledgment messages for each data message
- **PCAP Integration**: Correlates log entries with network packets from PCAP files
- **Markdown Reports**: Generates structured, human-readable reports with sections per message

## Installation

1. Clone the repository:
```bash
git clone https://github.com/feasel0/log-trace.git
cd log-trace
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage (Logs Only)

```bash
python analyze_traffic.py \
    --controller-log examples/controller.log \
    --dut-log examples/dut.log \
    --output traffic_report.md
```

### With PCAP Files

```bash
python analyze_traffic.py \
    --controller-log examples/controller.log \
    --dut-log examples/dut.log \
    --controller-pcap examples/controller.pcap \
    --dut-pcap examples/dut.pcap \
    --output traffic_report.md
```

### Command-Line Arguments

- `--controller-log`: Path to the controller log file (required)
- `--dut-log`: Path to the DUT log file (required)
- `--controller-pcap`: Path to the controller PCAP file (optional)
- `--dut-pcap`: Path to the DUT PCAP file (optional)
- `--output`: Output markdown file path (default: traffic_analysis.md)

## Log Format

The tool expects logs with timestamps and message information. Example format:

```
2026-01-30 10:15:25,789 [DEBUG] Sending message InvokeRequest to device, exchange: 0x1234, message counter: 1001
2026-01-30 10:15:26,100 [DEBUG] Received ACK from device, exchange: 0x1234, message counter: 1001
```

### Recognized Patterns

The parser looks for:
- **Timestamps**: Standard date-time formats (YYYY-MM-DD HH:MM:SS.mmm)
- **Message indicators**: "Sending message", "Received message", "Sending", "Received"
- **ACK indicators**: "ACK", "Ack", "acknowledgment"
- **Exchange IDs**: "exchange: <id>"
- **Message counters**: "message counter: <number>"
- **Message types**: InvokeRequest, InvokeResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse, SubscribeRequest, SubscribeResponse, ReportData, etc.

## Output Format

The tool generates a markdown report with the following structure:

```markdown
# Matter Traffic Analysis Report

## Message 1: InvokeRequest

### Controller Logs
**Message Sent:**
- Line 3: `2026-01-30 10:15:25,789 [DEBUG] Sending message InvokeRequest...`

**ACK Received:**
- Line 5: `2026-01-30 10:15:26,100 [DEBUG] Received ACK from device...`

### DUT Logs
**Message Received:**
- Line 3: `2026-01-30 10:15:25,800 [DEBUG] Received InvokeRequest message...`

**ACK Sent:**
- Line 4: `2026-01-30 10:15:25,850 [DEBUG] Sending ACK to controller...`

### Controller PCAP Packets
| Packet # | Timestamp | Source | Destination | Protocol | Info |
|----------|-----------|--------|-------------|----------|------|
| ... | ... | ... | ... | ... | ... |

### DUT PCAP Packets
| Packet # | Timestamp | Source | Destination | Protocol | Info |
|----------|-----------|--------|-------------|----------|------|
| ... | ... | ... | ... | ... | ... |
```

## Examples

Sample log files are provided in the `examples/` directory:
- `examples/controller.log`: Sample Matter controller log
- `examples/dut.log`: Sample DUT log

Run the example:
```bash
python analyze_traffic.py \
    --controller-log examples/controller.log \
    --dut-log examples/dut.log \
    --output example_report.md
```

## Architecture

The tool consists of several components:

1. **LogParser**: Parses controller and DUT log files, extracting relevant message entries
2. **PcapParser**: Parses PCAP files using Scapy to extract packet information
3. **MessageCorrelator**: Correlates messages across logs and PCAP files using exchange IDs, message counters, and timestamps
4. **ReportGenerator**: Generates structured markdown reports from correlated messages

### Known Limitations

- **PCAP Correlation**: The current implementation uses a simplified packet correlation mechanism. In a production environment, this should be enhanced with more sophisticated matching based on timestamps, IP addresses, and protocol-specific information.
- **Exchange ID Reuse**: The tool groups messages by exchange ID. If exchange IDs are reused over time, older messages with the same exchange ID may be grouped together. Consider the time window when analyzing large log files.
- **Error Handling**: Parsing errors are reported as warnings but don't stop execution. Missing or malformed files will result in empty sections in the report.

## Requirements

- Python 3.7 or higher
- scapy (for PCAP parsing)

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.