# Matter Log and Traffic Analyzer

A tool for analyzing Matter controller and DUT (Device Under Test) logs along with PCAP files to create a structured representation of network traffic.

## Overview

This tool reads logs from a Matter controller and DUT, correlates messages between them, and generates a comprehensive markdown report showing:
- Message exchanges between controller and DUT
- Log entries for sent/received messages
- ACK (acknowledgment) messages
- Related PCAP packets (when PCAP files are provided)

It also produces a per-iteration **timeline** report that normalizes timestamps across controller/DUT logs and PCAPs into a single unified timeline (controller-console time).

## Features

- **Log Parsing**: Extracts relevant message entries from controller and DUT logs
- **Message Correlation**: Matches messages across controller and DUT using exchange IDs and message counters
- **ACK Tracking**: Identifies acknowledgment messages for each data message
- **PCAP Integration**: Correlates log entries with network packets from PCAP files
- **Markdown Reports**: Generates structured, human-readable reports with sections per message
- **JSON Artifacts**: Emits machine-readable JSON outputs alongside the markdown reports
- **Timeline (MD + JSON)**: Emits `timeline_<iteration>.md/.json` with all timestamps normalized to controller-console time

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

### Analyze a MatterTest iteration directory (auto-detect inputs)

If your logs are stored as per-iteration folders (integer directory names) containing
timestamped filenames (for example: `controller_log_iteration_208_...`), you can point
the analyzer at the iteration directory and it will auto-detect the log/pcap files.

The generated report filename will include the iteration number but **not** a timestamp.

```bash
python analyze_traffic.py \
    --iteration-dir logs/MatterTest/ble-wifi/<timestamp>/<testcase>/<iteration>/
```

Artifacts written into the iteration directory:

- `traffic_report_<iteration>.md`
- `traffic_report_<iteration>.json`
- `timeline_<iteration>.md`
- `timeline_<iteration>.json`
- `time_offsets_<iteration>.json` (diagnostics for the offset computation)

### Analyze all failed iterations from a MatterTest `summary.json`

If you pass a `summary.json` (like the one produced by the stress/reliability harness),
the script will read `test_summary_record.list_of_iterations_failed` and generate a
per-iteration report for **each failed iteration**.

In this mode, it will **skip** work for an iteration if the expected report filename
already exists in that iteration directory, unless you pass `--force`.

```bash
python analyze_traffic.py logs/MatterTest/ble-wifi/<timestamp>/<testcase>/summary.json
```

Force regeneration of all failed-iteration reports:

```bash
python analyze_traffic.py \
        --force \
        logs/MatterTest/ble-wifi/<timestamp>/<testcase>/summary.json
```

Notes:
- This mode uses the report naming convention `traffic_report_<n>.md` inside each iteration directory
    (and also writes `traffic_report_<n>.json`).
- In contrast, when you analyze a single iteration directory via `--iteration-dir`, the
    script always regenerates the report (it does not skip if one already exists).

### Basic Usage (Logs Only)

```bash
python analyze_traffic.py \
    --controller-log examples/controller.log \
    --dut-log examples/dut.log \
    --output traffic_report.md
```

This produces both:

- `traffic_report.md`
- `traffic_report.json`

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
- `--force`: Summary mode only: regenerate per-iteration reports even if they already exist

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

## Timeline output (new)

When running in iteration-dir mode or summary mode, the tool also generates a timeline:

- `timeline_<iteration>.md`
- `timeline_<iteration>.json`

The timeline is organized by **exchange**, and within an exchange by **message counter** (one section per message counter).

### Timestamp alignment behavior (B2 pragmatic)

The analyzer chooses constant time offsets using robust statistics (medians) plus a small local search.
If ordering invariants are violated (best-violation count is non-zero), it is **not fatal**: the timeline is still emitted, and a loud **Violations summary** section is included in the timeline MD/JSON.
For deeper debugging, inspect `time_offsets_<iteration>.json`.

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
- `tshark` (Wireshark CLI) for PCAP parsing/decryption

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.