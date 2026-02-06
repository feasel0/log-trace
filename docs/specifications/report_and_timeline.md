# Traffic report + timeline specification (no state machine yet)

This document defines the current scope of this repository: given a MatterTest iteration directory (or a MatterTest `summary.json`), generate **traffic report** and **timeline** artifacts for each iteration.

This spec is intended to be detailed enough that an automated coding agent could recreate this tool from scratch.

## Goals / non-goals

### Goals

For each analyzed iteration directory, generate these derived artifacts **into the iteration directory**:

- `traffic_report_<iteration>.md` — human-readable traffic report
- `traffic_report_<iteration>.json` — machine-readable traffic report
- `timeline_<iteration>.md` — human-readable timeline, normalized to controller-console time
- `timeline_<iteration>.json` — machine-readable timeline, normalized to controller-console time
- `time_offsets_<iteration>.json` — time alignment diagnostics (inputs, medians, search results, violation counts)

Also support running over `summary.json` and generating reports for all failed iterations.

### Non-goals (for now)

- No deterministic state machine model.
- No “account for every line” checking.
- No training or comparison vs. ideal behavior.

## Inputs

An iteration directory has this general layout:

```
logs/MatterTest/<comm_method>/<timestamp>/<test_case>/<iteration>/
```

Where `<iteration>` is a directory name that is an integer, e.g. `208`.

Inside the iteration directory, the tool expects files with names that include timestamps. The tool must **auto-detect** the newest matching file for each category.

### Required inputs

- Controller console log: `controller_log_iteration_<iteration>_*.log`
- DUT console log: `Dut_log_iteration_<iteration>_*.log`

### Optional inputs

- Controller pcap: `controller_tcpdump_*.pcap`
- DUT pcap: several common patterns, choose the newest that exists:
  - `dut_tcpdump_*.pcap`
  - `Dut_tcpdump_*.pcap` / `DUT_tcpdump_*.pcap`
  - `RPI-DUT_tcpdump_*.pcap` or `RPI-DUT_tcpdump_*.pcap.bz2`
  - fallback glob: `*DUT*_tcpdump_*.pcap` or `*DUT*_tcpdump_*.pcap.bz2`

#### Compressed DUT pcap

If the DUT pcap ends with `.bz2`, the tool must decompress it before running tshark.

(Implementation note: streaming is preferred, but writing to a temporary file is acceptable for v1 as long as it works.)

## Running modes

The CLI supports 3 ways to run:

1) **Iteration directory mode**

- User passes `--iteration-dir <path>`
- The tool analyzes exactly that iteration and always overwrites the derived artifacts.

2) **Summary mode**

- User passes a positional `input_path` that is a file named `summary.json`
- The tool reads `test_summary_record.list_of_iterations_failed` from that file
- For each failed iteration directory (sibling `<iteration>` directories), generate artifacts
- In summary mode, the tool may skip work for an iteration if both:
  - `traffic_report_<iteration>.md` exists
  - `traffic_report_<iteration>.json` exists
  Unless `--force` is provided.

3) **Manual file mode**

- User passes explicit `--controller-log` and `--dut-log`
- Optional: explicit `--controller-pcap` and `--dut-pcap`
- Output is controlled by `--output <markdown_path>`
- In this mode, create:
  - `<output>.md` (the provided `--output` file)
  - `<output>.json` (same path but `.json` extension)

Timeline generation is not required in manual mode.

## Parsing console logs

### Supported log timestamp formats

The tool must extract a timestamp string from each relevant line. Two timestamp styles are supported:

- Controller log timestamp (Python logging style):
  - `YYYY-MM-DD HH:MM:SS,mmm` (comma) or `YYYY-MM-DD HH:MM:SS.mmm` (dot)
- DUT log timestamp (monotonic/epoch style):
  - `[<seconds>.<fraction>]` e.g. `[1769806702.974]`

### Relevant line selection: Matter EM lines

We only extract traffic lines that reference Matter EM messages.

A relevant EM line must contain:

- A marker like `[EM]` or `matter.native.EM`
- Direction arrows:
  - `<<<` means **sent** (console observed an outgoing message)
  - `>>>` means **received** (console observed an incoming message)
- An exchange id token: `E:<digits><i|r>`
  - Store exchange_id = the digits
- A message counter token: `M:<digits>`
- A type token:
  - `Type ####:## (SomeProto:SomeMessageName)`
  - Store message_type = `SomeMessageName` (strip the `Proto:` prefix)

ACK detection:

- Consider line an ACK if:
  - the type contains `StandaloneAck`, OR
  - line contains an explicit `Ack:<digits>` field, OR
  - line contains text `ACK` (fallback)

### Fallback “simple” log pattern

Some examples/tests use a simplified format like:

- `Sending message InvokeRequest ... exchange: 0x1234 ... message counter: 1001`

The tool may support this as a fallback parser.

## Parsing pcaps

PCAP parsing uses **tshark** and assumes a Wireshark profile exists named `matter-devkeys` to decrypt Matter traffic.

### Packet extraction

The tool must produce a list of packet summaries with fields:

- packet number
- epoch timestamp
- src ip(+port)
- dst ip(+port)
- protocol
- info string

### Message-counter index

The tool must build a mapping:

- `message_counter -> list[pkt]`

Strategy:

- Run tshark with a display filter `udp.port==5540`
- Parse `_ws.col.Info` for:
  - `MsgCntr=<8-hex-digits>`
  - optionally `AckMsgCntr=<8-hex-digits>`
- Convert hex message counter to **decimal string** to match console logs.
- Index the packet by MsgCntr.
- Also index the packet by AckMsgCntr (so that standalone ACK packets can be found when correlating the acked message id).

If `MsgCntr=` is missing, a conservative fallback may collect any 8-hex-digit tokens from Info and index those as candidates.

## Correlation model

The tool produces a list of `Message` objects, but **in this repository’s current code** a `Message` is effectively “one exchange section” (grouped by exchange id), not a strict single message-counter.

Required correlation behavior for v1:

- Group console log entries by `exchange_id`
- For each exchange:
  - compute an exchange-level `message_type` as the first observed non-ACK message_type
  - compute per-exchange message-counter inventories:
    - `controller_message_ids: message_counter -> list[line_number]`
    - `dut_message_ids: message_counter -> list[line_number]`
  - attach pcap index matches:
    - `controller_pcap_by_message_id: message_counter -> list[pkt]`
    - `dut_pcap_by_message_id: message_counter -> list[pkt]`

## Traffic report outputs

### `traffic_report_<iteration>.md`

A human-readable report. Minimum sections:

- Header with generation time and total exchange count
- A “visibility summary” showing which message counters are visible in each source
- Then per exchange:
  - exchange header: exchange id + inferred exchange message type
  - table listing message counters and where they appear (controller log lines, dut log lines, controller pcap pkt@time, dut pcap pkt@time)
  - raw evidence excerpts for controller logs, dut logs
  - packet tables for controller pcap and dut pcap

### `traffic_report_<iteration>.json`

A machine-readable serialization of the correlation output.

Top-level keys:

- `generated`: timestamp string
- `version`: integer
- `total_messages`: integer (exchange count)
- `messages`: list of exchange records

Each exchange record must include:

- `message_id` (monotonic integer)
- `message_type`
- `exchange_id`
- `controller_message_ids` and `dut_message_ids`
- `controller_pcap_by_message_id` and `dut_pcap_by_message_id` lists of packets
- optional anchor entries (`controller_sent`, `controller_received`, etc.) if available

## Unified time alignment (B2 pragmatic)

### Goal

Normalize all timestamps used in the timeline to a single timebase: **controller console time**.

### Model

Use constant offsets (no drift model in v1):

- Controller pcap → controller console
- DUT pcap → DUT console
- DUT console → controller console

### Robust estimation + refinement

For each offset stage, compute an initial estimate using medians of correspondence diffs, then refine by searching a window around the estimate and counting violations.

The tool must then **choose the offset with the minimum violations**.

### Invariants (ordering constraints)

Device-local (console vs its own pcap):

- Incoming messages (remote → this device): pcap observe time should be **before** console time
- Outgoing messages (this device → remote): console time should be **before** pcap observe time

Cross-device (controller console vs DUT console):

- Controller → DUT: controller log should be **before** DUT log (after applying DUT→controller offset)
- DUT → controller: DUT log should be **before** controller log

### Pragmatic behavior

Even if the minimum-violation offset has non-zero violations:

- The tool must still emit the timeline
- The tool must emit a loud “violations summary” in the timeline outputs
- The tool must write a detailed diagnostics file `time_offsets_<iteration>.json`

## Timeline outputs

### Structure (A1 granularity)

Timeline is organized as:

- One `##` section per exchange
- Within each exchange, one `###` section per **message counter** (Matter `M:<id>`)

### Required content per timeline message-counter section

For each message counter `M:<id>` that appears in the exchange, emit:

- Direction (`Cont → DUT` or `DUT → Cont`) inferred from which side logged it and the `<<<`/`>>>` arrow
- Type (best available `message_type`)
- Message counter
- A normalized “Timestamp” field (controller-console time), typically the earliest evidence timestamp
- Evidence blocks (each is a header line + optional indented bullets for retries/additional evidence):
  - Controller log lines for that `M:<id>`
  - Controller pcap packets for that `M:<id>`
  - DUT pcap packets for that `M:<id>`
  - DUT log lines for that `M:<id>`

All timestamps printed in the timeline must be controller-console time.

### `timeline_<iteration>.json`

Top-level keys:

- `iteration`
- `generated`
- `timebase`: `controller_console`
- `offsets`: numeric offsets used
- `violations_summary`: object (see below)
- `exchanges`: list

Each exchange has:

- `exchange_id`
- `messages`: list of per-message-counter records

Each per-message-counter record has:

- `index` (1-based numbering within the exchange)
- `message_counter`
- `exchange_id`
- `direction`
- `type`
- `timestamp_controller` (string)
- `evidence`:
  - `controller_log`, `dut_log`, `controller_pcap`, `dut_pcap` arrays, each containing timestamp-normalized evidence objects

### Violations summary

Both timeline MD and JSON must include a violations summary section/object with:

- `controller_console_to_pcap.best_offset`, `best_violations`
- `dut_console_to_pcap.best_offset`, `best_violations`
- `controller_vs_dut.best_offset`, `best_violations`
- `b2_mode`: must be `pragmatic`

This summary is intended to be “very loud” and to guide debugging when offsets are imperfect.
