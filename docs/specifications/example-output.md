## Message timeline (exchange 19423) — subscribe start → failure

This is the timeline rewritten strictly in terms of **messages** (direction, type, payload summary, and log-confirmations on each side).

Legend:
- **Sender TX?**: do we have a log line on the sender confirming it transmitted the message (an `EM` `<<<` line).
- **Receiver RX?**: do we have a log line on the receiver confirming it received the message (an `EM` `>>>` line).
- **Response Ack/confirm**: what message is sent in response, and whether we have TX/RX confirmation for that response.

### 1) Controller → DUT: SubscribeRequest (start of exchange)

- **Direction:** Controller → DUT
- **Type:** `IM:SubscribeRequest` (`0001:03`)
- **Message / exchange:** `E:19423i`, `M:62503407`
- **Payload summary:** subscription request for the ensuing priming report; test harness indicates “urgent events” and “empty list of attribs” (controller log includes only the header line here, not a full decoded subscribe payload).
- **Sender TX?** Yes (controller log): `<<< [E:19423i ... M:62503407] ... Type 0001:03 (IM:SubscribeRequest)`
- **Receiver RX?** Yes (DUT log): `>>> [E:19423r ... M:62503407] ... Type 0001:03 (IM:SubscribeRequest)` and `IM received SubscribeRequest on Exchange: 19423r`.

**Ack / response:**
- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` (`0001:05`) (first priming chunk)
- **Sender TX?** Yes (DUT log): `<<< [E:19423r ...] ... Type 0001:05 (IM:ReportData)`
- **Receiver RX?** Yes (controller log): `>>> [E:19423i ...] ... Type 0001:05 (IM:ReportData)`

### 2) DUT → Controller: ReportData chunk #1 (successful round)

- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` (`0001:05`)
- **Message / exchange:** `E:19423r` / `E:19423i`, `M:131534465`
- **Payload summary (from controller decode):** `ReportDataMessage` carrying `SubscriptionId = 0x5241fc7e` and multiple `AttributeReportIBs` (examples visible: NetworkCommissioning attributes like `maxNetworks`, lists like `attributeList`, etc.).
- **Sender TX?** Yes (DUT): `<<< ... M:131534465 ... Type 0001:05 (IM:ReportData)`
- **Receiver RX?** Yes (controller): `>>> ... M:131534465 ... Type 0001:05 (IM:ReportData)`

**Ack / response (report confirmation):**
- **Direction:** Controller → DUT
- **Type:** `IM:StatusResponse` (`0001:01`)
- **Message / exchange:** `E:19423i`, `M:62503408 (Ack:131534465)`
- **Payload summary:** `StatusResponse` with success status confirming receipt/processing of the `ReportData` chunk.
- **Sender TX?** Yes (controller): `<<< ... M:62503408 (Ack:131534465) ... Type 0001:01 (IM:StatusResponse)`
- **Receiver RX?** Yes (DUT): `>>> ... M:62503408 ... Type 0001:01 (IM:StatusResponse)`

### 3) DUT → Controller: ReportData chunk #2 (successful round)

- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` (`0001:05`)
- **Message / exchange:** `M:131534466`
- **Payload summary (from controller decode):** more attribute reports; notably includes complex data like OperationalCredentials material (e.g. `OperationalCredentials::NOCs` / `fabrics` items shown in decode).
- **Sender TX?** Yes (DUT): `<<< ... M:131534466 ... Type 0001:05 (IM:ReportData)`
- **Receiver RX?** Yes (controller): `>>> ... M:131534466 ... Type 0001:05 (IM:ReportData)`

**Ack / response (report confirmation):**
- **Direction:** Controller → DUT
- **Type:** `IM:StatusResponse` (`0001:01`)
- **Message / exchange:** `M:62503409 (Ack:131534466)`
- **Sender TX?** Yes (controller)
- **Receiver RX?** Yes (DUT)

### 4) DUT → Controller: ReportData chunk #3 (successful round)

- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` (`0001:05`)
- **Message / exchange:** `M:131534467`
- **Payload summary:** continued attribute report payload (subscription priming continues; large/varied clusters).
- **Sender TX?** Yes (DUT)
- **Receiver RX?** Yes (controller)

**Ack / response (report confirmation):**
- **Direction:** Controller → DUT
- **Type:** `IM:StatusResponse` (`0001:01`)
- **Message / exchange:** `M:62503410 (Ack:131534467)`
- **Sender TX?** Yes (controller)
- **Receiver RX?** Yes (DUT)

### 5) … many more chunks successfully round-trip (summarized)

- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` chunks
- **Observed on DUT TX:** 34 chunks total: `M:131534465 .. 131534508` (non-contiguous; gaps exist).
- **Observed on controller RX:** controller sees **35** `IM:ReportData` receipts on `E:19423i` (includes a duplicate `M:131534507`).

For most of the stream, each chunk has the same successful pattern:
- Controller receives `IM:ReportData` (`>>>`), then sends an `IM:StatusResponse` that confirms it (`<<< ... Type IM:StatusResponse` with `Ack:<chunkMC>`), and DUT logs that StatusResponse as received (`>>>`).

### 6) Divergence begins: controller’s last report-confirming StatusResponse becomes “stuck”

- **Direction:** Controller → DUT
- **Type:** `IM:StatusResponse` (`0001:01`)
- **Message / exchange:** `M:62503440 (Ack:131534507)`
- **Payload summary:** success StatusResponse used as the **report confirmation** for chunk `131534507`.
- **Sender TX?** Yes (controller)
- **Receiver RX?** Yes (DUT) — and the DUT sees it as a duplicate multiple times near teardown.

**Ack / response (transport ACK for 62503440):**
- **Direction:** DUT → Controller
- **Type:** `SecureChannel:StandaloneAck` (`0000:10`)
- **Message / exchange:** DUT sends StandaloneAcks that ACK `62503440` (e.g. `M:131534512 (Ack:62503440)` is seen by controller).
- **Sender TX?** Yes (DUT)
- **Receiver RX?** Yes (controller): `>>> ... Type 0000:10 (SecureChannel:StandaloneAck)` with `Ack:62503440`.

**But**: despite those ACKs being observed later, the controller’s MRP layer still gives up on `62503440`:
- **Controller log:** `<<5 [E:19423i ... M:62503440] ... failure (max retries:4)` (MRP retransmit exhaustion).

### 7) Final chunk is received by controller but not IM-confirmed

- **Direction:** DUT → Controller
- **Type:** `IM:ReportData` (`0001:05`)
- **Message / exchange:** `M:131534508`
- **Payload summary:** another chunk of subscription priming attribute reports; DUT’s `ReadHandler` still indicates “more chunks” upstream (no terminating `moreChunks=0` observed anywhere in this exchange on the DUT).
- **Sender TX?** Yes (DUT)
- **Receiver RX?** Yes (controller): controller has a `ReportData` RX for `131534508`.

**Ack / response:**
- **What we expected (but do NOT see):** Controller → DUT `IM:StatusResponse` with `Ack:131534508`.
  - **Sender TX?** **No** (controller): there is **no** `IM:StatusResponse (Ack:131534508)` in the controller log.
  - (Computed from controller log): `ReportData` chunks without an `IM:StatusResponse` confirmation: **only `[131534508]`**.

- **What we actually see:** Controller → DUT `SecureChannel:StandaloneAck` confirming transport receipt.
  - **Type:** `SecureChannel:StandaloneAck` (`0000:10`)
  - **Message / exchange:** `M:62503442 (Ack:131534508)`
  - **Sender TX?** Yes (controller)
  - **Receiver RX?** Yes (DUT)

### 8) Failure end-state (both sides time out)

- **DUT failure trigger:**
  - `Time out! failed to receive status response from Exchange: 19423r`
  - subscription torn down (`Subscription id 0x5241fc7e ... torn down`) and handler goes to `AwaitingDestruction`.

- **Controller failure trigger:**
  - `Time out! failed to receive report data from Exchange: 19423i`
  - `ReadClient timeout details: ... state=AwaitingSubscribeResponse ... pendingMoreChunks=1`
  - surfaced to python as `CHIP Error 0x00000032: Timeout`.

### 09:59:34.202 — First subscribe-related traffic is received

Very shortly after sending the subscribe, the controller receives `IM:ReportData`:
- `MessageReceived ... msgCounter 131534465 ...`
- Payload shows `report_data` with attribute reports.

This indicates the DUT *is* responding on the subscribe exchange, at least initially.

### 09:59:46.685–09:59:46.699 — Chunked ReportData (and duplicate) appears; controller expects more

Later, more `IM:ReportData` is received on `19423i`:
- `>>> [E:19423i ...] (S) Msg RX ... Type 0001:05 (IM:ReportData)`

The decoded payload explicitly indicates chunking:
- `"more_cunked_messages" : "true"`

And the exchange shows a duplicate handling event:
- `Forcing tx of solitary ack for duplicate MessageCounter:131534507 on exchange 19423i`

The key implication is: the controller **believes there are more chunks to come** to complete the report/priming flow.

### 09:59:46.833–09:59:50.057 — Controller retransmits and gives up at MRP layer

Immediately after the above, we see repeated retransmissions of a message with counter `62503440` on exchange `19423i`:
- `<<1 ... M:62503440 ... Msg Retransmission ...`
- retry count increments up to 4
- then:
  - `Msg Retransmission ... failure (max retries:4)` at **09:59:50.057**

This is strong evidence that the controller is trying to get *some* reliable message on that exchange acknowledged/fulfilled, but doesn’t.

### 09:59:56.912 — The actual failure: ReadClient timeout waiting for SubscribeResponse/report completion

The controller’s `ReadClient` times out:
- `Time out! failed to receive report data from Exchange: 19423i`
- `ReadClient timeout details: ... state=AwaitingSubscribeResponse isReporting=1 ... pendingMoreChunks=1`

Then the Python layer surfaces it:
- `Read failed ...`
- `matter.exceptions.ChipStackError: src/app/ReadClient.cpp:761: CHIP Error 0x00000032: Timeout`
- `SubscribeRequest failed ... CHIP Error 0x00000032: Timeout`

Finally, the harness marks the iteration failed:
- `Exception has been raised, failed iteration 583`
- `Iteration 583 FAIL :`

## What *exactly* is going wrong?

This does **not** look like the controller never received anything.

Instead, it looks like a **subscription establishment flow gets stuck mid-flight**, specifically:

1) The controller sends `IM:SubscribeRequest` on `19423i`.
2) The DUT sends at least one `IM:ReportData` that is **chunked** (`more_cunked_messages=true`).
3) The controller never receives the final chunk(s) and/or never receives the response it needs to move out of `AwaitingSubscribeResponse`.
4) Meanwhile the controller retransmits a message (`M:62503440`) and hits max retries.
5) `ReadClient` times out with `pendingMoreChunks=1`.

That `pendingMoreChunks=1` is the most concrete “this is what the stack thought was happening” indicator: **the stack believes the DUT promised more report data (chunks) but didn’t deliver it**.

What the DUT log adds is that this chunking isn’t “mysterious”: the DUT is explicitly running into **packet buffer memory limits while building the report**, then enabling chunking and continuing.

On the DUT, for exchange `19423r` (same exchange id as controller’s `19423i`, just opposite direction), we see:

- It receives the subscribe request:
  - `IM received SubscribeRequest on Exchange: 19423r`
- While building the first report it hits a packet-buffer allocation/fit failure:
  - `Next attribute value does not fit in packet ... CHIP Error 0x0000000B: No memory`
  - `<RE:Run> We cannot put more chunks into this report. Enable chunking.`
- It sends a first chunked `ReportData` with `moreChunks=1` (msgCounter `131534465`).
- The controller **ACKs it** (via a StatusResponse carrying `AckMsg = 131534465`).
- The DUT then builds/sends the **next** chunk (msgCounter `131534466`) and that also gets ACKed.

So the iteration-583 failure is not simply “first chunk was lost”: at least the first couple of chunked `ReportData` messages are exchanged successfully. The failure is later: **the chunk stream does not complete (or the controller can’t process/confirm completion) before ReadClient’s overall timeout, while it still has `pendingMoreChunks=1`.**

### New (strong) DUT-side correlation: the DUT actually sends *many* chunked reports, and they’re all ACKed

From the DUT log, on exchange `19423r`, the DUT transmits **34** separate `ReportData` messages as part of this subscribe priming/reporting burst:

- First chunk: `131534465` (`moreChunks=1`) — controller responds with `IM:StatusResponse` (SUCCESS) that ACKs it; DUT logs `Rxd Ack; Removing MessageCounter:131534465 ...`.
- …
- Last observed chunk: `131534508` (`moreChunks=1`) — controller sends a **StandaloneAck** ACKing it; DUT logs `Rxd Ack; Removing MessageCounter:131534508 ...`.

In other words: **yes**: prior to the failure, the DUT successfully sends several (in fact, dozens of) chunks; the controller receives them and ACKs them; the DUT sees the ACKs and keeps sending more chunks.

This shifts the likely failure mechanism away from “packets didn’t get through” and toward **“the subscribe never reaches a completion condition”** (e.g., the controller never sees a terminating `ReportData` with `moreChunks=0`, or the exchange gets into an unexpected state machine loop).

### New key observation: there is no terminating chunk (`moreChunks=0`) in the DUT log

We can now be very specific:

- The DUT logs **34** instances of:
  - `ReadHandler::SendReportData start exchangeId=0x4bdf moreChunks=1`
- The DUT logs **zero** instances of:
  - `ReadHandler::SendReportData start exchangeId=0x4bdf moreChunks=0`

So at least for this exchange, everything the DUT transmits is marked as “more chunks expected”. That lines up perfectly with the controller’s eventual timeout details (`pendingMoreChunks=1`).

This suggests the core failure is not transport reliability, but **a report-generation/dirty-set/chunking loop that never reaches a “final chunk” state**.

### Next-step deepening: what seems to drive the non-termination?

Two additional data points from the DUT log make the “never reaches final chunk” story more concrete:

1) **Persistent chunking pressure**
   - The DUT emits `Enable chunking.` **51 times** in the log.
   - The trigger is usually one of:
     - `Next attribute value does not fit in packet ... CHIP Error 0x0000000B: No memory`
     - `List does not fit in packet, chunk between list items ...`

2) **Chunking is not caused by one repeated offender**
   - For each of the 34 `ReadHandler::SendReportData ... moreChunks=1` sends on exchange `0x4bdf`, the “didn’t fit → enable chunking” trigger immediately beforehand references *different* clusters/attributes.
   - Examples across the chunk stream:
     - `clusterId: 0x0000_003E attributeId: 0x0000_0000`
     - `clusterId: 0x0000_003E attributeId: 0x0000_0004`
     - `clusterId: 0x0000_0038 attributeId: 0x0000_000C`
     - `clusterId: 0x0000_0036 attributeId: 0x0000_FFFB` (list chunking)
     - `clusterId: 0x0000_0551 attributeId: 0x0000_0008`
     - `clusterId: 0x0000_0802 attributeId: 0x0000_FFFC`

Taken together, this points to a simpler mechanical explanation: **the priming report set is so large (and so often fails to fit) that the reporting engine keeps producing chunk-after-chunk with `moreChunks=1` and never reaches the condition where it can send a final chunk (`moreChunks=0`) and then a `SubscribeResponse`.**

Also notable in the DUT log right after ACKing the last observed chunk:
- The ReadHandler transitions: `IM RH moving to [AwaitingDestruction]`
- It logs: `Schedule subscription resumption when failing to establish session, Retries: 1`

That looks like the DUT itself decided the subscription establishment was not healthy/complete, even though chunk ACKing was working.

### Corollary: no `SubscribeResponse` observed on either side

In iteration 583:
- DUT log: no `Subscribe Response (0x04)` / `ReadHandler::SendSubscribeResponse` observed.
- Controller log: no `Type 0001:04 (IM:SubscribeResponse)` observed for exchange `19423i`.

This matches the controller’s `ReadClient` state at failure: `AwaitingSubscribeResponse`.

### New: pinpoint why the DUT tears down the subscription attempt

The DUT does not tear down because it can’t send/ACK chunks. It tears down because **it times out waiting for a status response** on the subscribe exchange:

- DUT log at ~`1770130797.229`:
  - `Time out! failed to receive status response from Exchange: 19423r`
  - `Subscription id 0x5241fc7e from node <000000000001B669, 1> torn down`
  - `IM RH moving to [AwaitingDestruction]`
  - `Schedule subscription resumption when failing to establish session, Retries: 1`

Immediately after that timeout, the controller sends a StandaloneAck (`AckMsg = 131534508`) which the DUT receives and uses to remove the final chunk from its retrans table — i.e. **the ACK arrives, but too late to prevent the DUT’s “waiting for status response” timeout.**

This reframes the problem:
- The critical missing piece is not chunk delivery, but **the DUT waiting for an IM StatusResponse “report confirmation” message and not receiving it in time**, even though the controller later sends at least a StandaloneAck.

The controller log supports that it sends `IM:StatusResponse` acknowledgements for many chunks (`Ack:131534465`, `Ack:131534466`, …). However, it also gets stuck retransmitting `M:62503440` (sent at 09:59:46.467 as a NeedsAck message with `Ack:131534507`) and ultimately times out at the ReadClient layer.

### New: what “status response” the DUT was waiting for (and why a StandaloneAck didn’t save it)

The logs now pin this down to a very specific last-step mismatch at the end of the chunk burst:

- On the controller, `IM:StatusResponse` messages on exchange `19423i` are being used as **report confirmations**. We see **33** such TX messages in total, with their `Ack:` fields matching the DUT’s `ReportData` chunk message counters.
  - The last report-confirming StatusResponse observed is:
    - `IM:StatusResponse` **`M:62503440 (Ack:131534507)`**

- On the DUT, the last observed `ReportData` chunk is:
  - `IM:ReportData` **`M:131534508`**

- Critically: the controller does **not** send an `IM:StatusResponse` confirming `131534508`. Instead, it sends a transport-level ack:
  - `SecureChannel:StandaloneAck` **`M:62503442 (Ack:131534508)`**
  - The DUT receives that StandaloneAck only **after** it already logs:
    - `Time out! failed to receive status response from Exchange: 19423r`

This makes the failure mode much less ambiguous: for the last chunk, the DUT appears to require an **IM-level StatusResponse** (report confirmation) and a **StandaloneAck** is either (a) not sufficient for the ReadHandler’s report-confirmation logic, and/or (b) arrives too late to meet the status-response timer.

### New: why the controller stops sending report-confirming StatusResponses near the end

Right before the final chunk, the controller’s last report-confirming `IM:StatusResponse` (`M:62503440`) becomes pathological:

- Controller retransmits `M:62503440` and eventually logs:
  - `Msg Retransmission ... failure (max retries:4)`

At the same time, the DUT log around the teardown boundary shows it receiving `M:62503440` multiple times as a **duplicate** and responding with standalone ACKs that ACK `62503440`.

**Implication:** exchange `19423` gets stuck in an IM confirmation deadlock: the controller can’t complete delivery/ACK of its last `IM:StatusResponse` (`62503440`), and then appears to fall back to only transport-level acks for subsequent chunks (`131534508`). The DUT times out waiting for the IM-level status response.

## Concrete examples (verbatim log cues)

These are the most important log anchors to support the above narrative:

- Subscribe request send:
  - `<<< [E:19423i ...] ... Type 0001:03 (IM:SubscribeRequest)`

- Chunked ReportData:
  - `... "more_cunked_messages" : "true"`

- Duplicate message handling on the same exchange:
  - `Forcing tx of solitary ack for duplicate MessageCounter:131534507 on exchange 19423i`

- MRP retries and ultimate failure:
  - `Msg Retransmission ... retry_count ...`
  - `Msg Retransmission ... failure (max retries:4)`

- ReadClient timeout details:
  - `state=AwaitingSubscribeResponse ... pendingMoreChunks=1`

- Final exception:
  - `CHIP Error 0x00000032: Timeout`

## Testable hypotheses

These are ordered from “most directly supported by the log” to “needs more evidence”, and each includes how we can test it.

### H1: DUT starts a chunked ReportData but stalls before sending the final chunk(s)

**Why it fits:**
- `more_cunked_messages=true` plus `pendingMoreChunks=1` at timeout is a direct match.

**How to test:**
- Check the DUT log (`Dut_log_iteration_583_...`) for any crash, assert, or “out of buffers” around 09:59:34–09:59:56.
- If there’s a pcap for this iteration, verify whether the final `ReportData` chunks were ever sent and whether the controller ACKed them.
  - Note: controller log shows capture collection failing (`Capture compress failed ... pcap missing or unreadable`), so we may need to re-run with capture stabilized.

**Updated supporting evidence (DUT log):**
- Chunking is repeatedly triggered by packet buffer pressure:
  - `CHIP Error 0x0000000B: No memory` + `Enable chunking.`
- The DUT sends **34** `ReportData` messages on exchange `19423r` and **all 34 are ACKed** (removed from retrans table).
- Yet, none of the observed `ReportData` sends show `moreChunks=0` in the `ReadHandler::SendReportData` log line snippets we captured (the ones we looked at were all `moreChunks=1`).

So if H1 is true, it’s not “stalls immediately”; it’s more like: **the report stream never produces a terminating chunk (`moreChunks=0`) and never transitions into an actual subscribe completion (`SubscribeResponse`), so the controller keeps `pendingMoreChunks=1` until timeout.**

**Refined test for H1:**
- Identify what keeps making things “dirty” on the DUT (it repeatedly logs `Cluster ... Attribute ... is dirty` as it builds reports). If something keeps re-dirtying while chunking is enabled, the ReadHandler may keep scheduling more `ReportData` with `moreChunks=1`.

**Additional nuance:**
- A quick scan of `Cluster ..., Attribute ... is dirty` markers during the chunk stream shows a very wide spread (over a thousand unique cluster/attribute pairs logged) rather than a small hot loop. That makes it less likely that *one* attribute is re-dirtying and more likely that the initial “everything is dirty” priming set is simply huge.

### H2: ACK loss / retransmission spiral prevents reliable completion of the subscribe exchange

**Why it fits:**
- The controller retransmits `M:62503440` repeatedly and hits `max retries:4`.
- There was at least one duplicate inbound message on the exchange, which can occur when ACKs are missed.

**How to test:**
- Look in both controller + DUT logs for patterns like:
  - controller receiving duplicates
  - DUT retransmitting the same message counter
  - repeated StandaloneAck traffic
- If possible, capture traffic (pcap) to distinguish:
  - actual packet loss
  - DUT not responding
  - response sent but not received

**Updated nuance from DUT log:**
- ACKing works throughout the observed burst: all 34 `ReportData` chunks are ACKed on the DUT.
- That makes “ACK loss causes the timeout” unlikely as the primary mechanism (though it still could happen for *other* message types on the exchange).

**New supporting evidence:**
- The DUT’s teardown is explicitly triggered by `failed to receive status response from Exchange: 19423r`.
- The controller later sends a StandaloneAck for the final chunk (`Ack:131534508`), but the DUT has already timed out the status-response wait.

So, the more precise version of H2 is:
- **Some required “report confirmation” StatusResponse from controller → DUT is missing/delayed**, even though basic MRP ACKing for the `ReportData` chunks is working.

**Update (strongly supported by log):** the missing confirmation appears to be exactly for the final chunk `ReportData M:131534508`.

### H2b: the controller getting stuck retrying `IM:StatusResponse M:62503440` causes the late-stage confirmation gap

**Why it fits:**
- `M:62503440` is the last seen report-confirming StatusResponse (acks `131534507`).
- It hits max retries on the controller.
- Immediately after, controller is observed sending only StandaloneAcks (`62503441`, `62503442`) instead of more IM StatusResponses.

**How to test:**
- Determine whether `M:62503440` is being (a) dropped on the air (unlikely if DUT sees duplicates), or (b) processed but its required transport ACK isn’t being accepted/recorded by the controller.
- If possible, obtain/repair pcap collection for a rerun to see actual frame ordering around `62503440` and `131534508`.

### H3: DUT sends very large priming data for the urgent-event subscription and runs into internal resource limits

**Why it fits:**
- The logs show lots of attribute reporting; the timeout occurs during a subscription priming read.
- Some devices under stress eventually fail due to memory fragmentation or buffer exhaustion.

**Stronger evidence now:**
- The DUT explicitly logs packet buffer allocation/fit failures (`CHIP Error 0x0000000B: No memory`) while building the subscription reports, and repeatedly has to enable chunking.

**How to test:**
- In `iteration.json` and/or DUT logs, check for heap usage trends, watchdog resets, or errors around the failure window.
- Compare with later failures (e.g. iteration 596) to see if the failure signature matches.

### H4: CASE session becomes defunct because MRP fails, and that cascades into ReadClient timeout

**Why it fits:**
- Near the timeout:
  - `SecureSession... MarkAsDefunct` appears.

**How to test:**
- Determine whether the session becomes defunct *because* the exchange timed out (expected), or whether it became defunct earlier and caused the subsequent timeout.
- This needs more log context slightly earlier than the retransmission window.

## Notes / next data pulls

1) From the DUT log, figure out why the ReadHandler never reaches `moreChunks=0` (e.g., enumerate the “dirty” items and see whether the same cluster/attribute keeps reappearing).
2) From the controller log, identify what `M:62503440` is (original TX of that message counter on `19423i`) and what ACK it expects.
3) If possible, fix capture collection for a rerun (pcap would settle whether chunks were sent/received vs. stuck locally).

4) Correlate controller-side `IM:StatusResponse` transmissions for this exchange with DUT’s expectation window: find whether there is a “gap” near the end where the controller stops sending StatusResponses and only sends StandaloneAcks.
