{each exchange has a ## section}

## Exchange 19423 — {Title of this interaction} [{cont-side timestamp of the first message sent in this exchange}]

### 1) Cont → DUT: SubscribeRequest (start of exchange {this is a short description of what this message's purpose is})

- **Direction:** Cont → DUT
- **Type:** `IM:SubscribeRequest` (`0001:03`)
- **Message:** `M:62503407`
- **Payload summary:** {find something meaningful and informatino-full we can fill in here without having to do a lot of investigation}.
- **Cont log** [{cont-side timestamp}] `<<< [E:19423i ... M:62503407] ... Type 0001:03 (IM:SubscribeRequest)`
    -          [{cont-side timestamp}] `{line about scheduling retries}` 
    -          [{cont-side timestamp}] `{line for the 2nd attempt}` 
    -          [{cont-side timestamp}] `{line for the 3rd attempt}` 
    -          [{cont-side timestamp}] `{line for the 4th attempt}` 
    -          [{cont-side timestamp}] `{zero or more additional lines related to this message}`
- **Cont pcap** [{cont-side timestamp}] `{one-line summary for 1st attempt packet}`
    -           [{cont-side timestamp}] `{one-line summary for 2nd attempt packet}`
    -           [{cont-side timestamp}] `{one-line summary for 3rd attempt packet}`
    -           [{cont-side timestamp}] `{one-line summary for 4th attempt packet}`
    -           [{cont-side timestamp}] `{zero or more additional lines for packets related to this message}`
- **DUT pcap** [{cont-side timestamp}] `{one-line summary for 1st attempt packet}`
    -          [{cont-side timestamp}] `{one-line summary for 2nd attempt packet}`
    -          [{cont-side timestamp}] `{one-line summary for 3rd attempt packet}`
    -          [{cont-side timestamp}] `{one-line summary for 4th attempt packet}`
    -          [{cont-side timestamp}] `{zero or more additional lines for packets related to this message}`
- **DUT log** [{cont-side timestamp}] `>>> [E:19423r ... M:62503407] ... Type 0001:03 (IM:SubscribeRequest)` and `IM received SubscribeRequest on Exchange: 19423r`.
    -         [{cont-side timestamp}] `{line for the 2nd attempt receipt}` 
    -         [{cont-side timestamp}] `{line for the 3rd attempt receipt}` 
    -         [{cont-side timestamp}] `{line for the 4th attempt receipt}` 
    -         [{cont-side timestamp}] `{zero or more additional lines related to this message}`

- **Ack / response:**
- **Direction:** DUT → Cont
- **Type:** `IM:ReportData` (`0001:05`)
- **Message:** `M:123456 (Ack:62503407)`
- {lines for DUT log, DUT pcap, Cont pcap, Cont log, exactly the same format as the original message}

### 2) DUT → Cont: ReportData chunk #1 (successful round)

- {Same format as the previous message/ack, except the log/pcap lines are reversed in order.  Message goes DUT log, DUT pcap, Cont pcap, Cont log.  Ack goes Cont log, Cont pcap, DUT pcap, DUT log. }

### 3) DUT → Cont: ReportData chunk #2 (successful round)

- {Same format as the previous chunk}

### 4) DUT → Cont: ReportData chunk #3 (successful round)

- {Same format as the previous chunk}

### 5) ... many more chunks successfully round-trip (summarized)

{If this exchange is a SubscribeRequest and we have more than 3 successful chunks sent in a report, we'll make a summary section like this one that goes up to but not including the chunk that didn't get sent and received successfully}
- **Direction:** DUT → Cont
- **Type:** `IM:ReportData` (chunks)
- **Observed on DUT TX:** 34 chunks total: `M:131534465 .. 131534508`
- **Observed on Cont RX:** **35 chunks total**{bolded because it doesn't match the prev line} `IM:ReportData` receipts on `E:19423i` (includes a duplicate `M:131534507`).
- {short summary of exactly what a typical round looks like, including the messages and acks in both directions}

### 6) {title}

{from here on we stop summarizing and we once again do one section per message}
