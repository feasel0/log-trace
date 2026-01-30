# Matter Traffic Analysis Report

Generated: 2026-01-30 18:47:49

Total Messages: 5

---

## Message 1: InvokeRequest

### Controller Logs

**Message Sent:**
- Line 3: `2026-01-30 10:15:25,789 [DEBUG] Sending message InvokeRequest to device, exchange: 0x1234, message counter: 1001`

**Message Received:**
- Line 6: `2026-01-30 10:15:26,150 [DEBUG] Received InvokeResponse from device, exchange: 0x1234, message counter: 1002`

**ACK Sent:**
- Line 7: `2026-01-30 10:15:26,200 [DEBUG] Sending ACK to device, exchange: 0x1234, message counter: 1002`

**ACK Received:**
- Line 5: `2026-01-30 10:15:26,100 [DEBUG] Received ACK from device, exchange: 0x1234, message counter: 1001`

### DUT Logs

**Message Sent:**
- Line 6: `2026-01-30 10:15:26,120 [DEBUG] Sending InvokeResponse message to controller, exchange: 0x1234, message counter: 1002`

**Message Received:**
- Line 3: `2026-01-30 10:15:25,800 [DEBUG] Received InvokeRequest message from controller, exchange: 0x1234, message counter: 1001`

**ACK Sent:**
- Line 4: `2026-01-30 10:15:25,850 [DEBUG] Sending ACK to controller, exchange: 0x1234, message counter: 1001`

**ACK Received:**
- Line 7: `2026-01-30 10:15:26,220 [DEBUG] Received ACK from controller, exchange: 0x1234, message counter: 1002`

### Controller PCAP Packets

*No controller PCAP packets found*

### DUT PCAP Packets

*No DUT PCAP packets found*

---

## Message 2: ReadRequest

### Controller Logs

**Message Sent:**
- Line 9: `2026-01-30 10:15:30,100 [DEBUG] Sending ReadRequest message, exchange: 0x5678, message counter: 2001`

**Message Received:**
- Line 11: `2026-01-30 10:15:30,500 [DEBUG] Received ReadResponse message, exchange: 0x5678, message counter: 2002`

**ACK Sent:**
- Line 12: `2026-01-30 10:15:30,550 [DEBUG] Sending ACK for ReadResponse, exchange: 0x5678, message counter: 2002`

**ACK Received:**
- Line 10: `2026-01-30 10:15:30,300 [DEBUG] Received ACK, exchange: 0x5678, message counter: 2001`

### DUT Logs

**Message Sent:**
- Line 11: `2026-01-30 10:15:30,480 [DEBUG] Sending ReadResponse message, exchange: 0x5678, message counter: 2002`

**Message Received:**
- Line 8: `2026-01-30 10:15:30,150 [DEBUG] Received ReadRequest message from controller, exchange: 0x5678, message counter: 2001`

**ACK Sent:**
- Line 9: `2026-01-30 10:15:30,200 [DEBUG] Sending ACK, exchange: 0x5678, message counter: 2001`

**ACK Received:**
- Line 12: `2026-01-30 10:15:30,580 [DEBUG] Received ACK from controller, exchange: 0x5678, message counter: 2002`

### Controller PCAP Packets

*No controller PCAP packets found*

### DUT PCAP Packets

*No DUT PCAP packets found*

---

## Message 3: WriteRequest

### Controller Logs

**Message Sent:**
- Line 13: `2026-01-30 10:15:35,000 [DEBUG] Sending WriteRequest message to device, exchange: 0x9ABC, message counter: 3001`

**Message Received:**
- Line 15: `2026-01-30 10:15:35,200 [DEBUG] Received WriteResponse from device, exchange: 0x9ABC, message counter: 3002`

**ACK Sent:**
- Line 16: `2026-01-30 10:15:35,250 [DEBUG] Sending ACK, exchange: 0x9ABC, message counter: 3002`

**ACK Received:**
- Line 14: `2026-01-30 10:15:35,100 [DEBUG] Received ACK from device, exchange: 0x9ABC, message counter: 3001`

### DUT Logs

**Message Sent:**
- Line 16: `2026-01-30 10:15:35,180 [DEBUG] Sending WriteResponse message, exchange: 0x9ABC, message counter: 3002`

**Message Received:**
- Line 13: `2026-01-30 10:15:35,050 [DEBUG] Received WriteRequest message from controller, exchange: 0x9ABC, message counter: 3001`

**ACK Sent:**
- Line 14: `2026-01-30 10:15:35,080 [DEBUG] Sending ACK to controller, exchange: 0x9ABC, message counter: 3001`

**ACK Received:**
- Line 17: `2026-01-30 10:15:35,280 [DEBUG] Received ACK from controller, exchange: 0x9ABC, message counter: 3002`

### Controller PCAP Packets

*No controller PCAP packets found*

### DUT PCAP Packets

*No DUT PCAP packets found*

---

## Message 4: ReportData

### Controller Logs

**Message Received:**
- Line 22: `2026-01-30 10:15:45,000 [DEBUG] Received ReportData message from device, exchange: 0xABCD, message counter: 5001`

**ACK Sent:**
- Line 23: `2026-01-30 10:15:45,100 [DEBUG] Sending ACK for ReportData, exchange: 0xABCD, message counter: 5001`

### DUT Logs

**Message Sent:**
- Line 24: `2026-01-30 10:15:44,980 [DEBUG] Sending ReportData message to controller, exchange: 0xABCD, message counter: 5001`

**ACK Received:**
- Line 25: `2026-01-30 10:15:45,120 [DEBUG] Received ACK from controller, exchange: 0xABCD, message counter: 5001`

### Controller PCAP Packets

*No controller PCAP packets found*

### DUT PCAP Packets

*No DUT PCAP packets found*

---

## Message 5: SubscribeRequest

### Controller Logs

**Message Sent:**
- Line 18: `2026-01-30 10:15:40,100 [DEBUG] Sending SubscribeRequest message, exchange: 0xDEF0, message counter: 4001`

**Message Received:**
- Line 20: `2026-01-30 10:15:40,500 [DEBUG] Received SubscribeResponse message, exchange: 0xDEF0, message counter: 4002`

**ACK Sent:**
- Line 21: `2026-01-30 10:15:40,550 [DEBUG] Sending ACK for subscription, exchange: 0xDEF0, message counter: 4002`

**ACK Received:**
- Line 19: `2026-01-30 10:15:40,200 [DEBUG] Received ACK, exchange: 0xDEF0, message counter: 4001`

### DUT Logs

**Message Sent:**
- Line 21: `2026-01-30 10:15:40,480 [DEBUG] Sending SubscribeResponse message, exchange: 0xDEF0, message counter: 4002`

**Message Received:**
- Line 18: `2026-01-30 10:15:40,150 [DEBUG] Received SubscribeRequest message, exchange: 0xDEF0, message counter: 4001`

**ACK Sent:**
- Line 19: `2026-01-30 10:15:40,180 [DEBUG] Sending ACK for SubscribeRequest, exchange: 0xDEF0, message counter: 4001`

**ACK Received:**
- Line 22: `2026-01-30 10:15:40,580 [DEBUG] Received ACK from controller, exchange: 0xDEF0, message counter: 4002`

### Controller PCAP Packets

*No controller PCAP packets found*

### DUT PCAP Packets

*No DUT PCAP packets found*

---

