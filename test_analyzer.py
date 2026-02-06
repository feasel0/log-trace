#!/usr/bin/env python3
"""
Test script for the Matter Traffic Analyzer
"""

import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from analyze_traffic import LogParser, MessageCorrelator, ReportGenerator, PcapParser


def test_timeline_violations_summary_schema():
    """Smoke test for timeline JSON schema: violations_summary must exist.

    This test is intentionally pcaps-free and uses synthetic log entries so it can run
    without tshark or external captures.
    """
    print("Testing TimelineGenerator violations_summary schema...")

    import json
    from analyze_traffic import TimelineGenerator, Message, LogEntry

    controller_logs = [
        LogEntry(
            timestamp="2026-01-30 10:15:25,789",
            line_number=1,
            raw_line="matter.native.EM - <<< [E:1234i S:0 M:1001] Type 0001:03 (IM:SubscribeRequest)",
            message_type="SubscribeRequest",
            direction="sent",
            is_ack=False,
            exchange_id="1234",
            message_counter="1001",
        )
    ]
    dut_logs = [
        LogEntry(
            timestamp="[1769806702.974]",
            line_number=1,
            raw_line="[EM] >>> [E:1234r S:0 M:1001] Type 0001:03 (IM:SubscribeRequest)",
            message_type="SubscribeRequest",
            direction="received",
            is_ack=False,
            exchange_id="1234",
            message_counter="1001",
        )
    ]

    msg = Message(message_id=1, message_type="SubscribeRequest", exchange_id="1234")
    msg.controller_message_ids = {"1001": [1]}
    msg.dut_message_ids = {"1001": [1]}

    violations_summary = {
        "controller_console_to_pcap": {"best_offset": 0.0, "best_violations": 2},
        "dut_console_to_pcap": {"best_offset": 0.0, "best_violations": 1},
        "controller_vs_dut": {"best_offset": 0.0, "best_violations": 3},
        "b2_mode": "pragmatic",
    }

    with tempfile.TemporaryDirectory() as td:
        md_path = os.path.join(td, "timeline_1.md")
        json_path = os.path.join(td, "timeline_1.json")
        TimelineGenerator.generate_timeline(
            messages=[msg],
            iteration="1",
            controller_logs=controller_logs,
            dut_logs=dut_logs,
            controller_pcap_index={},
            dut_pcap_index={},
            controller_pcap_to_controller_console_offset=0.0,
            dut_pcap_to_dut_console_offset=0.0,
            dut_console_to_controller_console_offset=0.0,
            md_path=md_path,
            json_path=json_path,
            violations_summary=violations_summary,
        )

        assert os.path.exists(json_path), "timeline json not created"
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "violations_summary" in data, "violations_summary missing from timeline json"
        assert data["violations_summary"].get("b2_mode") == "pragmatic", "b2_mode must be pragmatic"
        assert "controller_console_to_pcap" in data["violations_summary"], "missing controller_console_to_pcap"
        assert "dut_console_to_pcap" in data["violations_summary"], "missing dut_console_to_pcap"
        assert "controller_vs_dut" in data["violations_summary"], "missing controller_vs_dut"

        # Also check the markdown includes the loud section title.
        assert os.path.exists(md_path), "timeline md not created"
        with open(md_path, "r", encoding="utf-8") as f:
            md = f.read()
        assert "Violations summary" in md, "timeline md missing violations summary section"

    print("  ✓ Timeline violations_summary schema looks correct")
    return True


def test_log_parser():
    """Test log parsing functionality"""
    print("Testing LogParser...")
    
    # Create test log content
    test_log = """
2026-01-30 10:15:25,789 [DEBUG] Sending message InvokeRequest to device, exchange: 0x1234, message counter: 1001
2026-01-30 10:15:26,100 [DEBUG] Received ACK from device, exchange: 0x1234, message counter: 1001
2026-01-30 10:15:26,150 [DEBUG] Received InvokeResponse from device, exchange: 0x1234, message counter: 1002
"""
    
    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(test_log)
        temp_file = f.name
    
    try:
        entries = LogParser.parse_log_file(temp_file)
        
        assert len(entries) == 3, f"Expected 3 entries, got {len(entries)}"
        assert entries[0].message_type == "InvokeRequest", f"Expected InvokeRequest, got {entries[0].message_type}"
        assert entries[0].direction == "sent", f"Expected sent, got {entries[0].direction}"
        assert entries[1].is_ack, f"Expected ACK, got {entries[1].is_ack}"
        assert entries[2].message_type == "InvokeResponse", f"Expected InvokeResponse, got {entries[2].message_type}"
        
        print("  ✓ Log parsing works correctly")
        return True
    finally:
        os.unlink(temp_file)


def test_message_correlation():
    """Test message correlation"""
    print("Testing MessageCorrelator...")
    
    # Create test log content
    controller_log = """
2026-01-30 10:15:25,789 [DEBUG] Sending message InvokeRequest to device, exchange: 0x1234, message counter: 1001
2026-01-30 10:15:26,100 [DEBUG] Received ACK from device, exchange: 0x1234, message counter: 1001
"""
    
    dut_log = """
2026-01-30 10:15:25,800 [DEBUG] Received InvokeRequest message from controller, exchange: 0x1234, message counter: 1001
2026-01-30 10:15:25,850 [DEBUG] Sending ACK to controller, exchange: 0x1234, message counter: 1001
"""
    
    # Write to temp files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(controller_log)
        controller_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(dut_log)
        dut_file = f.name
    
    try:
        controller_entries = LogParser.parse_log_file(controller_file)
        dut_entries = LogParser.parse_log_file(dut_file)
        
        messages = MessageCorrelator.correlate_messages(
            controller_entries, dut_entries, [], []
        )
        
        assert len(messages) == 1, f"Expected 1 message, got {len(messages)}"
        assert messages[0].message_type == "InvokeRequest", f"Expected InvokeRequest, got {messages[0].message_type}"
        assert messages[0].controller_sent is not None, "Expected controller_sent to be set"
        assert messages[0].dut_received is not None, "Expected dut_received to be set"
        assert messages[0].controller_ack_received is not None, "Expected controller_ack_received to be set"
        assert messages[0].dut_ack_sent is not None, "Expected dut_ack_sent to be set"
        
        print("  ✓ Message correlation works correctly")
        return True
    finally:
        os.unlink(controller_file)
        os.unlink(dut_file)


def test_report_generation():
    """Test report generation"""
    print("Testing ReportGenerator...")
    
    from analyze_traffic import Message, LogEntry
    
    # Create test message
    message = Message(
        message_id=1,
        message_type="TestRequest",
        controller_sent=LogEntry(
            timestamp="2026-01-30 10:15:25,789",
            line_number=1,
            raw_line="Sending TestRequest",
            message_type="TestRequest",
            direction="sent"
        )
    )
    
    # Generate report
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
        report_file = f.name
    
    try:
        ReportGenerator.generate_report([message], report_file)
        
        # Check report was created
        assert os.path.exists(report_file), "Report file was not created"
        
        # Check report content
        with open(report_file, 'r') as f:
            content = f.read()
            assert "Matter Traffic Analysis Report" in content, "Report header missing"
            assert "TestRequest" in content, "Message type missing from report"
            assert "Message Sent:" in content, "Message sent section missing"
        
        print("  ✓ Report generation works correctly")
        return True
    finally:
        if os.path.exists(report_file):
            os.unlink(report_file)


def test_end_to_end():
    """Test end-to-end with example files"""
    print("Testing end-to-end with example files...")
    
    examples_dir = Path(__file__).parent / "examples"
    controller_log = examples_dir / "controller.log"
    dut_log = examples_dir / "dut.log"
    
    if not controller_log.exists() or not dut_log.exists():
        print("  ⚠ Example files not found, skipping end-to-end test")
        return True
    
    # Parse logs
    controller_entries = LogParser.parse_log_file(str(controller_log))
    dut_entries = LogParser.parse_log_file(str(dut_log))
    
    # Correlate messages
    messages = MessageCorrelator.correlate_messages(
        controller_entries, dut_entries, [], []
    )
    
    # Generate report
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
        report_file = f.name
    
    try:
        ReportGenerator.generate_report(messages, report_file)
        
        # Verify report
        with open(report_file, 'r') as f:
            content = f.read()
            assert "InvokeRequest" in content, "InvokeRequest not in report"
            assert "ReadRequest" in content, "ReadRequest not in report"
            assert "WriteRequest" in content, "WriteRequest not in report"
            assert "SubscribeRequest" in content, "SubscribeRequest not in report"
            assert "ReportData" in content, "ReportData not in report"
        
        print("  ✓ End-to-end test passed")
        return True
    finally:
        if os.path.exists(report_file):
            os.unlink(report_file)


def main():
    """Run all tests"""
    print("Running Matter Traffic Analyzer Tests")
    print("=" * 50)
    
    tests = [
        test_log_parser,
        test_message_correlation,
        test_report_generation,
        test_timeline_violations_summary_schema,
        test_end_to_end,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"  ✗ Test failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Tests passed: {passed}/{len(tests)}")
    print(f"Tests failed: {failed}/{len(tests)}")
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
