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
