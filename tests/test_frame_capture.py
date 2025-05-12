#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests para la funcionalidad de captura de tramas en networking_tester."""

import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import logging
from scapy.all import Ether, IP, TCP, UDP, ICMP, Dot11, wrpcap, rdpcap
from io import StringIO

# Add the project root directory to Python path so it can find the networking_tester package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from networking_tester.capture import frame_capture as frame_capturer  # Alias to match existing code
from networking_tester.utils import logging_config

# Configure logging for tests
logging_config.setup_logging(log_level_str="INFO")
logger = logging.getLogger(__name__)

class TestFrameCapture(unittest.TestCase):
    """Test cases for frame capture functionality."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_pcap = os.path.join(self.test_dir, "test_capture.pcap")
        
        # Create sample packets for testing
        self.sample_packets = [
            Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=80, dport=12345),
            Ether()/IP(src="192.168.1.2", dst="8.8.8.8")/UDP(sport=12346, dport=53),
            Ether()/IP(src="192.168.1.2", dst="192.168.1.1")/ICMP(type=8),
            Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=443, dport=54321),
            Ether()/IP(src="172.16.0.5", dst="172.16.0.10")/UDP(sport=5000, dport=5001)
        ]
        
        # Create a sample WiFi packet
        self.wifi_packet = Dot11()/Dot11()
        
        # Write sample packets to pcap file for testing
        wrpcap(self.test_pcap, self.sample_packets)
        
        logger.info(f"Test setup complete. Created test PCAP at {self.test_pcap}")
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove test files
        if os.path.exists(self.test_pcap):
            os.remove(self.test_pcap)
        
        # Remove test directory
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)
            
        logger.info("Test cleanup complete")
    
    @patch('networking_tester.capture.frame_capture.sniff')
    def test_live_capture(self, mock_sniff):
        """Test capturing packets live from an interface."""
        # Set up the mock to return our sample packets
        mock_sniff.return_value = self.sample_packets
        
        # Test live capture
        capture = frame_capturer.FrameCapture()
        result = capture.start_capture(interface="eth0", count=5, timeout=10)
        
        # Verify capture results
        self.assertEqual(len(result), 5)
        mock_sniff.assert_called_once_with(
            iface="eth0", count=5, timeout=10, store=True, prn=capture._packet_callback
        )
        
        # Check that counts were updated correctly
        self.assertEqual(capture.stats["total_packets"], 5)
        self.assertEqual(capture.stats["tcp_count"], 2)
        self.assertEqual(capture.stats["udp_count"], 2)
        self.assertEqual(capture.stats["icmp_count"], 1)
        
        logger.info("Live capture test successful")
    
    def test_read_from_pcap(self):
        """Test reading packets from a PCAP file."""
        # Initialize the capture module
        capture = frame_capturer.FrameCapture()
        
        # Read from the test pcap file
        result = capture.read_pcap(self.test_pcap)
        
        # Verify results
        self.assertEqual(len(result), 5)
        self.assertEqual(capture.stats["total_packets"], 5)
        self.assertEqual(capture.stats["tcp_count"], 2)
        self.assertEqual(capture.stats["udp_count"], 2)
        self.assertEqual(capture.stats["icmp_count"], 1)
        
        logger.info("PCAP reading test successful")
    
    def test_write_to_pcap(self):
        """Test writing packets to a PCAP file."""
        output_pcap = os.path.join(self.test_dir, "output.pcap")
        
        # Initialize capture module
        capture = frame_capturer.FrameCapture()
        
        # Write packets to new pcap
        capture.write_pcap(self.sample_packets, output_pcap)
        
        # Verify file was created
        self.assertTrue(os.path.exists(output_pcap))
        
        # Read back and verify
        read_packets = rdpcap(output_pcap)
        self.assertEqual(len(read_packets), 5)
        
        # Clean up
        os.remove(output_pcap)
        
        logger.info("PCAP writing test successful")
    
    @patch('networking_tester.capture.frame_capture.sniff')
    def test_capture_with_filter(self, mock_sniff):
        """Test capturing packets with a BPF filter."""
        # Set up the mock to return filtered packets
        filtered_packets = [
            self.sample_packets[0],  # TCP packet
            self.sample_packets[3]   # Another TCP packet
        ]
        mock_sniff.return_value = filtered_packets
        
        # Test capture with filter
        capture = frame_capturer.FrameCapture()
        result = capture.start_capture(
            interface="eth0", 
            count=5, 
            filter_str="tcp port 80 or tcp port 443"
        )
        
        # Verify capture results
        self.assertEqual(len(result), 2)
        
        # Check that the filter was passed to sniff
        mock_sniff.assert_called_once_with(
            iface="eth0", count=5, timeout=None, 
            filter="tcp port 80 or tcp port 443",  # Filter should be passed through
            store=True, prn=capture._packet_callback
        )
        
        logger.info("Capture with filter test successful")
    
    def test_packet_analysis_callback(self):
        """Test that packet callback correctly analyzes packets."""
        # Initialize capture with a mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_packet.return_value = {
            'protocol': 'TCP',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2'
        }
        
        capture = frame_capturer.FrameCapture(analyzer=mock_analyzer)
        
        # Process a packet through the callback
        packet = self.sample_packets[0]
        capture._packet_callback(packet)
        
        # Verify analyzer was called
        mock_analyzer.analyze_packet.assert_called_once_with(packet)
        
        # Check that packet was added to results and stats updated
        self.assertEqual(len(capture.captured_packets), 1)
        self.assertEqual(capture.stats["total_packets"], 1)
        
        logger.info("Packet analysis callback test successful")
    
    @patch('networking_tester.capture.frame_capture.sniff')
    def test_error_handling(self, mock_sniff):
        """Test error handling during capture."""
        # Set up mock to simulate an error
        mock_sniff.side_effect = Exception("Interface not found")
        
        # Test capture with error
        capture = frame_capturer.FrameCapture()
        
        # Capture should handle the exception and return empty list
        result = capture.start_capture(interface="nonexistent0")
        
        self.assertEqual(result, [])
        self.assertEqual(capture.stats["error_count"], 1)
        
        logger.info("Error handling test successful")
    
    def test_capture_statistics(self):
        """Test the generation of capture statistics."""
        # Initialize capture
        capture = frame_capturer.FrameCapture()
        
        # Manually add packets to simulate capture
        for packet in self.sample_packets:
            capture._packet_callback(packet)
        
        # Generate statistics
        stats = capture.get_statistics()
        
        # Verify statistics
        self.assertEqual(stats["total_packets"], 5)
        self.assertEqual(stats["tcp_count"], 2)
        self.assertEqual(stats["udp_count"], 2)
        self.assertEqual(stats["icmp_count"], 1)
        self.assertEqual(stats["error_count"], 0)
        
        # Check for timestamp ranges
        self.assertIn("start_time", stats)
        self.assertIn("end_time", stats)
        
        # Check protocol distribution
        self.assertIn("protocol_distribution", stats)
        self.assertEqual(stats["protocol_distribution"]["TCP"], 40.0)  # 2/5 = 40%
        self.assertEqual(stats["protocol_distribution"]["UDP"], 40.0)  # 2/5 = 40%
        self.assertEqual(stats["protocol_distribution"]["ICMP"], 20.0)  # 1/5 = 20%
        
        logger.info("Capture statistics test successful")
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_capture_summary(self, mock_stdout):
        """Test printing a summary of captured packets."""
        # Initialize capture and add packets
        capture = frame_capturer.FrameCapture()
        for packet in self.sample_packets:
            capture._packet_callback(packet)
        
        # Print summary
        capture.print_summary()
        
        # Verify output
        output = mock_stdout.getvalue()
        self.assertIn("Total packets captured: 5", output)
        self.assertIn("TCP: 2", output)
        self.assertIn("UDP: 2", output)
        self.assertIn("ICMP: 1", output)
        
        logger.info("Print capture summary test successful")
    
    @patch('networking_tester.capture.frame_capture.AsyncSniffer')
    def test_async_capture(self, mock_async_sniffer):
        """Test asynchronous packet capture."""
        # Create mock for AsyncSniffer
        mock_sniffer = MagicMock()
        mock_async_sniffer.return_value = mock_sniffer
        
        # Initialize capture
        capture = frame_capturer.FrameCapture()
        
        # Start async capture
        capture.start_async_capture(interface="eth0")
        
        # Verify AsyncSniffer was called correctly
        mock_async_sniffer.assert_called_once()
        mock_sniffer.start.assert_called_once()
        
        # Stop capture
        capture.stop_async_capture()
        
        # Verify stop was called
        mock_sniffer.stop.assert_called_once()
        
        logger.info("Async capture test successful")


if __name__ == '__main__':
    unittest.main()
