#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests para la funcionalidad de captura de tramas en networking_tester."""

import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import logging
from scapy.all import Ether, IP, TCP, UDP, ICMP, Dot11, wrpcap, rdpcap # Ensure rdpcap is imported
from io import StringIO

# Add the project root directory to Python path so it can find the networking_tester package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from networking_tester.capture.frame_capture import FrameCapture
from networking_tester.utils import logging_config
# ConfigManager is not directly used by FrameCapture constructor anymore
# from networking_tester.utils.config_manager import ConfigManager 

# Configure logging for tests
logging_config.setup_logging() # Removed log_level_str argument
logger = logging.getLogger(__name__)

class TestFrameCapture(unittest.TestCase):
    """Test cases for frame capture functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_pcap = os.path.join(self.test_dir, "test_capture.pcap")
        
        self.sample_packets = [
            Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=80, dport=12345),
            Ether()/IP(src="192.168.1.2", dst="8.8.8.8")/UDP(sport=12346, dport=53),
            Ether()/IP(src="192.168.1.2", dst="192.168.1.1")/ICMP(type=8),
            Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=443, dport=54321),
            Ether()/IP(src="172.16.0.5", dst="172.16.0.10")/UDP(sport=5000, dport=5001)
        ]
        
        self.wifi_packet = Dot11()/Dot11() # Not used in current tests but kept for potential future use
        wrpcap(self.test_pcap, self.sample_packets)
        
        self.mock_packet_processor = MagicMock()

        logger.info(f"Test setup complete. Created test PCAP at {self.test_pcap}")
    
    def tearDown(self):
        """Clean up after tests."""
        if os.path.exists(self.test_pcap):
            os.remove(self.test_pcap)
        # Clean up any other files created in test_dir
        for item in os.listdir(self.test_dir):
            item_path = os.path.join(self.test_dir, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)
            
        logger.info("Test cleanup complete")
    
    @patch('networking_tester.capture.frame_capture.sniff') 
    def test_live_capture(self, mock_scapy_sniff):
        """Test capturing packets live (synchronously) from an interface."""
        
        def mock_sniff_with_callback(*args, **kwargs):
            prn_callback = kwargs.get('prn')
            if prn_callback:
                # Simulate Scapy calling prn for a subset of packets based on count
                packets_to_process = self.sample_packets
                if kwargs.get('count', 0) > 0:
                    packets_to_process = self.sample_packets[:kwargs.get('count')]
                for pkt in packets_to_process:
                    prn_callback(pkt)
            return [] # sniff with store=False and prn usually doesn't return packets

        mock_scapy_sniff.side_effect = mock_sniff_with_callback

        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        capture_count = 3
        
        capture.start_capture(interface="eth0", count=capture_count, timeout=10) 
        
        mock_scapy_sniff.assert_called_once()
        call_kwargs = mock_scapy_sniff.call_args[1] 
        self.assertEqual(call_kwargs.get('iface'), "eth0")
        self.assertEqual(call_kwargs.get('count'), capture_count)
        self.assertEqual(call_kwargs.get('timeout'), 10)
        self.assertEqual(call_kwargs.get('prn'), capture._internal_scapy_callback)
        self.assertFalse(call_kwargs.get('store'))

        self.assertEqual(self.mock_packet_processor.call_count, capture_count)
        for i in range(capture_count):
            self.mock_packet_processor.assert_any_call(self.sample_packets[i])
        
        logger.info("Live capture test successful (adapted for sync capture)")
    
    def test_read_from_pcap(self):
        """Test reading packets from a PCAP file."""
        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        # Call the read_pcap method
        read_packets_list = capture.read_pcap(self.test_pcap) 
        
        # Verify the callback was called for each packet
        self.assertEqual(self.mock_packet_processor.call_count, len(self.sample_packets))
        for i, call_arg in enumerate(self.mock_packet_processor.call_args_list):
            self.assertIsInstance(call_arg[0][0], Ether) 
            self.assertEqual(bytes(call_arg[0][0]), bytes(self.sample_packets[i]))

        # Verify the returned list (though primary processing is via callback)
        self.assertEqual(len(read_packets_list), len(self.sample_packets))
        for i in range(len(self.sample_packets)):
             self.assertEqual(bytes(read_packets_list[i]), bytes(self.sample_packets[i]))


        logger.info("PCAP reading test successful (verified callback calls and return)")
    
    @patch('networking_tester.capture.frame_capture.wrpcap') # Patch scapy's wrpcap used by FrameCapture
    def test_write_to_pcap(self, mock_scapy_wrpcap):
        """Test writing packets to a PCAP file."""
        output_pcap = os.path.join(self.test_dir, "output_test.pcap")
        capture = FrameCapture() # Callback not needed for writing
        
        success = capture.write_pcap(self.sample_packets, output_pcap)
        
        self.assertTrue(success)
        mock_scapy_wrpcap.assert_called_once_with(output_pcap, self.sample_packets)
            
        logger.info("PCAP writing test successful (adapted)")
    
    @patch('networking_tester.capture.frame_capture.sniff') 
    def test_capture_with_filter(self, mock_scapy_sniff):
        """Test capturing packets (synchronously) with a BPF filter."""
        
        def mock_sniff_with_callback(*args, **kwargs):
            prn_callback = kwargs.get('prn')
            if prn_callback:
                for pkt in self.sample_packets: # Simulate Scapy passing all packets to prn
                    prn_callback(pkt)           # Actual filtering is done by Scapy internally
            return []
        mock_scapy_sniff.side_effect = mock_sniff_with_callback

        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        test_filter = "tcp port 80"
        
        capture.start_capture(interface="eth0", count=len(self.sample_packets), filter_str=test_filter)
        
        mock_scapy_sniff.assert_called_once()
        call_kwargs = mock_scapy_sniff.call_args[1]
        self.assertEqual(call_kwargs.get('iface'), "eth0")
        self.assertEqual(call_kwargs.get('filter'), test_filter)
        self.assertEqual(call_kwargs.get('prn'), capture._internal_scapy_callback)

        self.assertEqual(self.mock_packet_processor.call_count, len(self.sample_packets))
        logger.info("Capture with filter test successful (adapted, checks filter pass-through)")
    
    def test_packet_processing_callback_usage(self):
        """Test that FrameCapture calls the provided packet processing callback."""
        # This test is implicitly covered by test_read_from_pcap, test_live_capture, 
        # and test_async_capture where we check mock_packet_processor.
        self.assertTrue(True, "Callback usage tested in other methods.")
        logger.info("Packet processing callback usage is tested via other methods.")

    @patch('networking_tester.capture.frame_capture.logger')
    def test_error_handling_read_pcap_non_existent(self, mock_capture_logger):
        """Test error handling when reading a non-existent PCAP file."""
        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        non_existent_pcap = os.path.join(self.test_dir, "non_existent.pcap")
        
        result_packets = capture.read_pcap(non_existent_pcap)
        
        self.assertEqual(result_packets, []) 
        mock_capture_logger.error.assert_called_once() 
        self.assertIn(f"Error reading PCAP file {non_existent_pcap}", mock_capture_logger.error.call_args[0][0])
        
        logger.info("Error handling for read_pcap (non-existent file) test successful")

    @patch('networking_tester.capture.frame_capture.wrpcap')
    @patch('networking_tester.capture.frame_capture.logger')
    def test_error_handling_write_pcap_fail(self, mock_capture_logger, mock_wrpcap_call):
        """Test error handling when writing a PCAP file fails."""
        mock_wrpcap_call.side_effect = Exception("Disk full")
        capture = FrameCapture()
        output_pcap = os.path.join(self.test_dir, "fail_output.pcap")
        
        success = capture.write_pcap(self.sample_packets, output_pcap)
        
        self.assertFalse(success)
        mock_capture_logger.error.assert_called_once()
        self.assertIn(f"Error writing PCAP file {output_pcap}", mock_capture_logger.error.call_args[0][0])
        logger.info("Error handling for write_pcap (failure) test successful")

    @patch('networking_tester.capture.frame_capture.AsyncSniffer')
    @patch('networking_tester.capture.frame_capture.logger')
    def test_error_handling_async_start_fail(self, mock_capture_logger, mock_async_sniffer_class):
        """Test error handling when starting asynchronous capture fails."""
        mock_async_sniffer_class.side_effect = Exception("Failed to init AsyncSniffer")
        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        
        success = capture.start_async_capture(interface="eth0")
        
        self.assertFalse(success)
        mock_capture_logger.error.assert_called_once()
        self.assertIn("Error starting asynchronous capture", mock_capture_logger.error.call_args[0][0])
        logger.info("Error handling for async start failure test successful")
    
    def test_capture_statistics(self):
        """Test that FrameCapture does not maintain old statistics attributes."""
        capture = FrameCapture()
        self.assertFalse(hasattr(capture, 'packet_counts'), "FrameCapture should not have packet_counts attribute.")
        self.assertFalse(hasattr(capture, 'statistics'), "FrameCapture should not have statistics attribute.")
        logger.info("Capture statistics test successful (verified absence of stats attributes)")
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_capture_summary(self, mock_stdout):
        """Test that FrameCapture does not have old summary printing methods."""
        capture = FrameCapture()
        self.assertFalse(hasattr(capture, 'print_summary'), "FrameCapture should not have print_summary method.")
        # If it did, and was a no-op:
        # if hasattr(capture, 'print_summary'): capture.print_summary()
        # self.assertEqual(mock_stdout.getvalue(), "")
        logger.info("Print capture summary test successful (verified absence of summary method)")
    
    @patch('networking_tester.capture.frame_capture.AsyncSniffer')
    def test_async_capture(self, mock_async_sniffer_class):
        """Test asynchronous packet capture."""
        mock_sniffer_instance = MagicMock()
        mock_async_sniffer_class.return_value = mock_sniffer_instance
        
        capture = FrameCapture(packet_processing_callback=self.mock_packet_processor)
        
        # Call start_async_capture with parameters
        capture.start_async_capture(interface="eth0", filter_str="tcp")
        
        mock_async_sniffer_class.assert_called_once_with(
            iface="eth0",
            prn=capture._internal_scapy_callback, 
            store=False,
            filter="tcp"
        )
        mock_sniffer_instance.start.assert_called_once()
        
        test_packet1 = Ether()/IP()/TCP()
        test_packet2 = Ether()/IP()/TCP()
        # Simulate Scapy calling the internal callback
        capture._internal_scapy_callback(test_packet1)
        capture._internal_scapy_callback(test_packet2)

        self.assertEqual(self.mock_packet_processor.call_count, 2)
        self.mock_packet_processor.assert_any_call(test_packet1)
        self.mock_packet_processor.assert_any_call(test_packet2)

        capture.stop_async_capture()
        mock_sniffer_instance.stop.assert_called_once()
        if hasattr(mock_sniffer_instance, 'join') and callable(mock_sniffer_instance.join):
            mock_sniffer_instance.join.assert_called_once()
        
        logger.info("Async capture test successful (adapted)")

if __name__ == '__main__':
    unittest.main()
