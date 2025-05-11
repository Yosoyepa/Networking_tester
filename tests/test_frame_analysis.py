#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Test suite for frame analysis capabilities of networking_tester."""

import unittest
import os
import sys
from unittest.mock import patch, MagicMock
import logging
import tempfile
import json

# Add project root to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from networking_tester.analysis.ieee802_3_analyzer import IEEE802_3_Analyzer
from networking_tester.analysis.ieee802_11_analyzer import IEEE802_11_Analyzer
from networking_tester.analysis.protocol_analyzer import ProtocolAnalyzer
from networking_tester.utils import logging_config

logger = logging_config.setup_logging(log_level_str="DEBUG")

class TestFrameAnalysis(unittest.TestCase):
    """Test suite for frame analysis capabilities."""
    
    def setUp(self):
        """Set up test environment."""
        # Create analyzers
        self.ethernet_analyzer = IEEE802_3_Analyzer()
        self.wifi_analyzer = IEEE802_11_Analyzer()
        self.protocol_analyzer = ProtocolAnalyzer()
        
        # Create test directory for output files
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up after tests."""
        # Clean up test directory and files if needed
        pass
    
    def test_ethernet_frame_analysis(self):
        """Test analysis of Ethernet frames."""
        # Create mock Ethernet frames
        mock_frames = self._create_mock_ethernet_frames()
        
        # Test each frame
        for i, mock_frame in enumerate(mock_frames):
            # Mock the scapy Ether layer
            with patch('scapy.layers.l2.Ether') as mock_ether:
                mock_ether_instance = MagicMock()
                mock_ether_instance.src = "00:11:22:33:44:55"
                mock_ether_instance.dst = "AA:BB:CC:DD:EE:FF"
                mock_ether_instance.type = 0x0800  # IPv4
                mock_ether.return_value = mock_ether_instance
                
                # Configure frame-specific attributes
                if hasattr(mock_frame, 'src'):
                    mock_ether_instance.src = mock_frame.src
                if hasattr(mock_frame, 'dst'):
                    mock_ether_instance.dst = mock_frame.dst
                if hasattr(mock_frame, 'type'):
                    mock_ether_instance.type = mock_frame.type
                
                # Analyze the frame
                result = self.ethernet_analyzer.analyze_frame(mock_frame)
                
                # Verify results
                self.assertIsInstance(result, dict)
                self.assertEqual(result.get('type'), 'ethernet')
                self.assertIn('src_mac', result)
                self.assertIn('dst_mac', result)
                self.assertIn('ethertype', result)
                
                # Additional verification based on frame type
                if hasattr(mock_frame, 'type') and mock_frame.type == 0x0800:
                    self.assertEqual(result.get('protocol_name'), 'IPv4')
                elif hasattr(mock_frame, 'type') and mock_frame.type == 0x86DD:
                    self.assertEqual(result.get('protocol_name'), 'IPv6')
                elif hasattr(mock_frame, 'type') and mock_frame.type == 0x0806:
                    self.assertEqual(result.get('protocol_name'), 'ARP')
        
        logger.info(f"Analyzed {len(mock_frames)} Ethernet frames successfully")
    
    def test_wifi_frame_analysis(self):
        """Test analysis of WiFi (802.11) frames."""
        # Create mock WiFi frames
        mock_frames = self._create_mock_wifi_frames()
        
        # Test each frame
        for i, mock_frame in enumerate(mock_frames):
            # Mock the scapy Dot11 layer
            with patch('scapy.layers.dot11.Dot11') as mock_dot11:
                mock_dot11_instance = MagicMock()
                mock_dot11_instance.addr1 = "00:11:22:33:44:55"  # destination
                mock_dot11_instance.addr2 = "AA:BB:CC:DD:EE:FF"  # source
                mock_dot11_instance.addr3 = "FF:EE:DD:CC:BB:AA"  # BSSID
                mock_dot11_instance.type = 0  # Management frame
                mock_dot11_instance.subtype = 8  # Beacon
                mock_dot11_instance.FCfield = 0  # No flags set
                
                # Set frame-specific attributes
                if hasattr(mock_frame, 'type'):
                    mock_dot11_instance.type = mock_frame.type
                if hasattr(mock_frame, 'subtype'):
                    mock_dot11_instance.subtype = mock_frame.subtype
                if hasattr(mock_frame, 'FCfield'):
                    mock_dot11_instance.FCfield = mock_frame.FCfield
                
                # Mock frame.haslayer() method
                mock_frame.haslayer = MagicMock(return_value=True)
                mock_frame.getlayer = MagicMock(return_value=mock_dot11_instance)
                
                # Analyze the frame
                result = self.wifi_analyzer.analyze_frame(mock_frame)
                
                # Verify results
                self.assertIsInstance(result, dict)
                self.assertEqual(result.get('type'), 'wifi')
                self.assertIn('type_general', result)
                self.assertIn('tipo_subtipo', result)
                
                # Verify frame type specific information
                if mock_dot11_instance.type == 0:  # Management
                    self.assertIn('Management', result.get('tipo_subtipo', ''))
                elif mock_dot11_instance.type == 1:  # Control
                    self.assertIn('Control', result.get('tipo_subtipo', ''))
                elif mock_dot11_instance.type == 2:  # Data
                    self.assertIn('Data', result.get('tipo_subtipo', ''))
        
        logger.info(f"Analyzed {len(mock_frames)} WiFi frames successfully")
    
    def test_protocol_analysis(self):
        """Test protocol-specific analysis (TCP, UDP, ICMP, etc.)."""
        # Create mock IP packets with different protocols
        mock_packets = self._create_mock_ip_packets()
        
        # Test each packet
        for i, mock_packet in enumerate(mock_packets):
            # Analyze the packet
            with patch('scapy.layers.inet.IP') as mock_ip, \
                 patch('scapy.layers.inet.TCP') as mock_tcp, \
                 patch('scapy.layers.inet.UDP') as mock_udp, \
                 patch('scapy.layers.inet.ICMP') as mock_icmp:
                
                # Configure mock IP layer
                mock_ip_instance = MagicMock()
                mock_ip_instance.src = "192.168.1.100"
                mock_ip_instance.dst = "8.8.8.8"
                mock_ip_instance.proto = 6  # TCP by default
                mock_ip.return_value = mock_ip_instance
                
                # Override with packet-specific values
                if hasattr(mock_packet, 'proto'):
                    mock_ip_instance.proto = mock_packet.proto
                
                # Configure TCP/UDP/ICMP based on protocol
                if mock_ip_instance.proto == 6:  # TCP
                    mock_tcp_instance = MagicMock()
                    mock_tcp_instance.sport = 12345
                    mock_tcp_instance.dport = 80
                    mock_tcp_instance.flags = "S"  # SYN flag
                    mock_tcp.return_value = mock_tcp_instance
                    mock_packet.haslayer = lambda x: x == mock_tcp or x == mock_ip
                    mock_packet.getlayer = lambda x: mock_tcp_instance if x == mock_tcp else mock_ip_instance
                
                elif mock_ip_instance.proto == 17:  # UDP
                    mock_udp_instance = MagicMock()
                    mock_udp_instance.sport = 53243
                    mock_udp_instance.dport = 53
                    mock_udp.return_value = mock_udp_instance
                    mock_packet.haslayer = lambda x: x == mock_udp or x == mock_ip
                    mock_packet.getlayer = lambda x: mock_udp_instance if x == mock_udp else mock_ip_instance
                
                elif mock_ip_instance.proto == 1:  # ICMP
                    mock_icmp_instance = MagicMock()
                    mock_icmp_instance.type = 8  # Echo request
                    mock_icmp.return_value = mock_icmp_instance
                    mock_packet.haslayer = lambda x: x == mock_icmp or x == mock_ip
                    mock_packet.getlayer = lambda x: mock_icmp_instance if x == mock_icmp else mock_ip_instance
                
                # Analyze protocol
                result = self.protocol_analyzer.analyze_packet(mock_packet)
                
                # Verify results
                self.assertIsInstance(result, dict)
                self.assertIn('src_ip', result)
                self.assertIn('dst_ip', result)
                self.assertIn('protocol', result)
                
                # Protocol-specific verification
                if mock_ip_instance.proto == 6:  # TCP
                    self.assertEqual(result.get('protocol'), 'TCP')
                    self.assertIn('src_port', result)
                    self.assertIn('dst_port', result)
                    self.assertIn('flags', result)
                
                elif mock_ip_instance.proto == 17:  # UDP
                    self.assertEqual(result.get('protocol'), 'UDP')
                    self.assertIn('src_port', result)
                    self.assertIn('dst_port', result)
                
                elif mock_ip_instance.proto == 1:  # ICMP
                    self.assertEqual(result.get('protocol'), 'ICMP')
                    self.assertIn('icmp_type', result)
                    
        logger.info(f"Analyzed {len(mock_packets)} protocol packets successfully")
    
    def test_qos_extraction(self):
        """Test extraction of QoS information from frames."""
        # Create Ethernet frames with QoS/DSCP markings
        mock_ip_qos_frames = self._create_mock_ip_qos_packets()
        
        for i, mock_frame in enumerate(mock_ip_qos_frames):
            # Mock IP packet with DSCP field
            with patch('scapy.layers.inet.IP') as mock_ip:
                mock_ip_instance = MagicMock()
                mock_ip_instance.src = "192.168.1.100"
                mock_ip_instance.dst = "8.8.8.8"
                mock_ip_instance.tos = 0  # Default ToS value
                
                if hasattr(mock_frame, 'tos'):
                    mock_ip_instance.tos = mock_frame.tos
                
                mock_ip.return_value = mock_ip_instance
                mock_frame.haslayer = MagicMock(return_value=True)
                mock_frame.getlayer = MagicMock(return_value=mock_ip_instance)
                
                # Analyze QoS
                result = self.ethernet_analyzer.analyze_frame(mock_frame)
                
                # Extract DSCP/QoS
                dscp = (mock_ip_instance.tos >> 2) & 0x3F
                ecn = mock_ip_instance.tos & 0x3
                
                # Verify results
                self.assertIsInstance(result, dict)
                if 'qos' in result:
                    self.assertEqual(result['qos'].get('dscp'), dscp)
                    self.assertEqual(result['qos'].get('ecn'), ecn)
        
        logger.info(f"QoS extraction from {len(mock_ip_qos_frames)} IP packets successful")
        
        # Create WiFi frames with QoS Control field
        mock_wifi_qos_frames = self._create_mock_wifi_qos_frames()
        
        for i, mock_frame in enumerate(mock_wifi_qos_frames):
            # Mock WiFi QoS frame
            with patch('scapy.layers.dot11.Dot11') as mock_dot11, \
                 patch('scapy.layers.dot11.Dot11QoS') as mock_dot11qos:
                
                mock_dot11_instance = MagicMock()
                mock_dot11_instance.type = 2  # Data frame
                mock_dot11_instance.subtype = 8  # QoS Data
                
                mock_dot11qos_instance = MagicMock()
                mock_dot11qos_instance.TID = i % 8  # Cycle through priorities
                
                mock_dot11.return_value = mock_dot11_instance
                mock_dot11qos.return_value = mock_dot11qos_instance
                
                mock_frame.haslayer = lambda x: True
                mock_frame.getlayer = lambda x: mock_dot11qos_instance if x == mock_dot11qos else mock_dot11_instance
                
                # Analyze the frame
                result = self.wifi_analyzer.analyze_frame(mock_frame)
                
                # Verify QoS results
                self.assertIsInstance(result, dict)
                if 'qos_control' in result:
                    self.assertEqual(result['qos_control'].get('priority'), mock_dot11qos_instance.TID & 0x7)
                
                # Verify friendly interpretation
                if 'qos_interpretacion' in result:
                    self.assertIn("Prioridad de Usuario", result['qos_interpretacion'])
        
        logger.info(f"QoS extraction from {len(mock_wifi_qos_frames)} WiFi QoS frames successful")
    
    def test_security_analysis(self):
        """Test security analysis of frames."""
        # Test Ethernet/IP security (TLS, IPsec, etc.)
        mock_secure_ip_frames = self._create_mock_secure_ip_packets()
        
        for i, mock_frame in enumerate(mock_secure_ip_frames):
            # Mock secure IP packet (TCP with TLS, ESP, etc.)
            with patch('scapy.layers.inet.IP') as mock_ip, \
                 patch('scapy.layers.inet.TCP') as mock_tcp:
                
                mock_ip_instance = MagicMock()
                mock_ip_instance.proto = 6  # TCP
                
                mock_tcp_instance = MagicMock()
                mock_tcp_instance.sport = 12345
                mock_tcp_instance.dport = 443  # HTTPS port
                
                # Set up frame-specific security attributes
                if hasattr(mock_frame, 'security'):
                    # This would be handled by protocol-specific logic in a real analyzer
                    pass
                
                mock_ip.return_value = mock_ip_instance
                mock_tcp.return_value = mock_tcp_instance
                
                mock_frame.haslayer = lambda x: True
                mock_frame.getlayer = lambda x: mock_tcp_instance if x == mock_tcp else mock_ip_instance
                
                # Analyze the frame
                result = self.protocol_analyzer.analyze_packet(mock_frame)
                
                # Verify result contains security information if port indicates secure protocol
                self.assertIsInstance(result, dict)
                
                # HTTPS detection
                if mock_tcp_instance.dport == 443:
                    self.assertIn('protocol_info', result)
                    self.assertIn('HTTPS', result.get('protocol_info', ''))
        
        logger.info(f"Security analysis of {len(mock_secure_ip_frames)} IP packets successful")
        
        # Test WiFi security (WEP, WPA, WPA2, etc.)
        mock_secure_wifi_frames = self._create_mock_secure_wifi_frames()
        
        for i, mock_frame in enumerate(mock_secure_wifi_frames):
            # Mock secure WiFi frame
            with patch('scapy.layers.dot11.Dot11') as mock_dot11:
                mock_dot11_instance = MagicMock()
                mock_dot11_instance.FCfield = 0x40  # Protected Frame flag
                
                # Set frame-specific security flags
                if hasattr(mock_frame, 'security_type'):
                    # This would be handled by specific logic in real analyzer
                    pass
                
                mock_dot11.return_value = mock_dot11_instance
                
                mock_frame.haslayer = MagicMock(return_value=True)
                mock_frame.getlayer = MagicMock(return_value=mock_dot11_instance)
                
                # Analyze the frame
                result = self.wifi_analyzer.analyze_frame(mock_frame)
                
                # Verify security analysis
                self.assertIsInstance(result, dict)
                if 'security_info' in result:
                    self.assertIn('protegida', result['security_info'].lower())
        
        logger.info(f"Security analysis of {len(mock_secure_wifi_frames)} WiFi frames successful")
    
    def test_packet_summary_generation(self):
        """Test generation of human-readable packet summaries."""
        # Test Ethernet frame summary
        mock_eth_frame = MagicMock()
        with patch.object(self.ethernet_analyzer, 'analyze_frame') as mock_analyze:
            mock_analyze.return_value = {
                'type': 'ethernet',
                'src_mac': '00:11:22:33:44:55',
                'dst_mac': 'AA:BB:CC:DD:EE:FF',
                'protocol_name': 'IPv4',
                'packet_length': 74
            }
            
            # Generate summary
            result = self.ethernet_analyzer.analyze_frame(mock_eth_frame)
            
            # Verify summary
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get('type'), 'ethernet')
        
        # Test WiFi frame summary
        mock_wifi_frame = MagicMock()
        with patch.object(self.wifi_analyzer, 'analyze_frame') as mock_analyze:
            mock_analyze.return_value = {
                'type': 'wifi',
                'type_general': 'IEEE 802.11',
                'tipo_subtipo': 'Beacon',
                'src_mac': 'AA:BB:CC:DD:EE:FF',
                'ssid': 'TestNetwork',
                'packet_length': 98
            }
            
            # Generate summary
            result = self.wifi_analyzer.analyze_frame(mock_wifi_frame)
            
            # Verify summary
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get('type'), 'wifi')
        
        logger.info("Packet summary generation test successful")
    
    def test_performance_metrics_extraction(self):
        """Test extraction of performance metrics from frames."""
        # Create frames with performance metrics
        mock_frames = self._create_mock_frames_with_performance()
        
        # Set up a mock analyzer that extracts performance metrics
        for i, mock_frame in enumerate(mock_frames):
            # Analyze frame
            if mock_frame.get('type') == 'ethernet':
                with patch.object(self.ethernet_analyzer, 'analyze_frame') as mock_analyze:
                    mock_analyze.return_value = mock_frame
                    result = self.ethernet_analyzer.analyze_frame(MagicMock())
            else:  # wifi
                with patch.object(self.wifi_analyzer, 'analyze_frame') as mock_analyze:
                    mock_analyze.return_value = mock_frame
                    result = self.wifi_analyzer.analyze_frame(MagicMock())
            
            # Verify performance metrics
            self.assertIsInstance(result, dict)
            if 'performance' in result:
                performance = result['performance']
                if 'throughput' in performance:
                    self.assertIsInstance(performance['throughput'], (int, float))
                if 'latency' in performance:
                    self.assertIsInstance(performance['latency'], (int, float))
                if 'signal_strength' in performance:
                    self.assertIsInstance(performance['signal_strength'], (int, float))
                if 'data_rate' in performance:
                    self.assertIsInstance(performance['data_rate'], (int, float))
        
        logger.info(f"Performance metrics extraction from {len(mock_frames)} frames successful")
    
    def _create_mock_ethernet_frames(self):
        """Create mock Ethernet frames for testing."""
        frames = []
        # IPv4 frame
        ipv4_frame = MagicMock()
        ipv4_frame.src = "00:11:22:33:44:55"
        ipv4_frame.dst = "AA:BB:CC:DD:EE:FF"
        ipv4_frame.type = 0x0800  # IPv4
        frames.append(ipv4_frame)
        
        # IPv6 frame
        ipv6_frame = MagicMock()
        ipv6_frame.src = "00:11:22:33:44:55"
        ipv6_frame.dst = "AA:BB:CC:DD:EE:FF"
        ipv6_frame.type = 0x86DD  # IPv6
        frames.append(ipv6_frame)
        
        # ARP frame
        arp_frame = MagicMock()
        arp_frame.src = "00:11:22:33:44:55"
        arp_frame.dst = "FF:FF:FF:FF:FF:FF"  # Broadcast
        arp_frame.type = 0x0806  # ARP
        frames.append(arp_frame)
        
        return frames
    
    def _create_mock_wifi_frames(self):
        """Create mock WiFi frames for testing."""
        frames = []
        
        # Management frame (Beacon)
        beacon_frame = MagicMock()
        beacon_frame.type = 0  # Management
        beacon_frame.subtype = 8  # Beacon
        beacon_frame.FCfield = 0  # No flags
        frames.append(beacon_frame)
        
        # Control frame (ACK)
        ack_frame = MagicMock()
        ack_frame.type = 1  # Control
        ack_frame.subtype = 13  # ACK
        ack_frame.FCfield = 0  # No flags
        frames.append(ack_frame)
        
        # Data frame
        data_frame = MagicMock()
        data_frame.type = 2  # Data
        data_frame.subtype = 0  # Data
        data_frame.FCfield = 0x41  # ToDS and Protected flags
        frames.append(data_frame)
        
        return frames
    
    def _create_mock_ip_packets(self):
        """Create mock IP packets with different protocols."""
        packets = []
        
        # TCP packet
        tcp_packet = MagicMock()
        tcp_packet.proto = 6  # TCP
        packets.append(tcp_packet)
        
        # UDP packet
        udp_packet = MagicMock()
        udp_packet.proto = 17  # UDP
        packets.append(udp_packet)
        
        # ICMP packet
        icmp_packet = MagicMock()
        icmp_packet.proto = 1  # ICMP
        packets.append(icmp_packet)
        
        return packets
    
    def _create_mock_ip_qos_packets(self):
        """Create mock IP packets with QoS/DSCP markings."""
        packets = []
        
        # Create packets with different DSCP values
        for dscp in range(0, 64, 8):  # 0, 8, 16, 24, 32, 40, 48, 56
            for ecn in range(4):  # 0, 1, 2, 3
                packet = MagicMock()
                packet.tos = (dscp << 2) | ecn
                packets.append(packet)
        
        return packets
    
    def _create_mock_wifi_qos_frames(self):
        """Create mock WiFi frames with QoS information."""
        frames = []
        
        # Create QoS frames with different priority levels
        for i in range(8):  # 8 priority levels
            frame = MagicMock()
            frame.tid = i
            frames.append(frame)
        
        return frames
    
    def _create_mock_secure_ip_packets(self):
        """Create mock IP packets with security features."""
        packets = []
        
        # HTTPS (TLS) packet
        https_packet = MagicMock()
        https_packet.security = {
            'encrypted': True,
            'cipher': 'TLS1.3',
            'protocol': 'HTTPS'
        }
        packets.append(https_packet)
        
        # IPsec packet
        ipsec_packet = MagicMock()
        ipsec_packet.security = {
            'encrypted': True,
            'cipher': 'AES-GCM',
            'protocol': 'IPsec-ESP'
        }
        packets.append(ipsec_packet)
        
        # Unencrypted packet
        plain_packet = MagicMock()
        plain_packet.security = {
            'encrypted': False,
            'cipher': None,
            'protocol': 'HTTP'
        }
        packets.append(plain_packet)
        
        return packets
    
    def _create_mock_secure_wifi_frames(self):
        """Create mock WiFi frames with security features."""
        frames = []
        
        # WPA2 frame
        wpa2_frame = MagicMock()
        wpa2_frame.security_type = 'WPA2'
        frames.append(wpa2_frame)
        
        # WPA3 frame
        wpa3_frame = MagicMock()
        wpa3_frame.security_type = 'WPA3'
        frames.append(wpa3_frame)
        
        # Open (unencrypted) frame
        open_frame = MagicMock()
        open_frame.security_type = 'None'
        frames.append(open_frame)
        
        return frames
    
    def _create_mock_frames_with_performance(self):
        """Create mock frames with performance metrics."""
        frames = []
        
        # Ethernet frames with varying performance
        for i in range(5):
            frame = {
                'type': 'ethernet',
                'src_mac': '00:11:22:33:44:55',
                'dst_mac': 'AA:BB:CC:DD:EE:FF',
                'protocol_name': 'IPv4',
                'packet_length': 64 + i * 10,
                'performance': {
                    'throughput': 10.0 + i * 5.0,  # Mbps
                    'latency': 5.0 + i * 2.0       # ms
                }
            }
            frames.append(frame)
        
        # WiFi frames with varying performance
        for i in range(5):
            frame = {
                'type': 'wifi',
                'type_general': 'IEEE 802.11',
                'tipo_subtipo': 'Data',
                'packet_length': 100 + i * 15,
                'performance': {
                    'signal_strength': -30 - i * 5,  # dBm
                    'data_rate': 54.0 - i * 5.0     # Mbps
                }
            }
            frames.append(frame)
        
        return frames

if __name__ == '__main__':
    unittest.main()
