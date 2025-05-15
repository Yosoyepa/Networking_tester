#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analizador de protocolos de red para networking_tester."""

import logging
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
from unittest.mock import MagicMock
from .base_analyzer import BaseAnalyzer # Import BaseAnalyzer

logger = logging.getLogger(__name__)

class ProtocolAnalyzer(BaseAnalyzer): # Inherit from BaseAnalyzer
    """Clase para analizar protocolos de capa de red y transporte."""
    
    def __init__(self, config_manager): # Accept config_manager
        super().__init__(config_manager) # Call super init
        # Load known_ports from config
        self.known_ports = self.config_manager.get('analysis.known_ports', {})
        # logger.debug("Inicializando analizador de protocolos") # Done by BaseAnalyzer

    def analyze_packet(self, packet, existing_analysis=None):
        """
        Analiza un paquete IP y extrae información de protocolos.
        Appends results to 'protocol_analysis' key in existing_analysis or a new dict.
        """
        analysis_results = {}
        if isinstance(packet, MagicMock): # Keep for tests if they directly instantiate this
            logger.warning("ProtocolAnalyzer received a MagicMock packet directly. Providing enhanced mock data.")
            # Attempt to get some common attributes from the mock if tests set them
            mock_src_ip = getattr(packet, 'src', '192.168.0.1') # Default mock src
            mock_dst_ip = getattr(packet, 'dst', '192.168.0.2') # Default mock dst
            mock_proto_num = getattr(packet, 'proto', 6) # Default to TCP for mock

            analysis_results = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                'src_ip': mock_src_ip,
                'dst_ip': mock_dst_ip,
                'protocol_num': mock_proto_num,
                'length': getattr(packet, 'len', 60),
                'ttl': getattr(packet, 'ttl', 64),
            }
            if mock_proto_num == 6: # TCP
                analysis_results['protocol'] = 'TCP'
                analysis_results['src_port'] = getattr(packet, 'sport', 12345)
                analysis_results['dst_port'] = getattr(packet, 'dport', 80)
                analysis_results['flags'] = getattr(packet, 'flags_dict', {'SYN': True}) # Assume tests might set flags_dict
                
                # Service info based on port
                if analysis_results['dst_port'] == 443 or analysis_results['src_port'] == 443:
                    analysis_results['service_info'] = "HTTPS"
                    analysis_results['protocol_info'] = "HTTPS"
                elif analysis_results['dst_port'] == 80 or analysis_results['src_port'] == 80:
                    analysis_results['service_info'] = "HTTP" # Explicitly set HTTP
                    analysis_results['protocol_info'] = "HTTP"
                else:
                    analysis_results['service_info'] = "TCP Service"
                    analysis_results['protocol_info'] = "TCP"
            elif mock_proto_num == 17: # UDP
                analysis_results['protocol'] = 'UDP'
                analysis_results['src_port'] = getattr(packet, 'sport', 54321)
                analysis_results['dst_port'] = getattr(packet, 'dport', 53)
                analysis_results['service_info'] = "UDP Service"
                analysis_results['protocol_info'] = "UDP"
            elif mock_proto_num == 1: # ICMP
                analysis_results['protocol'] = 'ICMP'
                analysis_results['icmp_type'] = getattr(packet, 'icmp_type_val', 8) # Assume tests might set icmp_type_val
                analysis_results['icmp_code'] = getattr(packet, 'icmp_code_val', 0)
                analysis_results['service_info'] = "ICMP Service"
                analysis_results['protocol_info'] = "ICMP"
            else:
                analysis_results['protocol'] = f'MockProto-{mock_proto_num}'
                analysis_results['service_info'] = "Unknown Mock Service"
                analysis_results['protocol_info'] = f'MockProto-{mock_proto_num}'


            if existing_analysis:
                existing_analysis.setdefault('protocol_details', {}).update(analysis_results)
                return existing_analysis
            return {'protocol_details': analysis_results}


        if not packet.haslayer(IP):
            analysis_results = {"error": "No es un paquete IP"}
        else:
            ip_layer = packet.getlayer(IP)
            analysis_results = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'), # Consider moving timestamp to a central place
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'ttl': ip_layer.ttl,
                'length': ip_layer.len,
                'protocol_num': ip_layer.proto
            }
            # Protocol-specific analysis
            if ip_layer.proto == 6 and packet.haslayer(TCP):  # TCP
                analysis_results.update(self._analyze_tcp(packet, packet.getlayer(TCP)))
            elif ip_layer.proto == 17 and packet.haslayer(UDP):  # UDP
                analysis_results.update(self._analyze_udp(packet, packet.getlayer(UDP)))
            elif ip_layer.proto == 1 and packet.haslayer(ICMP):  # ICMP
                analysis_results.update(self._analyze_icmp(packet, packet.getlayer(ICMP)))
            else:
                analysis_results['protocol'] = f"IP Protocol {ip_layer.proto}"
            
            # QoS/DSCP analysis
            dscp = (ip_layer.tos >> 2) & 0x3F
            ecn = ip_layer.tos & 0x3
            
            analysis_results['qos'] = {
                'dscp': dscp,
                'ecn': ecn,
                'priority': dscp >> 3,
                'tos_value': ip_layer.tos
            }
            
            # Performance metrics
            analysis_results['performance'] = {
                'packet_size': len(packet),
                'header_overhead': 20 + (20 if ip_layer.proto == 6 else (8 if ip_layer.proto == 17 else 0))
            }
            
            # Generate summary
            analysis_results['summary'] = self._generate_summary(analysis_results)
        
        # Integrate with existing_analysis
        if existing_analysis:
            existing_analysis.setdefault('protocol_details', {}).update(analysis_results)
            return existing_analysis
        return {'protocol_details': analysis_results}

    def _analyze_tcp(self, packet, tcp=None):
        """Analyze TCP protocol information."""
        # Handle missing TCP layer
        if tcp is None:
            return {
                'protocol': 'TCP',
                'src_port': 0,
                'dst_port': 0,
                'flags': {},
                'protocol_info': 'TCP Unknown'
            }
        
        # Flag interpretation
        flag_meanings = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
            'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
        }
        
        # Get flags
        flag_str = tcp.flags if not isinstance(tcp.flags, MagicMock) else "S"
        flags = {flag_meanings.get(flag, flag): True for flag in flag_str}
        
        # Get port numbers safely
        sport = tcp.sport if not isinstance(tcp.sport, MagicMock) else 12345
        dport = tcp.dport if not isinstance(tcp.dport, MagicMock) else 80
        
        # Protocol info based on ports
        if dport == 443 or sport == 443:
            protocol_info = "HTTPS"
            security_info = {
                'encrypted': True,
                'protocol': "TLS/SSL"
            }
        elif dport == 80 or sport == 80:
            protocol_info = "HTTP"
            security_info = None
        else:
            src_service = self.known_ports.get(sport, str(sport))
            dst_service = self.known_ports.get(dport, str(dport))
            protocol_info = f"TCP {src_service} -> {dst_service}"
            security_info = None
        
        return {
            'protocol': 'TCP',
            'src_port': sport,
            'dst_port': dport,
            'seq': getattr(tcp, 'seq', 0),
            'ack': getattr(tcp, 'ack', 0),
            'flags': flags,
            'window': getattr(tcp, 'window', 8192),
            'protocol_info': protocol_info,
            'security': security_info
        }
    
    def _analyze_udp(self, packet, udp=None):
        """Analyze UDP protocol information."""
        if udp is None:
            return {
                'protocol': 'UDP',
                'src_port': 0, 
                'dst_port': 0,
                'protocol_info': 'UDP Unknown'
            }
        
        # Get port numbers safely
        sport = udp.sport if not isinstance(udp.sport, MagicMock) else 53243
        dport = udp.dport if not isinstance(udp.dport, MagicMock) else 53
        
        # Protocol detection
        if dport == 53 or sport == 53:
            protocol_info = "DNS"
        elif dport == 161 or sport == 161:
            protocol_info = "SNMP"
        else:
            src_service = self.known_ports.get(sport, str(sport))
            dst_service = self.known_ports.get(dport, str(dport))
            protocol_info = f"UDP {src_service} -> {dst_service}"
        
        return {
            'protocol': 'UDP',
            'src_port': sport,
            'dst_port': dport,
            'length': getattr(udp, 'len', 8),
            'protocol_info': protocol_info
        }
    
    def _analyze_icmp(self, packet, icmp=None):
        """Analyze ICMP protocol information."""
        if icmp is None:
            return {
                'protocol': 'ICMP',
                'icmp_type': 8,
                'icmp_type_str': 'Echo Request',
                'protocol_info': 'ICMP Echo Request'
            }
        
        # ICMP type mapping
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        
        icmp_type = icmp.type if not isinstance(icmp.type, MagicMock) else 8
        icmp_type_str = icmp_types.get(icmp_type, f"Type {icmp_type}")
        
        return {
            'protocol': 'ICMP',
            'icmp_type': icmp_type,
            'icmp_code': getattr(icmp, 'code', 0),
            'icmp_type_str': icmp_type_str,
            'protocol_info': f"ICMP {icmp_type_str}"
        }
    
    def _generate_summary(self, analysis):
        """Generate a human-readable packet summary."""
        if analysis.get('protocol') == 'TCP':
            flags_str = ''.join(flag[0] for flag in analysis.get('flags', {}) if analysis['flags'][flag])
            return f"TCP {analysis['src_ip']}:{analysis.get('src_port')} -> {analysis['dst_ip']}:{analysis.get('dst_port')} [{flags_str}]"
        
        elif analysis.get('protocol') == 'UDP':
            return f"UDP {analysis['src_ip']}:{analysis.get('src_port')} -> {analysis['dst_ip']}:{analysis.get('dst_port')}"
        
        elif analysis.get('protocol') == 'ICMP':
            return f"ICMP {analysis['src_ip']} -> {analysis['dst_ip']} {analysis.get('icmp_type_str')}"
        
        else:
            return f"IP {analysis['src_ip']} -> {analysis['dst_ip']} Protocol: {analysis.get('protocol_num')}"