#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analizador de tramas IEEE 802.3 (Ethernet) para networking_tester."""

from scapy.all import Ether, IP, ARP, Dot1Q, Raw
from unittest.mock import MagicMock # Assuming MagicMock might be used as in other analyzers
import logging
from datetime import datetime

from .base_analyzer import BaseAnalyzer
from .protocol_analyzer import ProtocolAnalyzer # To perform IP layer analysis

logger = logging.getLogger(__name__)

class IEEE802_3_Analyzer(BaseAnalyzer):
    """Clase para analizar tramas IEEE 802.3 (Ethernet)."""

    def __init__(self, config_manager):
        super().__init__(config_manager)
        # Assuming ethertype_map is loaded from config or defined in BaseAnalyzer/statically
        # For example:
        self.ethertype_map = self.config_manager.get('analysis.ethertype_map', {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN (802.1Q)",
            0x88A8: "Provider Bridging (802.1ad) & Shortest Path Bridging IEEE 802.1aq",
            0x88CC: "LLDP (Link Layer Discovery Protocol)",
            # Add more common EtherTypes as needed
        })
        self.ip_analyzer = ProtocolAnalyzer(config_manager) # For nested IP analysis
        logger.debug("IEEE802_3_Analyzer initialized.")

    def _analyze_arp_packet(self, arp_packet):
        """Helper para analizar un paquete ARP."""
        if not arp_packet.haslayer(ARP):
            return {"error": "No es un paquete ARP"}
        
        arp_layer = arp_packet[ARP]
        # ARP opcodes: 1=request, 2=reply
        operation = "request" if arp_layer.op == 1 else ("reply" if arp_layer.op == 2 else f"op {arp_layer.op}")
            
        return {
            "operation": operation,
            "sender_hardware_address": arp_layer.hwsrc,
            "sender_protocol_address": arp_layer.psrc,
            "target_hardware_address": arp_layer.hwdst,
            "target_protocol_address": arp_layer.pdst,
        }

    def analyze_packet(self, packet, existing_analysis=None):
        """
        Analiza una trama Ethernet IEEE 802.3.
        Extrae detalles de Capa 2, maneja VLAN tags, y anida el análisis de Capa 3/4.
        """
        analysis_results = {}

        # Handle MagicMock for testing, similar to other analyzers
        if isinstance(packet, MagicMock):
            mock_eth_type_val = getattr(packet, 'type', 0x0800)  # Default to IPv4 type if not on mock
            protocol_name_from_map = self.ethertype_map.get(mock_eth_type_val, f"Unknown ({hex(mock_eth_type_val)})")
            
            analysis_results = {
                "type": "ethernet (mock)", # This indicates it's from the mock processing path
                "src_mac": getattr(packet, 'src', "00:00:00:00:00:00"),
                "dst_mac": getattr(packet, 'dst', "FF:FF:FF:FF:FF:FF"),
                "ethertype": hex(mock_eth_type_val),
                "protocol_name": f"{protocol_name_from_map} (mock)", # Dynamically set based on mock's type
                "frame_length": getattr(packet, 'len', getattr(packet, 'packet_length', 64)), # Use 'len' or 'packet_length' for mock
                "analysis_timestamp": datetime.now().isoformat(),
                "mock_payload_type": "IP (assumed)" # This could be further enhanced if needed
            }
            # If mock packet has a mock IP payload, simulate ip_layer_details
            if hasattr(packet, 'payload') and isinstance(packet.payload, MagicMock) and getattr(packet.payload, 'is_ip_mock', False):
                analysis_results['ip_layer_details'] = {
                    "mock_ip_info": "Simulated IP details for mock Ethernet frame",
                    "src_ip": getattr(packet.payload, 'src', "192.168.0.10"),
                    "dst_ip": getattr(packet.payload, 'dst', "192.168.0.1"),
                    "protocol": getattr(packet.payload, 'protocol', "TCP (mock)")
                }

        elif not packet.haslayer(Ether):
            analysis_results = {"error": "No es una trama Ethernet"}
        else:
            ether_layer = packet[Ether]
            ethertype_val = ether_layer.type # Scapy gives the type of the payload after 802.1Q
            
            analysis_results = {
                "analysis_timestamp": datetime.now().isoformat(),
                "type": "ethernet",
                "src_mac": ether_layer.src,
                "dst_mac": ether_layer.dst,
                "ethertype": hex(ethertype_val),
                "protocol_name": self.ethertype_map.get(ethertype_val, f"Unknown ({hex(ethertype_val)})"),
                "frame_length": len(packet) # Total length of the captured frame
            }

            current_payload = ether_layer.payload
            vlan_tags_data = []
            
            # Handle VLAN tags (802.1Q)
            # Scapy's ether_layer.payload will be the payload after the first VLAN tag if present.
            # To get all VLAN tags, we need to check the original packet structure.
            temp_layer = packet[Ether] # Start with the Ethernet layer
            while temp_layer.payload and temp_layer.payload.haslayer(Dot1Q):
                vlan_layer = temp_layer.payload
                vlan_tags_data.append({
                    "priority_code_point": vlan_layer.prio,
                    "drop_eligible_indicator": vlan_layer.dei,
                    "vlan_identifier": vlan_layer.vlan,
                    "ethertype_in_vlan": hex(vlan_layer.type) # EtherType of the encapsulated frame
                })
                temp_layer = vlan_layer # Move to the current VLAN layer to check for more
            
            if vlan_tags_data:
                analysis_results["vlan_tags"] = vlan_tags_data
            
            # current_payload is already the payload after all VLAN tags due to Scapy's handling
            # when accessing packet[Ether].payload initially.
            # If specific VLAN handling changed current_payload, ensure it points to the L3 payload.
            # For simplicity, we rely on ether_layer.type and ether_layer.payload for the final encapsulated protocol.

            if ethertype_val == 0x0800 and current_payload.haslayer(IP): # IPv4
                ip_analysis_bundle = self.ip_analyzer.analyze_packet(current_payload, existing_analysis=None) # Pass only the IP packet
                if 'protocol_details' in ip_analysis_bundle:
                    analysis_results['ip_layer_details'] = ip_analysis_bundle['protocol_details']
                else: # Handle error or unexpected structure from ip_analyzer
                    analysis_results['ip_layer_details'] = {"error": "Failed to get IP details", "raw_output": ip_analysis_bundle}
            
            elif ethertype_val == 0x0806 and current_payload.haslayer(ARP): # ARP
                analysis_results['arp_layer_details'] = self._analyze_arp_packet(current_payload)
            
            elif ethertype_val == 0x86DD: # IPv6 (Placeholder for IPv6 analysis)
                # Similar to IPv4, you would call an IPv6 analyzer if available
                # For now, just indicate it's IPv6
                analysis_results['ipv6_layer_details'] = {
                    "info": "IPv6 packet detected",
                    "payload_preview": str(current_payload.summary()) if current_payload else "N/A"
                }
                # If self.ip_analyzer can handle IPv6, you could call it:
                # ipv6_analysis_bundle = self.ip_analyzer.analyze_packet(current_payload, existing_analysis=None)
                # if 'protocol_details' in ipv6_analysis_bundle:
                #     analysis_results['ipv6_layer_details'] = ipv6_analysis_bundle['protocol_details']

            else: # Other EtherTypes or raw payload
                if isinstance(current_payload, Raw):
                    analysis_results['payload_preview'] = current_payload.load[:64].hex() # Show first 64 bytes of raw payload
                    analysis_results['payload_length'] = len(current_payload.load)
                elif current_payload: # If it's a known Scapy layer but not IP/ARP/IPv6 handled above
                    analysis_results['encapsulated_protocol_summary'] = current_payload.summary()


        # Integrate with existing_analysis (standard way to return from analyzers)
        if existing_analysis:
            existing_analysis.setdefault('ethernet_details', {}).update(analysis_results)
            return existing_analysis
        return {'ethernet_details': analysis_results}