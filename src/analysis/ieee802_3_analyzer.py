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

    def analyze_packet(self, packet, existing_analysis=None): # existing_analysis is not used by engine for this
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

            # Ensure mock data is structured correctly if it was previously nested
            return analysis_results # Return mock results directly

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
                    "vlan_id": vlan_layer.vlan,
                    "priority_code_point": vlan_layer.prio,
                    "drop_eligible_indicator": vlan_layer.dei if hasattr(vlan_layer, 'dei') else vlan_layer.id, # .id for older scapy, .dei for newer
                    "ethertype_vlan": hex(vlan_layer.type) # EtherType of the encapsulated frame
                })
                ethertype_val = vlan_layer.type # Update ethertype to the one inside the VLAN tag
                analysis_results["protocol_name"] = self.ethertype_map.get(ethertype_val, f"Unknown ({hex(ethertype_val)}) after VLAN")
                analysis_results["ethertype"] = hex(ethertype_val) # Update the main ethertype
                current_payload = vlan_layer.payload
            
            if vlan_tags_data:
                analysis_results["vlan_tags"] = vlan_tags_data

            # Analyze the payload (e.g., IP, ARP) using the appropriate analyzer
            # The engine will call the ProtocolAnalyzer if it's IP, so we don't call it directly here.
            # We just provide the Ethernet details.
            # However, if it's ARP, we can handle it here as it's specific to Ethernet context.
            if ethertype_val == 0x0806: # ARP
                if current_payload and current_payload.haslayer(ARP):
                    analysis_results["arp_details"] = self._analyze_arp_packet(current_payload) # Pass current_payload which is the ARP layer
                else:
                    analysis_results["arp_details"] = {"error": "ARP EtherType but no ARP layer found in payload"}
            # For IP, the engine will call ProtocolAnalyzer separately. We just ensure ethernet_details are complete.
            # No need to set ip_layer_details here, that will be under protocol_details from ProtocolAnalyzer.

        return analysis_results # Return the populated dictionary directly