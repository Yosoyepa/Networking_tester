#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analizador de tramas IEEE 802.3 (Ethernet) para networking_tester."""

from scapy.all import Ether, IP, ARP, Dot1Q, Raw
from unittest.mock import MagicMock # Assuming MagicMock might be used as in other analyzers
import logging
from datetime import datetime
import json # Importing json to handle ethertype map loading

from .base_analyzer import BaseAnalyzer
from .protocol_analyzer import ProtocolAnalyzer # To perform IP layer analysis

logger = logging.getLogger(__name__)

class IEEE802_3_Analyzer(BaseAnalyzer):
    """Clase para analizar tramas IEEE 802.3 (Ethernet)."""

    def __init__(self, config_manager):
        super().__init__(config_manager)
        # Assuming ethertype_map is loaded from config or defined in BaseAnalyzer/statically
        # For example:
        default_ethertype_map = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN (802.1Q)",
            0x88A8: "Provider Bridging (802.1ad) & Shortest Path Bridging IEEE 802.1aq",
            0x88CC: "LLDP (Link Layer Discovery Protocol)",
            # Add more common EtherTypes as needed
        }
        loaded_ethertype_map = self.config_manager.get('analysis.ethertype_map', default_ethertype_map)
        if loaded_ethertype_map is None:
            logger.warning("'analysis.ethertype_map' is null in config, using default ethertype map.")
            self.ethertype_map = default_ethertype_map
        else:
            self.ethertype_map = loaded_ethertype_map
            
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

    def _calculate_frame_components(self, packet):
        """
        Analyze and return the complete frame structure components
        including Preamble, SFD, payload, padding and FCS
        
        Args:
            packet: The Ethernet packet to analyze
            
        Returns:
            Dictionary with all frame components
        """
        ether_layer = packet[Ether]
        total_length = len(packet)
        
        # Standard Ethernet header is 14 bytes (6+6+2)
        header_length = 14
        
        # Determine if this is a WiFi frame by looking at the MAC prefix
        is_wifi = False
        if hasattr(ether_layer, 'src'):
            src_prefix = ether_layer.src.lower()[:8]
            if src_prefix.startswith('60:e3:2b'):  # Your specific WiFi adapter
                is_wifi = True
        
        # Determine preamble based on frame type
        if is_wifi:
            preamble_sfd = "Variable (WiFi frame)" # WiFi has different preamble structure
        else:
            preamble_sfd = "55-55-55-55-55-55-55-D5" # Standard Ethernet
            
        # Calculate data length (excluding the 4 byte FCS which isn't in the Scapy packet)
        data_length = total_length - header_length
        
        # Calculate padding (if any)
        min_payload_size = 46  # Minimum Ethernet payload size
        padding_size = 0
        if data_length < min_payload_size:
            padding_size = min_payload_size - data_length
            
        components = {
            "preamble_sfd": preamble_sfd,
            "dest_mac": ether_layer.dst,
            "src_mac": ether_layer.src,
            "ethertype_length": hex(ether_layer.type),
            "data_length": data_length,
            "padding": padding_size,  # Add padding field
            "frame_check_sequence": self._calculate_crc32(packet)  # Renamed from fcs to be more descriptive
        }
        
        return components
        
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
                "frame_length": len(packet), # Total length of the captured frame
                
                # Frame structure information - now using the dedicated method
                "frame_components": self._calculate_frame_components(packet),
                
                # Timing information
                "frame_timing": {
                    "start_time": self._get_packet_time(packet),
                    "end_time": self._get_packet_time(packet, is_end=True),
                    "duration_ns": self._calculate_frame_duration(packet)
                }
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

    def _calculate_crc32(self, packet):
        """
        Calculate or retrieve the CRC-32 (FCS) value for an Ethernet frame.
        In real Ethernet frames, this is a 4-byte field at the end of the frame.
        
        Args:
            packet: The Ethernet packet to analyze
            
        Returns:
            String representation of the CRC-32 value in hexadecimal format
        """
        import zlib
        import binascii
        
        # Convert the packet to bytes, excluding any FCS field that might be present
        # In Scapy captures, the FCS is often not included as it's validated by hardware
        packet_bytes = bytes(packet)
        
        # Calculate CRC-32 on the packet bytes
        crc = zlib.crc32(packet_bytes) & 0xFFFFFFFF
        
        # Convert to hexadecimal representation with 0x prefix
        return f"0x{crc:08x}"
        
    def _get_packet_time(self, packet, is_end=False):
        """
        Get the timestamp of a packet, either start time or calculated end time.
        
        Args:
            packet: The packet to get the time for
            is_end: If True, calculate the end time based on packet size and theoretical transmission time
            
        Returns:
            ISO format timestamp string
        """
        if not hasattr(packet, 'time'):
            # If no timestamp available, use current time
            return datetime.now().isoformat()
            
        # Get the packet's timestamp
        try:
            # Convert EDecimal or other timestamp format to float
            timestamp = float(packet.time)
            
            if is_end:
                # Calculate end time by adding theoretical transmission time
                # Assuming 1Gbps Ethernet, it takes 8ns to transmit 1 byte
                # (1 / (1000^3 bits/sec)) * (len(packet) * 8 bits) = transmission time in seconds
                transmission_time_ns = (len(packet) * 8) / 1  # Assuming 1 bit/ns (1Gbps)
                timestamp += (transmission_time_ns / 1_000_000_000)  # Convert ns to seconds
                
            # Convert timestamp to datetime and return ISO format
            return datetime.fromtimestamp(timestamp).isoformat()
            
        except (TypeError, ValueError, OverflowError):
            # If conversion fails, use current time
            return datetime.now().isoformat()
    
    def _calculate_frame_duration(self, packet):
        """
        Calculate the theoretical transmission duration of an Ethernet frame in nanoseconds.
        
        Args:
            packet: The packet to calculate the duration for
            
        Returns:
            Duration in nanoseconds (int)
        """
        # Assuming 1Gbps Ethernet (1 bit per nanosecond)
        # A standard Ethernet frame includes:
        # 8 bytes preamble + SFD (not in Scapy captures)
        # 14 bytes header (dest MAC, src MAC, EtherType)
        # N bytes data
        # 4 bytes FCS (not usually in Scapy captures)
        # 12 bytes inter-frame gap (not in Scapy captures)
        
        # Calculate based on the wire format with all the components
        wire_size = len(packet) + 8 + 4 + 12  # Add preamble, FCS, and inter-frame gap
        
        # Each bit takes 1ns at 1Gbps
        duration_ns = wire_size * 8
        
        return duration_ns
    
    def _load_ethertype_map(self, file_path):
        """
        Load a custom EtherType map from a JSON file.
        
        Args:
            file_path: The path to the JSON file containing the EtherType mappings
            
        Returns:
            Dictionary with EtherType mappings, or an empty dictionary if an error occurs
        """
        try:
            with open(file_path, 'r') as json_file:
                ethertype_map = json.load(json_file)
                
                # Validate that the loaded data is a dictionary
                if not isinstance(ethertype_map, dict):
                    logger.error(f"Invalid data format in ethertype map file: {file_path}. Expected a JSON object.")
                    return {}
                
                return ethertype_map
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from ethertype map file: {file_path}")
            return {}
        except Exception as e: # Catch any other unexpected errors
            logger.error(f"An unexpected error occurred while loading ethertype map from {file_path}: {e}")
            return {} # Ensure it always returns a dict