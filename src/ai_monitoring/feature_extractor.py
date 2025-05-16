#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para feature_extractor dentro de networking_tester."""

import logging
import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, Dot11, Raw

logger = logging.getLogger(__name__)

class PacketFeatureExtractor:
    """
    Extracts features from Scapy packets for AI analysis.
    """
    def __init__(self):
        logger.info("PacketFeatureExtractor initialized.")

    def extract_features_to_dataframe(self, packets: list) -> pd.DataFrame:
        """
        Extracts features from a list of Scapy packets and returns a Pandas DataFrame.

        Args:
            packets (list): A list of Scapy packet objects.

        Returns:
            pd.DataFrame: A DataFrame where each row represents a packet and columns are features.
        """
        if not packets:
            return pd.DataFrame()

        features_list = []
        for pkt in packets:
            features = {}
            try:
                # General features
                features['frame_length'] = len(pkt)
                features['timestamp'] = float(pkt.time) # Scapy packet timestamp

                # IP Layer
                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    features['ip_version'] = int(ip_layer.version)
                    features['ip_ihl'] = int(ip_layer.ihl)
                    features['ip_tos'] = int(ip_layer.tos)
                    features['dscp'] = int(ip_layer.tos) >> 2 # Extract DSCP from TOS
                    features['ip_len'] = int(ip_layer.len)
                    features['ip_id'] = int(ip_layer.id)
                    features['ip_flags'] = int(ip_layer.flags) # Convert flags to int
                    features['ip_frag'] = int(ip_layer.frag)
                    features['ip_ttl'] = int(ip_layer.ttl)
                    features['ip_protocol'] = int(ip_layer.proto)
                    features['ip_src'] = str(ip_layer.src)
                    features['ip_dst'] = str(ip_layer.dst)
                    features['is_ip'] = 1
                else:
                    features['is_ip'] = 0
                    # Fill with defaults if no IP layer
                    for col in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol']:
                        features[col] = 0
                    features['ip_src'] = '0.0.0.0'
                    features['ip_dst'] = '0.0.0.0'

                # Transport Layer (TCP/UDP/ICMP)
                features['is_tcp'] = 1 if pkt.haslayer(TCP) else 0
                features['is_udp'] = 1 if pkt.haslayer(UDP) else 0
                features['is_icmp'] = 1 if pkt.haslayer(ICMP) else 0

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    features['src_port'] = int(tcp_layer.sport)
                    features['dst_port'] = int(tcp_layer.dport)
                    features['tcp_seq'] = float(tcp_layer.seq) # Use float to safely handle large sequence numbers
                    features['tcp_ack'] = float(tcp_layer.ack) # Use float to safely handle large ACK numbers
                    features['tcp_dataofs'] = float(tcp_layer.dataofs)
                    features['tcp_reserved'] = float(tcp_layer.reserved)
                    features['tcp_flags'] = float(int(tcp_layer.flags)) # Convert flags to int then float
                    features['tcp_window'] = float(tcp_layer.window)
                    features['tcp_chksum'] = float(tcp_layer.chksum)
                    features['tcp_urgptr'] = float(tcp_layer.urgptr)
                    # Set UDP and ICMP fields to 0
                    features['udp_len'] = 0.0
                    features['udp_chksum'] = 0.0
                    features['icmp_type'] = 0.0
                    features['icmp_code'] = 0.0
                    features['icmp_chksum'] = 0.0
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    features['src_port'] = int(udp_layer.sport)
                    features['dst_port'] = int(udp_layer.dport)
                    features['udp_len'] = float(udp_layer.len)
                    features['udp_chksum'] = float(udp_layer.chksum)
                    # Set TCP and ICMP fields to 0
                    features['tcp_seq'] = 0.0
                    features['tcp_ack'] = 0.0
                    features['tcp_dataofs'] = 0.0
                    features['tcp_reserved'] = 0.0
                    features['tcp_flags'] = 0.0
                    features['tcp_window'] = 0.0
                    features['tcp_chksum'] = 0.0
                    features['tcp_urgptr'] = 0.0
                    features['icmp_type'] = 0.0
                    features['icmp_code'] = 0.0
                    features['icmp_chksum'] = 0.0
                elif pkt.haslayer(ICMP):
                    icmp_layer = pkt[ICMP]
                    features['icmp_type'] = float(icmp_layer.type)
                    features['icmp_code'] = float(icmp_layer.code)
                    features['icmp_chksum'] = float(icmp_layer.chksum)
                    # Set port numbers to 0 for ICMP
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    # Set TCP and UDP fields to 0
                    features['tcp_seq'] = 0.0
                    features['tcp_ack'] = 0.0
                    features['tcp_dataofs'] = 0.0
                    features['tcp_reserved'] = 0.0
                    features['tcp_flags'] = 0.0
                    features['tcp_window'] = 0.0
                    features['tcp_chksum'] = 0.0
                    features['tcp_urgptr'] = 0.0
                    features['udp_len'] = 0.0
                    features['udp_chksum'] = 0.0
                else: # No TCP/UDP/ICMP
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    # Set all transport layer fields to 0
                    features['tcp_seq'] = 0.0
                    features['tcp_ack'] = 0.0
                    features['tcp_dataofs'] = 0.0
                    features['tcp_reserved'] = 0.0
                    features['tcp_flags'] = 0.0
                    features['tcp_window'] = 0.0
                    features['tcp_chksum'] = 0.0
                    features['tcp_urgptr'] = 0.0
                    features['udp_len'] = 0.0
                    features['udp_chksum'] = 0.0
                    features['icmp_type'] = 0.0
                    features['icmp_code'] = 0.0
                    features['icmp_chksum'] = 0.0

                # Wi-Fi (802.11) Layer - Check both for Dot11 layer and our inference markers
                has_wifi = False
                if pkt.haslayer(Dot11):
                    has_wifi = True
                    dot11_layer = pkt[Dot11]
                    features['wifi_fc_type'] = int(dot11_layer.type)
                    features['wifi_fc_subtype'] = int(dot11_layer.subtype)
                    features['wifi_fc_to_ds'] = 1 if dot11_layer.FCfield & 0x1 else 0
                    features['wifi_fc_from_ds'] = 1 if dot11_layer.FCfield & 0x2 else 0
                    features['wifi_fc_more_frag'] = 1 if dot11_layer.FCfield & 0x4 else 0
                    features['wifi_fc_retry'] = 1 if dot11_layer.FCfield & 0x8 else 0
                    features['wifi_fc_pwr_mgt'] = 1 if dot11_layer.FCfield & 0x10 else 0
                    features['wifi_fc_more_data'] = 1 if dot11_layer.FCfield & 0x20 else 0
                    features['wifi_fc_protected'] = 1 if dot11_layer.FCfield & 0x40 else 0
                    features['wifi_fc_order'] = 1 if dot11_layer.FCfield & 0x80 else 0
                    features['wifi_duration_id'] = int(dot11_layer.ID)
                    features['wifi_addr1'] = str(dot11_layer.addr1) if hasattr(dot11_layer, 'addr1') and dot11_layer.addr1 else "00:00:00:00:00:00"
                    features['wifi_addr2'] = str(dot11_layer.addr2) if hasattr(dot11_layer, 'addr2') and dot11_layer.addr2 else "00:00:00:00:00:00"
                    features['wifi_addr3'] = str(dot11_layer.addr3) if hasattr(dot11_layer, 'addr3') and dot11_layer.addr3 else "00:00:00:00:00:00"
                    features['wifi_addr4'] = str(dot11_layer.addr4) if hasattr(dot11_layer, 'addr4') and dot11_layer.addr4 else "00:00:00:00:00:00"
                    features['wifi_tid'] = 0  # Default TID
                # Check for inferred WiFi from our enhanced analyzer
                elif hasattr(pkt, '_wifi_inferred') and pkt._wifi_inferred:
                    has_wifi = True
                    # For inferred WiFi, we set basic WiFi fields with placeholder values
                    features['wifi_fc_type'] = 2  # Data frame
                    features['wifi_fc_subtype'] = 0 
                    for flag_field in ['wifi_fc_to_ds', 'wifi_fc_from_ds', 'wifi_fc_more_frag', 
                                     'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                                     'wifi_fc_protected', 'wifi_fc_order']:
                        features[flag_field] = 0
                    features['wifi_duration_id'] = 0
                    # Use MAC addresses from Ethernet layer if available
                    if hasattr(pkt, 'src'):
                        features['wifi_addr2'] = str(pkt.src)  # Source is addr2 in WiFi
                    else:
                        features['wifi_addr2'] = "00:00:00:00:00:00"
                    if hasattr(pkt, 'dst'):
                        features['wifi_addr1'] = str(pkt.dst)  # Destination is addr1 in WiFi
                    else:
                        features['wifi_addr1'] = "00:00:00:00:00:00"
                    features['wifi_addr3'] = "00:00:00:00:00:00"
                    features['wifi_addr4'] = "00:00:00:00:00:00"
                    features['wifi_tid'] = 0
                
                # Set is_wifi based on our detection
                features['is_wifi'] = 1 if has_wifi else 0
                
                # If not WiFi, populate the WiFi fields with default values
                if not has_wifi:
                    for col in ['wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
                                'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                                'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id', 'wifi_tid']:
                        features[col] = 0
                    for col in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                        features[col] = "00:00:00:00:00:00"

                # Payload features
                if pkt.haslayer(Raw):
                    features['payload_length'] = len(pkt[Raw].load)
                else:
                    features['payload_length'] = 0
                
            except Exception as e:
                logger.error(f"Error extracting features from a packet: {e}", exc_info=True)
                # Skip this packet if extraction fails
                continue
            
            features_list.append(features)

        if not features_list:
            logger.warning("No valid features could be extracted from any packet.")
            return pd.DataFrame()
            
        df = pd.DataFrame(features_list)
        
        # Fill any NaN values with zeros
        df = df.fillna(0)
        
        logger.info(f"Extracted features for {len(df)} packets. DataFrame shape: {df.shape}")
        return df

logger.debug(f'Módulo {__name__} cargado y PacketFeatureExtractor definida.')
