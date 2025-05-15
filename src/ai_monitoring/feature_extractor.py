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

                # Ethernet Layer (assuming it's the base for IP, etc.)
                # if pkt.haslayer(Ether):
                # features['eth_src'] = pkt[Ether].src
                # features['eth_dst'] = pkt[Ether].dst
                # features['eth_type'] = pkt[Ether].type

                # IP Layer
                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    features['ip_version'] = ip_layer.version
                    features['ip_ihl'] = ip_layer.ihl
                    features['ip_tos'] = ip_layer.tos
                    features['dscp'] = ip_layer.tos >> 2 # Extract DSCP from TOS
                    features['ip_len'] = ip_layer.len
                    features['ip_id'] = ip_layer.id
                    features['ip_flags'] = int(ip_layer.flags) # Convert flags to int
                    features['ip_frag'] = ip_layer.frag
                    features['ip_ttl'] = ip_layer.ttl
                    features['ip_protocol'] = ip_layer.proto
                    features['ip_src'] = ip_layer.src
                    features['ip_dst'] = ip_layer.dst
                    features['is_ip'] = 1
                else:
                    features['is_ip'] = 0
                    # Fill with defaults if no IP layer to maintain consistent columns
                    for col in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol', 'ip_src', 'ip_dst']:
                        features[col] = 0 if col not in ['ip_src', 'ip_dst'] else '0.0.0.0'


                # Transport Layer (TCP/UDP/ICMP)
                features['is_tcp'] = 1 if pkt.haslayer(TCP) else 0
                features['is_udp'] = 1 if pkt.haslayer(UDP) else 0
                features['is_icmp'] = 1 if pkt.haslayer(ICMP) else 0

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    features['src_port'] = tcp_layer.sport
                    features['dst_port'] = tcp_layer.dport
                    features['tcp_seq'] = tcp_layer.seq
                    features['tcp_ack'] = tcp_layer.ack
                    features['tcp_dataofs'] = tcp_layer.dataofs
                    features['tcp_reserved'] = tcp_layer.reserved
                    features['tcp_flags'] = int(tcp_layer.flags) # Convert flags to int
                    features['tcp_window'] = tcp_layer.window
                    features['tcp_chksum'] = tcp_layer.chksum
                    features['tcp_urgptr'] = tcp_layer.urgptr
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    features['src_port'] = udp_layer.sport
                    features['dst_port'] = udp_layer.dport
                    features['udp_len'] = udp_layer.len
                    features['udp_chksum'] = udp_layer.chksum
                elif pkt.haslayer(ICMP):
                    icmp_layer = pkt[ICMP]
                    features['icmp_type'] = icmp_layer.type
                    features['icmp_code'] = icmp_layer.code
                    features['icmp_chksum'] = icmp_layer.chksum
                    # Set sport/dport to 0 for ICMP for consistent columns
                    features['src_port'] = 0
                    features['dst_port'] = 0
                else: # No TCP/UDP/ICMP
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    for col in ['tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'udp_len', 'udp_chksum', 'icmp_type', 'icmp_code', 'icmp_chksum']:
                         features[col] = 0


                # Wi-Fi (802.11) Layer
                features['is_wifi'] = 1 if pkt.haslayer(Dot11) else 0
                if pkt.haslayer(Dot11):
                    dot11_layer = pkt[Dot11]
                    features['wifi_fc_type'] = dot11_layer.type
                    features['wifi_fc_subtype'] = dot11_layer.subtype
                    features['wifi_fc_to_ds'] = 1 if dot11_layer.FCfield & 0x1 else 0
                    features['wifi_fc_from_ds'] = 1 if dot11_layer.FCfield & 0x2 else 0
                    features['wifi_fc_more_frag'] = 1 if dot11_layer.FCfield & 0x4 else 0
                    features['wifi_fc_retry'] = 1 if dot11_layer.FCfield & 0x8 else 0
                    features['wifi_fc_pwr_mgt'] = 1 if dot11_layer.FCfield & 0x10 else 0
                    features['wifi_fc_more_data'] = 1 if dot11_layer.FCfield & 0x20 else 0
                    features['wifi_fc_protected'] = 1 if dot11_layer.FCfield & 0x40 else 0
                    features['wifi_fc_order'] = 1 if dot11_layer.FCfield & 0x80 else 0
                    features['wifi_duration_id'] = dot11_layer.ID
                    features['wifi_addr1'] = dot11_layer.addr1
                    features['wifi_addr2'] = dot11_layer.addr2
                    features['wifi_addr3'] = dot11_layer.addr3
                    if dot11_layer.addr4: # addr4 is optional
                        features['wifi_addr4'] = dot11_layer.addr4
                    else:
                        features['wifi_addr4'] = "00:00:00:00:00:00" # Placeholder

                    # QoS Control field for TID (if present)
                    if dot11_layer.haslayer(Raw) and hasattr(dot11_layer, 'FCfield') and dot11_layer.FCfield.subtype == 8: # QoS Data frame
                        # This is a simplified check. Real QoS control field parsing is more complex.
                        # Assuming TID is in the first byte of QoS control if present.
                        # Scapy's Dot11QoS class handles this better if packets are parsed with it.
                        # For now, a placeholder or a more robust check is needed.
                        # This part might need refinement based on how Scapy exposes QoS TID.
                        # Let's assume for now it might be part of a higher-level Scapy object or requires manual parsing.
                        # For a generic Dot11, TID is not directly exposed as a simple field.
                        # We'll add a placeholder and it can be improved.
                        features['wifi_tid'] = 0 # Placeholder, needs better parsing
                    else:
                        features['wifi_tid'] = 0
                else: # No WiFi
                    for col in ['wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
                                'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                                'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id', 'wifi_addr1',
                                'wifi_addr2', 'wifi_addr3', 'wifi_addr4', 'wifi_tid']:
                        features[col] = 0 if col not in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4'] else "00:00:00:00:00:00"


                # Payload features
                if pkt.haslayer(Raw):
                    features['payload_length'] = len(pkt[Raw].load)
                else:
                    features['payload_length'] = 0
                
                # Add more features as needed, e.g., from DNS, HTTP, etc.

            except Exception as e:
                logger.error(f"Error extracting features from a packet: {e}", exc_info=True)
                # Add empty features for this packet to maintain DataFrame structure
                # This assumes we know all possible feature names.
                # A more robust way is to collect all unique keys after loop and then create DataFrame.
                # For now, we rely on the fact that most features are added conditionally.
                # If a packet causes an error, it might have fewer features than others.
                # This will be handled by df.fillna(0) later.
                pass
            features_list.append(features)

        df = pd.DataFrame(features_list)
        
        # Post-processing: Ensure all expected numeric columns exist and fill NaNs
        # Define a comprehensive list of all potential numeric columns that should default to 0
        # and string columns that should default to an empty string or placeholder.
        # This helps in creating a consistent DataFrame structure.
        
        # Example:
        # numeric_cols_expected = ['frame_length', 'timestamp', 'ip_version', ..., 'payload_length', 'wifi_tid']
        # string_cols_expected = ['ip_src', 'ip_dst', 'wifi_addr1', ...]
        # for col in numeric_cols_expected:
        #     if col not in df.columns:
        #         df[col] = 0
        # for col in string_cols_expected:
        #     if col not in df.columns:
        #         df[col] = 'N/A' # or appropriate placeholder

        # For simplicity now, just fill all NaNs that might have occurred.
        # Convert object columns that should be numeric (e.g. if some packets missed a field)
        for col in df.columns:
            if df[col].dtype == 'object':
                # Attempt to convert to numeric, if it fails, it's likely a true string column (like IP addresses)
                try:
                    # Check if it's not an address column before trying to convert to numeric
                    if col not in ['ip_src', 'ip_dst', 'wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                        df[col] = pd.to_numeric(df[col], errors='coerce') # Coerce errors to NaN
                except: # pylint: disable=bare-except
                    pass # Keep as object if conversion fails (e.g. for IP addresses)
        
        df = df.fillna(0) # Fill any NaNs (e.g. from coerce or missing fields) with 0 for numeric features
                         # For string features that became NaN, 0 might not be ideal, but models often need numeric input.
                         # Proper handling would involve one-hot encoding for categorical or specific imputation.

        logger.info(f"Extracted features for {len(df)} packets. DataFrame shape: {df.shape}")
        return df

logger.debug(f'Módulo {__name__} cargado y PacketFeatureExtractor definida.')
