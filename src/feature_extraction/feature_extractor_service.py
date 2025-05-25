import json
import logging
import time
import uuid
from typing import Dict, Any, Optional

import pandas as pd
from src.messaging import MessageConsumer, MessageProducer

logger = logging.getLogger(__name__)

# Define the list of all expected feature columns for consistency
# This list should be comprehensive based on the PacketFeatureExtractor logic
EXPECTED_FEATURE_COLUMNS = [
    'frame_length', 'timestamp', 
    'ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 
    'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol', 'ip_src', 'ip_dst', 'is_ip',
    'is_tcp', 'is_udp', 'is_icmp',
    'src_port', 'dst_port',
    'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 
    'tcp_window', 'tcp_chksum', 'tcp_urgptr',
    'udp_len', 'udp_chksum',
    'icmp_type', 'icmp_code', 'icmp_chksum',
    'is_wifi',
    'wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
    'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
    'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id',
    'wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4', 'wifi_tid',
    'payload_length'
]

class FeatureExtractorService:
    def __init__(self, consumer: MessageConsumer, producer: MessageProducer,
                 parsed_packets_queue: str, feature_vectors_queue: str):
        self.consumer = consumer
        self.producer = producer
        self.parsed_packets_queue = parsed_packets_queue
        self.feature_vectors_queue = feature_vectors_queue
        self._running = False
        logger.info("FeatureExtractorService initialized.")

    def _extract_features_from_parsed_packet(self, parsed_packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extracts features from a single parsed packet (JSON/dict format).
        This adapts the logic from the old PacketFeatureExtractor to work with dicts.
        """
        features: Dict[str, Any] = {}
        layers = parsed_packet_data.get('layers', {})
        if not layers: # No layers, no features
            return None

        try:
            # General features
            # features['frame_length'] = layers.get('payload', {}).get('payload_length_original', 0) # Placeholder
            features['frame_length'] = int(parsed_packet_data.get('original_frame_length', 0))
            features['timestamp'] = float(pd.to_datetime(parsed_packet_data['raw_frame_timestamp']).timestamp())

            # IP Layer
            ip_layer_data = layers.get('ip') # Prioritize IPv4
            ipv6_layer_data = layers.get('ipv6')

            if ip_layer_data:
                features['is_ip'] = 1
                features['ip_version'] = int(ip_layer_data.get('version', 4))
                features['ip_ihl'] = int(ip_layer_data.get('header_length', 0)) // 4 if ip_layer_data.get('header_length') else 0
                features['ip_tos'] = int(ip_layer_data.get('tos', 0))
                features['dscp'] = int(ip_layer_data.get('tos', 0)) >> 2
                features['ip_len'] = int(ip_layer_data.get('length', 0))
                features['ip_id'] = int(ip_layer_data.get('id', 0))
                
                ip_flags_str = str(ip_layer_data.get('flags', '0')).upper()
                flags_val = 0
                if ip_flags_str.isdigit(): # If it's already an int string
                    flags_val = int(ip_flags_str)
                else: # Parse common string representations
                    if 'DF' in ip_flags_str: flags_val |= 2
                    if 'MF' in ip_flags_str: flags_val |= 1
                    if 'EVIL' in ip_flags_str: flags_val |= 4 # Scapy's IP_FLAGS['evil'] = 0x04 / 4
                features['ip_flags'] = flags_val

                features['ip_frag'] = int(ip_layer_data.get('fragment_offset', 0))
                features['ip_ttl'] = int(ip_layer_data.get('ttl', 0))
                features['ip_protocol'] = int(ip_layer_data.get('protocol', 0))
                features['ip_src'] = str(ip_layer_data.get('source_ip', '0.0.0.0'))
                features['ip_dst'] = str(ip_layer_data.get('destination_ip', '0.0.0.0'))
            elif ipv6_layer_data:
                features['is_ip'] = 1 # Still IP
                features['ip_version'] = int(ipv6_layer_data.get('version', 6))
                features['ip_ihl'] = 0 # IPv6 has no IHL field in the same way; header is fixed 40 bytes
                features['ip_tos'] = int(ipv6_layer_data.get('traffic_class', 0))
                features['dscp'] = int(ipv6_layer_data.get('traffic_class', 0)) >> 2
                features['ip_len'] = int(ipv6_layer_data.get('payload_length', 0)) + 40 # Total length for IPv6
                features['ip_id'] = 0 # No ID field in IPv6 main header
                features['ip_flags'] = 0 # No Flags field in IPv6 main header
                features['ip_frag'] = 0 # No Fragment Offset in IPv6 main header
                features['ip_ttl'] = int(ipv6_layer_data.get('hop_limit', 0))
                features['ip_protocol'] = int(ipv6_layer_data.get('next_header', 0))
                features['ip_src'] = str(ipv6_layer_data.get('source_ip', '::'))
                features['ip_dst'] = str(ipv6_layer_data.get('destination_ip', '::'))
            else:
                features['is_ip'] = 0
                for col in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol']:
                    features[col] = 0
                features['ip_src'] = '0.0.0.0'
                features['ip_dst'] = '0.0.0.0'

            # Transport Layer
            tcp_layer_data = layers.get('tcp')
            udp_layer_data = layers.get('udp')
            icmp_layer_data = layers.get('icmp')

            features['is_tcp'] = 1 if tcp_layer_data else 0
            features['is_udp'] = 1 if udp_layer_data else 0
            features['is_icmp'] = 1 if icmp_layer_data else 0

            if tcp_layer_data:
                features['src_port'] = int(tcp_layer_data.get('source_port', 0))
                features['dst_port'] = int(tcp_layer_data.get('destination_port', 0))
                features['tcp_seq'] = float(tcp_layer_data.get('sequence_number', 0))
                features['tcp_ack'] = float(tcp_layer_data.get('acknowledgment_number', 0))
                # data_offset in parsed message is already in bytes, old extractor used Scapy's (words*4)
                # Scapy .dataofs is in 32-bit words. If schema provides bytes, use as is or divide by 4 for words.
                # The old extractor had `float(tcp_layer.dataofs)`. Assuming .dataofs was number of words.
                # If `tcp_layer_data.get('data_offset')` is header length in bytes (e.g. 20 for min TCP header):
                features['tcp_dataofs'] = float(tcp_layer_data.get('data_offset', 0)) / 4.0 if tcp_layer_data.get('data_offset') else 0.0
                features['tcp_reserved'] = 0.0 # Not in schema, default
                
                flags_val = 0
                tcp_flags_dict = tcp_layer_data.get('flags', {})
                if tcp_flags_dict.get('fin'): flags_val |= 0x01
                if tcp_flags_dict.get('syn'): flags_val |= 0x02
                if tcp_flags_dict.get('rst'): flags_val |= 0x04
                if tcp_flags_dict.get('psh'): flags_val |= 0x08
                if tcp_flags_dict.get('ack'): flags_val |= 0x10
                if tcp_flags_dict.get('urg'): flags_val |= 0x20
                if tcp_flags_dict.get('ece'): flags_val |= 0x40
                if tcp_flags_dict.get('cwr'): flags_val |= 0x80
                features['tcp_flags'] = float(flags_val)
                
                features['tcp_window'] = float(tcp_layer_data.get('window_size', 0))
                features['tcp_chksum'] = float(int(tcp_layer_data.get('checksum', '0x0'), 16)) if isinstance(tcp_layer_data.get('checksum'), str) else float(tcp_layer_data.get('checksum',0))
                features['tcp_urgptr'] = float(tcp_layer_data.get('urgent_pointer', 0))
            elif udp_layer_data:
                features['src_port'] = int(udp_layer_data.get('source_port', 0))
                features['dst_port'] = int(udp_layer_data.get('destination_port', 0))
                features['udp_len'] = float(udp_layer_data.get('length', 0))
                features['udp_chksum'] = float(int(udp_layer_data.get('checksum', '0x0'), 16)) if isinstance(udp_layer_data.get('checksum'), str) else float(udp_layer_data.get('checksum',0))
            elif icmp_layer_data:
                features['icmp_type'] = float(icmp_layer_data.get('type', 0))
                features['icmp_code'] = float(icmp_layer_data.get('code', 0))
                features['icmp_chksum'] = float(int(icmp_layer_data.get('checksum', '0x0'), 16)) if isinstance(icmp_layer_data.get('checksum'), str) else float(icmp_layer_data.get('checksum',0))
                features['src_port'] = 0
                features['dst_port'] = 0

            # Fill missing transport layer fields with defaults
            default_transport_fields = {
                'src_port':0, 'dst_port':0,
                'tcp_seq': 0.0, 'tcp_ack': 0.0, 'tcp_dataofs': 0.0, 'tcp_reserved': 0.0, 
                'tcp_flags': 0.0, 'tcp_window': 0.0, 'tcp_chksum': 0.0, 'tcp_urgptr': 0.0,
                'udp_len': 0.0, 'udp_chksum': 0.0,
                'icmp_type': 0.0, 'icmp_code': 0.0, 'icmp_chksum': 0.0
            }
            for key, val in default_transport_fields.items():
                if key not in features:
                    features[key] = val

            # Wi-Fi (802.11) Layer
            dot11_layer_data = layers.get('dot11')
            if dot11_layer_data:
                features['is_wifi'] = 1
                type_subtype = dot11_layer_data.get('type_subtype', '0/0').split('/')
                features['wifi_fc_type'] = int(type_subtype[0]) if len(type_subtype) > 0 and type_subtype[0].isdigit() else 0
                features['wifi_fc_subtype'] = int(type_subtype[1]) if len(type_subtype) > 1 and type_subtype[1].isdigit() else 0
                
                fc_flags_str = str(dot11_layer_data.get('flags', '')).lower()
                features['wifi_fc_to_ds'] = 1 if 'to-ds' in fc_flags_str else 0
                features['wifi_fc_from_ds'] = 1 if 'from-ds' in fc_flags_str else 0
                features['wifi_fc_more_frag'] = 1 if 'morefrag' in fc_flags_str else 0
                features['wifi_fc_retry'] = 1 if 'retry' in fc_flags_str else 0
                features['wifi_fc_pwr_mgt'] = 1 if 'pw-mgt' in fc_flags_str or 'pwr-mgt' in fc_flags_str else 0
                features['wifi_fc_more_data'] = 1 if 'moredata' in fc_flags_str else 0
                features['wifi_fc_protected'] = 1 if 'protected' in fc_flags_str or 'wep' in fc_flags_str else 0
                features['wifi_fc_order'] = 1 if 'order' in fc_flags_str else 0

                features['wifi_duration_id'] = int(dot11_layer_data.get('duration_id', 0))
                features['wifi_addr1'] = str(dot11_layer_data.get('address1', "00:00:00:00:00:00"))
                features['wifi_addr2'] = str(dot11_layer_data.get('address2', "00:00:00:00:00:00"))
                features['wifi_addr3'] = str(dot11_layer_data.get('address3', "00:00:00:00:00:00"))
                features['wifi_addr4'] = str(dot11_layer_data.get('address4', "00:00:00:00:00:00")) # Ensure this is correctly extracted by parser if present
                features['wifi_tid'] = 0 # Default, as TID is often in QoS headers not base Dot11
            else:
                features['is_wifi'] = 0
                for col in ['wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
                            'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                            'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id', 'wifi_tid']:
                    if col not in features: features[col] = 0 # Only set if not already defaulted by transport
                for col in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                    if col not in features: features[col] = "00:00:00:00:00:00"

            # Payload features
            payload_info = layers.get('payload')
            if payload_info and 'payload_length_original' in payload_info:
                features['payload_length'] = int(payload_info['payload_length_original'])
            elif 'payload_length' not in features: # If not set by other means (e.g. frame_length as proxy)
                features['payload_length'] = 0
            
            # Ensure all EXPECTED_FEATURE_COLUMNS are present, fill with defaults if not already handled
            for col in EXPECTED_FEATURE_COLUMNS:
                if col not in features:
                    if col in ['ip_src', 'ip_dst']:
                        features[col] = "0.0.0.0"
                    elif col in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                        features[col] = "00:00:00:00:00:00"
                    else:
                        features[col] = 0 # Default for numerical features

            # Final type conversion pass
            final_features = {}
            for key, value in features.items():
                if key in ['ip_src', 'ip_dst', 'wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                    final_features[key] = str(value) # Ensure these are strings
                elif isinstance(value, bool):
                    final_features[key] = int(value)
                elif isinstance(value, (int, float)):
                    final_features[key] = value
                elif isinstance(value, str):
                    try:
                        final_features[key] = float(value)
                    except ValueError:
                        logger.warning(f"Could not convert string feature '{key}' value '{value}' to float. Using 0.0.")
                        final_features[key] = 0.0
                else: # For any other types, attempt conversion to float or default to 0.0
                    try:
                        final_features[key] = float(value)
                    except (ValueError, TypeError):
                        logger.warning(f"Could not convert feature '{key}' value '{value}' (type {type(value)}) to float. Using 0.0.")
                        final_features[key] = 0.0
            
            return final_features

        except Exception as e:
            logger.error(f"Error extracting features from parsed packet ID {parsed_packet_data.get('parsed_packet_id', 'N/A')}: {e}", exc_info=True)
            return None


    def _process_parsed_packet_message(self, channel, method, properties, body):
        try:
            parsed_packet_msg = json.loads(body.decode('utf-8'))
            logger.debug(f"Received parsed packet: {parsed_packet_msg.get('parsed_packet_id')}")

            parsed_packet_id = parsed_packet_msg.get('parsed_packet_id', str(uuid.uuid4()))
            
            if parsed_packet_msg.get("parsing_errors") and len(parsed_packet_msg["parsing_errors"]) > 0:
                logger.warning(f"Skipping feature extraction for packet {parsed_packet_id} due to parsing errors: {parsed_packet_msg['parsing_errors']}")
                channel.basic_ack(delivery_tag=method.delivery_tag)
                return

            features = self._extract_features_from_parsed_packet(parsed_packet_msg)

            if features:
                feature_vector_msg = {
                    "schema_version": "1.0", # Define a schema version for feature vectors
                    "feature_vector_id": str(uuid.uuid4()),
                    "parsed_packet_id": parsed_packet_id,
                    "raw_frame_id": parsed_packet_msg.get("original_raw_frame_id"),
                    "extraction_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(time.time())) + ("%.6f" % (time.time() % 1))[2:] + 'Z',
                    "source_info": parsed_packet_msg.get("source_info"),
                    "features": features
                }
                self.producer.publish_message(feature_vector_msg, self.feature_vectors_queue)
                logger.debug(f"Published feature vector for parsed packet {parsed_packet_id}")
            else:
                logger.warning(f"No features extracted for parsed packet {parsed_packet_id}. Not publishing.")

            channel.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for incoming parsed packet message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except KeyError as e:
            logger.error(f"Missing key in parsed packet message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.error(f"Unexpected error processing parsed packet message: {e}", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue for potentially transient

    def start(self):
        if self._running:
            logger.info("FeatureExtractorService is already running.")
            return

        logger.info("Starting FeatureExtractorService...")
        try:
            self.consumer.connect()
            self.producer.connect()
            
            # Consumer declares parsed_packets_queue, Producer declares feature_vectors_queue
            # (Assuming this is handled by their respective methods)

            self.consumer.start_consuming(self.parsed_packets_queue, self._process_parsed_packet_message)
            self._running = True
            logger.info(f"FeatureExtractorService started. Consuming from '{self.parsed_packets_queue}' and publishing to '{self.feature_vectors_queue}'.")
            
            # Keep alive if start_consuming is not blocking
            # while self._running:
            #     time.sleep(1)

        except Exception as e:
            logger.error(f"Failed to start FeatureExtractorService: {e}", exc_info=True)
            self._running = False

    def stop(self):
        logger.info("Stopping FeatureExtractorService...")
        self._running = False
        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.close()
        logger.info("FeatureExtractorService stopped.")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    RABBITMQ_HOST = 'localhost'
    PARSED_PACKETS_QUEUE = 'parsed_packets_queue'
    FEATURE_VECTORS_QUEUE = 'feature_vectors_queue'

    # Example parsed packet message (simplified for testing)
    example_parsed_packet = {
        "schema_version": "1.0",
        "parsed_packet_id": str(uuid.uuid4()),
        "original_raw_frame_id": str(uuid.uuid4()),
        "raw_frame_timestamp": "2025-05-18T12:00:00.000000Z",
        "parsing_timestamp": "2025-05-18T12:00:01.000000Z",
        "source_info": {"type": "live_capture", "identifier": "eth_test"},
        "original_frame_length": 74, # Example: Eth(14) + IP(20) + TCP(20) + Payload(20) = 74
        "layers": {
            "ethernet": {"destination_mac": "ff:ff:ff:ff:ff:ff", "source_mac": "00:01:02:03:04:05", "ethertype": "0x0800"},
            "ip": {"version": 4, "source_ip": "192.168.1.100", "destination_ip": "192.168.1.1", "protocol": 6, "ttl": 64, "length": 60, "header_length":20, "flags": "DF", "id": 12345, "tos": 0, "fragment_offset": 0},
            "tcp": {"source_port": 12345, "destination_port": 80, "sequence_number": 1000, "acknowledgment_number": 2000, "data_offset": 20, "flags": {"syn": True, "ack":True}, "window_size": 65535, "checksum": "0xabcd", "urgent_pointer": 0},
            "payload": {"payload_bytes_base64": "SGVsbG8gV29ybGQhISEhISE=", "payload_length_original": 20 } # Hello World!!!!!!!
        },
        "parsing_errors": []
    }

    # Example for WiFi packet
    example_wifi_parsed_packet = {
        "schema_version": "1.0",
        "parsed_packet_id": str(uuid.uuid4()),
        "original_raw_frame_id": str(uuid.uuid4()),
        "raw_frame_timestamp": "2025-05-18T12:00:05.000000Z",
        "parsing_timestamp": "2025-05-18T12:00:05.100000Z",
        "source_info": {"type": "live_capture", "identifier": "wlan_test"},
        "original_frame_length": 120,
        "layers": {
            "dot11": {
                "type_subtype": "2/0", "flags": "From-DS+Retry", "duration_id": 314,
                "address1": "00:11:22:AA:BB:CC", "address2": "00:11:22:DD:EE:FF", "address3": "00:11:22:33:44:55",
                "sequence_control": 123
            },
            "llc_snap": {"llc_dsap": 170, "llc_ssap": 170, "llc_ctrl": 3, "snap_oui": 0, "snap_pid": 2048},
            "ip": {"version": 4, "source_ip": "192.168.1.150", "destination_ip": "192.168.1.1", "protocol": 17, "ttl": 128, "length": 80, "header_length": 20, "flags": "0", "id": 54321, "tos": 0, "fragment_offset": 0},
            "udp": {"source_port": 54321, "destination_port": 53, "length": 60, "checksum": "0x1234"},
            "payload": {"payload_bytes_base64": "ABCD", "payload_length_original": 4}
        },
        "parsing_errors": []
    }

    consumer = None
    producer = None
    try:
        test_producer = MessageProducer(host=RABBITMQ_HOST)
        test_producer.connect()
        test_producer.publish_message(example_parsed_packet, PARSED_PACKETS_QUEUE)
        logger.info(f"Sent test parsed packet to '{PARSED_PACKETS_QUEUE}'. ID: {example_parsed_packet['parsed_packet_id']}")
        test_producer.publish_message(example_wifi_parsed_packet, PARSED_PACKETS_QUEUE) # Send WiFi example too
        logger.info(f"Sent test WiFi parsed packet to '{PARSED_PACKETS_QUEUE}'. ID: {example_wifi_parsed_packet['parsed_packet_id']}")
        test_producer.close()

        consumer = MessageConsumer(host=RABBITMQ_HOST, prefetch_count=10)
        consumer.connect()
        consumer.start_consuming(PARSED_PACKETS_QUEUE, lambda ch, method, properties, body: logger.info(f"Test consumer received message: {body}"))

    except Exception as e:
        logger.error(f"Error in test setup: {e}", exc_info=True)
    finally:
        if consumer:
            consumer.close()
        if test_producer:
            test_producer.close()
