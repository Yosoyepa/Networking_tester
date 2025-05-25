"""
Feature Extractor Service - Phase 1 Implementation

Consumes ParsedPacket messages, extracts features for ML models, and publishes FeatureVector messages.
This is a clean, stable implementation focused on core functionality for Phase 1 completion.

Features:
- Robust feature extraction from parsed packet data
- Comprehensive network protocol feature support
- Error handling and logging
- Metrics tracking
- Clean dataclass handling
"""
import logging
import time
import uuid
import json
from typing import Dict, Any, Optional
import os

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import ParsedPacket, FeatureVector, PARSED_PACKETS_TOPIC, FEATURES_TOPIC
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)


class FeatureExtractorService:
    """
    Feature Extractor Service for Phase 1.
    
    Extracts comprehensive features from ParsedPacket messages and publishes FeatureVector messages.
    """
    
    def __init__(self, 
                 mq_client: RabbitMQClient,
                 input_exchange_name: str, 
                 input_queue_name: str,
                 output_exchange_name: str, 
                 output_routing_key: str):
        """
        Initializes the FeatureExtractorService.
        
        Args:
            mq_client: An instance of the message queue client.
            input_exchange_name: Exchange for the input queue.
            input_queue_name: Queue to consume ParsedPacket messages from.
            output_exchange_name: Exchange to publish FeatureVector messages to.
            output_routing_key: Routing key for publishing FeatureVector messages.
        """
        self.mq_client = mq_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.output_exchange_name = output_exchange_name
        self.output_routing_key = output_routing_key
        
        # Metrics tracking
        self.extraction_count = 0
        self.error_count = 0
        
        self._setup_messaging()

    def _setup_messaging(self):
        """Setup messaging infrastructure."""
        logger.info(f"Setting up messaging for FeatureExtractorService.")
        
        # Input: Consuming from parsed_packets_queue bound to parsed_packets_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name)
        
        # Output: Publishing to features_exchange
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name}, publishing to {self.output_exchange_name} with key {self.output_routing_key}")

    def _extract_features(self, parsed_packet: ParsedPacket) -> Optional[FeatureVector]:
        """
        Extract comprehensive features from a ParsedPacket.
        
        Args:
            parsed_packet: The ParsedPacket dataclass containing parsed packet data.
            
        Returns:
            FeatureVector with extracted features or None if extraction fails.
        """
        try:
            packet_id_val = parsed_packet.message_id
            timestamp_str = str(time.time())
            
            # Access parsed data from the dataclass
            parsed_data = parsed_packet.parsed_data
            layers = parsed_data.get('layers', {})
            metadata = parsed_data.get('metadata', {})
            
            if not packet_id_val:
                logger.error(f"ParsedPacket missing message_id: {parsed_packet}")
                return None

            features: Dict[str, float] = {}

            # Extract comprehensive features
            self._extract_general_features(features, metadata)
            self._extract_ip_features(features, layers)
            self._extract_tcp_features(features, layers)
            self._extract_udp_features(features, layers)
            self._extract_wifi_features(features, layers)
            self._extract_icmp_features(features, layers)
            self._extract_payload_features(features, layers)
            self._extract_derived_features(features)
            
            # Create feature vector
            feature_vector = FeatureVector(
                message_id=str(uuid.uuid4()),
                original_packet_id=packet_id_val,
                features=features,
                timestamp=timestamp_str,
                feature_names=list(features.keys())
            )
            
            self.extraction_count += 1
            return feature_vector
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error extracting features from parsed packet {parsed_packet.message_id}: {e}", exc_info=True)
            return None

    def _extract_general_features(self, features: Dict[str, float], metadata: Dict[str, Any]):
        """Extract general packet features."""
        features['frame_length'] = float(metadata.get('original_length', 0) or 
                                       metadata.get('raw_frame_length', 0) or
                                       metadata.get('raw_frame_data_len', 0))

    def _extract_ip_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract IP layer features."""
        if 'ip' in layers:
            ip_layer = layers['ip']
            features['ip_version'] = float(ip_layer.get('version', 0))
            features['ip_ihl'] = float(ip_layer.get('ihl', 0))
            features['ip_tos'] = float(ip_layer.get('tos', 0))
            features['ip_len'] = float(ip_layer.get('len', 0))
            features['ip_id'] = float(ip_layer.get('id', 0))
            features['ip_flags'] = float(ip_layer.get('flags', 0))
            features['ip_frag'] = float(ip_layer.get('frag', 0))
            features['ip_ttl'] = float(ip_layer.get('ttl', 0))
            features['ip_proto'] = float(ip_layer.get('proto', 0))
            features['ip_chksum'] = float(ip_layer.get('chksum', 0))
            
            # Extract IP addresses as numeric features (last octet as feature)
            src_ip = ip_layer.get('src', '0.0.0.0')
            dst_ip = ip_layer.get('dst', '0.0.0.0')
            try:
                features['ip_src_last_octet'] = float(src_ip.split('.')[-1])
                features['ip_dst_last_octet'] = float(dst_ip.split('.')[-1])
            except (ValueError, IndexError):
                features['ip_src_last_octet'] = 0.0
                features['ip_dst_last_octet'] = 0.0

    def _extract_tcp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract TCP layer features."""
        if 'tcp' in layers:
            tcp_layer = layers['tcp']
            features['tcp_sport'] = float(tcp_layer.get('sport', 0))
            features['tcp_dport'] = float(tcp_layer.get('dport', 0))
            features['tcp_seq'] = float(tcp_layer.get('seq', 0))
            features['tcp_ack'] = float(tcp_layer.get('ack', 0))
            features['tcp_dataofs'] = float(tcp_layer.get('dataofs', 0))
            features['tcp_reserved'] = float(tcp_layer.get('reserved', 0))
            features['tcp_flags'] = float(tcp_layer.get('flags', 0))
            features['tcp_window'] = float(tcp_layer.get('window', 0))
            features['tcp_chksum'] = float(tcp_layer.get('chksum', 0))
            features['tcp_urgptr'] = float(tcp_layer.get('urgptr', 0))
            
            # TCP flag bits
            flags = tcp_layer.get('flags', 0)
            features['tcp_flag_fin'] = float((flags & 0x01) > 0)
            features['tcp_flag_syn'] = float((flags & 0x02) > 0)
            features['tcp_flag_rst'] = float((flags & 0x04) > 0)
            features['tcp_flag_psh'] = float((flags & 0x08) > 0)
            features['tcp_flag_ack'] = float((flags & 0x10) > 0)
            features['tcp_flag_urg'] = float((flags & 0x20) > 0)
        else:
            # Set TCP features to 0 if no TCP layer
            tcp_features = ['tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_dataofs', 
                          'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr',
                          'tcp_flag_fin', 'tcp_flag_syn', 'tcp_flag_rst', 'tcp_flag_psh', 
                          'tcp_flag_ack', 'tcp_flag_urg']
            for feat in tcp_features:
                features[feat] = 0.0

    def _extract_udp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract UDP layer features."""
        if 'udp' in layers:
            udp_layer = layers['udp']
            features['udp_sport'] = float(udp_layer.get('sport', 0))
            features['udp_dport'] = float(udp_layer.get('dport', 0))
            features['udp_len'] = float(udp_layer.get('len', 0))
            features['udp_chksum'] = float(udp_layer.get('chksum', 0))
        else:
            # Set UDP features to 0 if no UDP layer
            udp_features = ['udp_sport', 'udp_dport', 'udp_len', 'udp_chksum']
            for feat in udp_features:
                features[feat] = 0.0

    def _extract_wifi_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract WiFi/802.11 layer features."""
        if 'wifi' in layers or '802.11' in layers:
            wifi_layer = layers.get('wifi', layers.get('802.11', {}))
            features['wifi_type'] = float(wifi_layer.get('type', 0))
            features['wifi_subtype'] = float(wifi_layer.get('subtype', 0))
            features['wifi_flags'] = float(wifi_layer.get('flags', 0))
            features['wifi_duration'] = float(wifi_layer.get('duration', 0))
            features['wifi_seq'] = float(wifi_layer.get('seq', 0))
        else:
            # Set WiFi features to 0 if no WiFi layer
            wifi_features = ['wifi_type', 'wifi_subtype', 'wifi_flags', 'wifi_duration', 'wifi_seq']
            for feat in wifi_features:
                features[feat] = 0.0

    def _extract_icmp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract ICMP layer features."""
        if 'icmp' in layers:
            icmp_layer = layers['icmp']
            features['icmp_type'] = float(icmp_layer.get('type', 0))
            features['icmp_code'] = float(icmp_layer.get('code', 0))
            features['icmp_chksum'] = float(icmp_layer.get('chksum', 0))
            features['icmp_id'] = float(icmp_layer.get('id', 0))
            features['icmp_seq'] = float(icmp_layer.get('seq', 0))
        else:
            # Set ICMP features to 0 if no ICMP layer
            icmp_features = ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq']
            for feat in icmp_features:
                features[feat] = 0.0

    def _extract_payload_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract payload-related features."""
        raw_data = layers.get('raw', {})
        if isinstance(raw_data, dict):
            payload = raw_data.get('load', b'')
        else:
            payload = raw_data
            
        if isinstance(payload, str):
            payload = payload.encode('utf-8', errors='ignore')
        elif not isinstance(payload, bytes):
            payload = b''
            
        features['payload_length'] = float(len(payload))
        features['payload_entropy'] = self._calculate_entropy(payload)

    def _extract_derived_features(self, features: Dict[str, float]):
        """Extract derived features from existing features."""
        # Protocol type indicators
        features['is_tcp'] = float(features.get('tcp_sport', 0) > 0)
        features['is_udp'] = float(features.get('udp_sport', 0) > 0)
        features['is_icmp'] = float(features.get('icmp_type', 0) > 0)
        features['is_wifi'] = float(features.get('wifi_type', 0) > 0)
        
        # Port categories (well-known, registered, dynamic)
        tcp_sport = features.get('tcp_sport', 0)
        tcp_dport = features.get('tcp_dport', 0)
        udp_sport = features.get('udp_sport', 0)
        udp_dport = features.get('udp_dport', 0)
        
        features['has_well_known_port'] = float(
            any(port < 1024 for port in [tcp_sport, tcp_dport, udp_sport, udp_dport] if port > 0)
        )
        
        # Size categories
        frame_length = features.get('frame_length', 0)
        features['is_small_packet'] = float(frame_length < 64)
        features['is_large_packet'] = float(frame_length > 1500)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
              # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability).bit_length()
                
        return entropy

    def _on_message_callback(self, message_data: Dict[str, Any]):
        """Callback function for processing consumed messages."""
        try:
            logger.debug(f"Received message: {message_data}")
            
            # Convert dict to ParsedPacket dataclass
            parsed_packet = ParsedPacket.from_json(json.dumps(message_data))
            
            # Extract features
            feature_vector = self._extract_features(parsed_packet)
            
            if feature_vector:
                # Publish the FeatureVector message
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=json.loads(feature_vector.to_json())
                )
                logger.debug(f"Published FeatureVector for packet {parsed_packet.message_id}")
            
        except Exception as e:
            logger.error(f"Error processing message in FeatureExtractorService: {e}", exc_info=True)

    def start_consuming(self):
        """Start consuming messages from the input queue."""
        logger.info("FeatureExtractorService starting to consume messages...")
        
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._on_message_callback
            )
        except Exception as e:
            logger.error(f"FeatureExtractorService failed to start consuming: {e}", exc_info=True)
            raise
        finally:
            try:
                self.mq_client.close()
            except Exception:
                pass
            logger.info("FeatureExtractorService consumption finished.")

    def get_service_metrics(self) -> Dict[str, Any]:
        """Get service performance metrics."""
        return {
            "extraction_count": self.extraction_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(self.extraction_count, 1)
        }


if __name__ == '__main__':
    # Use setup_logging from utils
    setup_logging()
    
    # --- Configuration ---
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    
    # --- Input Configuration ---
    INPUT_EXCHANGE_NAME = "parsed_packets_exchange"
    INPUT_QUEUE_NAME = "parsed_packets_queue"
    
    # --- Output Configuration ---
    OUTPUT_EXCHANGE_NAME = "features_exchange"
    OUTPUT_ROUTING_KEY = "features_queue"
    
    logger.info("Feature Extractor Service starting...")
    
    mq_client_instance = None
    
    try:
        # Initialize RabbitMQ client
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST)
        
        # Create feature extractor service
        feature_extractor_service = FeatureExtractorService(
            mq_client=mq_client_instance,
            input_exchange_name=INPUT_EXCHANGE_NAME,
            input_queue_name=INPUT_QUEUE_NAME,
            output_exchange_name=OUTPUT_EXCHANGE_NAME,
            output_routing_key=OUTPUT_ROUTING_KEY
        )
        
        logger.info("Feature Extractor Service initialized successfully")
        
        # Start consuming (this will block)
        feature_extractor_service.start_consuming()
        
    except Exception as e:
        logger.error(f"Error in Feature Extractor Service: {e}", exc_info=True)
    finally:
        if mq_client_instance:
            try:
                mq_client_instance.close()
                logger.info("Closing RabbitMQ connection.")
            except Exception:
                pass
                
        logger.info("Feature Extractor Service finished.")
