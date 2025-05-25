"""
Enhanced Feature Extractor Service with Model Registry Integration

Consumes ParsedPacket messages, extracts features relevant for ML models with dynamic
model-aware feature extraction capabilities, and publishes FeatureVector messages.

Features:
- Dynamic model-aware feature extraction based on active models
- Feature schema validation against deployed model requirements
- Model-specific feature filtering and transformation
- Enhanced model registry integration for feature schema management
- Dynamic feature set adaptation based on active model configurations
"""
import logging
import time
import uuid
import json
import asyncio
from typing import Dict, Any, List, Optional, Set
import os

# Removed pandas import as we process packet by packet
# from scapy.all import IP, TCP, UDP, ICMP, Dot11, Raw # Not needed directly, using parsed_packet

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import ParsedPacket, FeatureVector, PARSED_PACKETS_TOPIC, FEATURES_TOPIC
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)

class EnhancedFeatureExtractorService:
    """
    Enhanced Feature Extractor Service with Model Registry Integration.
    
    Features:
    - Dynamic model-aware feature extraction based on active models
    - Feature schema validation against deployed model requirements
    - Model-specific feature filtering and transformation
    - Enhanced model registry integration for feature schema management
    - Dynamic feature set adaptation based on active model configurations
    """
    
    def __init__(self, 
                 mq_client: RabbitMQClient,
                 model_registry_client: EnhancedModelRegistryClient,
                 input_exchange_name: str, 
                 input_queue_name: str,
                 output_exchange_name: str, 
                 output_routing_key: str,
                 active_model_configs: Optional[List[Dict[str, str]]] = None):
        """
        Initializes the Enhanced FeatureExtractorService.

        Args:
            mq_client: An instance of the message queue client.
            model_registry_client: Enhanced model registry client for dynamic model management.
            input_exchange_name: Exchange for the input queue.
            input_queue_name: Queue to consume ParsedPacket messages from.
            output_exchange_name: Exchange to publish FeatureVector messages to.
            output_routing_key: Routing key for publishing FeatureVector messages.
            active_model_configs: List of active model configurations [{model_name, model_version}].
        """
        self.mq_client = mq_client
        self.model_registry_client = model_registry_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.output_exchange_name = output_exchange_name
        self.output_routing_key = output_routing_key
        
        # Model-aware feature extraction state
        self.active_model_configs = active_model_configs or []
        self.model_feature_schemas: Dict[str, Set[str]] = {}
        self.unified_feature_schema: Set[str] = set()
        self.model_feature_requirements: Dict[str, Dict[str, Any]] = {}
        
        # Feature extraction metrics
        self.extraction_count = 0
        self.error_count = 0
        self.feature_adaptation_count = 0
        
        self._setup_messaging()
        self._initialize_model_feature_schemas()

    def _setup_messaging(self):
        """Setup messaging infrastructure."""
        logger.info(f"Setting up messaging for Enhanced FeatureExtractorService.")
        # Input: Consuming from parsed_packets_queue bound to parsed_packets_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name)
        
        # Output: Publishing to features_exchange
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name}, publishing to {self.output_exchange_name} with key {self.output_routing_key}")

    def _initialize_model_feature_schemas(self):
        """Initialize feature schemas from active models in the registry."""
        logger.info("Initializing model feature schemas from registry...")
        
        if not self.active_model_configs:
            logger.warning("No active model configurations provided. Using default feature extraction.")
            return
            
        unified_features = set()
        
        for model_config in self.active_model_configs:
            model_name = model_config.get("model_name")
            model_version = model_config.get("model_version", "latest")
            
            if not model_name:
                logger.warning(f"Invalid model configuration: {model_config}")
                continue
                
            try:
                model_details = self.model_registry_client.get_model_details(model_name, model_version)
                
                if not model_details:
                    logger.warning(f"Could not retrieve details for model '{model_name}' v{model_version}")
                    continue
                    
                # Extract feature schema from model metadata
                metadata = model_details.get("metadata", {})
                trained_features = self._extract_feature_schema_from_metadata(metadata, model_name, model_version)
                
                if trained_features:
                    model_key = f"{model_name}-{model_version}"
                    self.model_feature_schemas[model_key] = set(trained_features)
                    unified_features.update(trained_features)
                    
                    self.model_feature_requirements[model_key] = {
                        "model_name": model_name,
                        "model_version": model_version,
                        "required_features": trained_features,
                        "model_type": metadata.get("model_type"),
                        "source": model_details.get("source", "unknown")
                    }
                    
                    logger.info(f"Loaded feature schema for {model_key}: {len(trained_features)} features")
                else:
                    logger.warning(f"No feature schema found for model {model_name} v{model_version}")
                    
            except Exception as e:
                logger.error(f"Error loading feature schema for {model_name}: {e}", exc_info=True)
                
        self.unified_feature_schema = unified_features
        logger.info(f"Unified feature schema initialized with {len(unified_features)} unique features")
        logger.info(f"Active models: {list(self.model_feature_schemas.keys())}")

    def _extract_feature_schema_from_metadata(self, metadata: Dict[str, Any], model_name: str, model_version: str) -> Optional[List[str]]:
        """Extract feature schema from model metadata."""
        # Try different common metadata keys for feature schemas
        potential_keys = [
            "trained_features", 
            "feature_columns", 
            "expected_features", 
            "input_features",
            "feature_names"
        ]
        
        for key in potential_keys:
            if key in metadata and metadata[key]:
                features = metadata[key]
                if isinstance(features, list):
                    logger.debug(f"Found feature schema for {model_name} under key '{key}': {features}")
                    return features
                    
        # If no direct feature schema found, try to load from model artifacts
        try:
            model_path = metadata.get("model_path")
            if model_path and os.path.exists(model_path):
                return self._load_feature_schema_from_artifacts(model_path, metadata.get("model_type"))
        except Exception as e:
            logger.debug(f"Could not load feature schema from artifacts for {model_name}: {e}")
            
        return None
            
    def _load_feature_schema_from_artifacts(self, model_path: str, model_type: Optional[str]) -> Optional[List[str]]:
        """Load feature schema from model artifact files."""
        if not model_type:
            return None
            
        try:
            if model_type == "isolation_forest":
                features_file = os.path.join(model_path, "model.features")
                if os.path.exists(features_file):
                    with open(features_file, 'r') as f:
                        return json.load(f)
                        
            elif model_type == "gmm":
                # For GMM models, try to load from metadata file
                metadata_files = [
                    os.path.join(model_path, "model_metadata.json"),
                    os.path.join(model_path, f"{os.path.basename(model_path)}_metadata.joblib")
                ]
                
                for metadata_file in metadata_files:
                    if os.path.exists(metadata_file):
                        if metadata_file.endswith('.json'):
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                                return metadata.get("trained_features")
                        # Note: joblib files would need joblib.load, but avoiding dependency here
                        
            elif model_type == "vae":
                # VAE models might have feature schema in different format
                config_file = os.path.join(model_path, "model_config.json")
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        return config.get("input_features") or config.get("trained_features")
                        
        except Exception as e:
            logger.debug(f"Error loading feature schema from artifacts at {model_path}: {e}")
            
        return None

    def _categorize_packet_size(self, size: float) -> float:
        """Categorize packet size into bins."""
        if size <= 64:
            return 1.0
        elif size <= 128:
            return 2.0
        elif size <= 256:
            return 3.0
        elif size <= 512:
            return 4.0
        elif size <= 1024:
            return 5.0
        elif size <= 1500:
            return 6.0
        else:
            return 7.0
            
    def _categorize_protocol(self, protocol: float) -> float:
        """Categorize IP protocol numbers."""
        protocol_map = {
            1: 1.0,   # ICMP
            6: 2.0,   # TCP
            17: 3.0,  # UDP
            41: 4.0,  # IPv6
            58: 5.0,  # ICMPv6
        }
        return protocol_map.get(int(protocol), 0.0)
        
    def _categorize_ports(self, port: float) -> float:
        """Categorize port numbers into ranges."""
        port_int = int(port)
        if port_int == 0:
            return 0.0
        elif port_int <= 1023:
            return 1.0  # Well-known ports
        elif port_int <= 49151:
            return 2.0  # Registered ports
        else:
            return 3.0  # Dynamic/private ports

    def _load_feature_schema_from_artifacts(self, model_path: str, model_type: str) -> Optional[List[str]]:
        """Load feature schema from model artifact files."""        try:
            if model_type == "isolation_forest":
                features_file = os.path.join(model_path, "model.features")
                if os.path.exists(features_file):
                    with open(features_file, 'r') as f:
                        return json.load(f)
                        
            elif model_type == "gmm":
                # For GMM models, try to load from metadata file
                metadata_files = [
                    os.path.join(model_path, "model_metadata.json"),
                    os.path.join(model_path, f"{os.path.basename(model_path)}_metadata.joblib")
                ]
                
                for metadata_file in metadata_files:
                    if os.path.exists(metadata_file):
                        if metadata_file.endswith('.json'):
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                                return metadata.get("trained_features")
                        # Note: joblib files would need joblib.load, but avoiding dependency here
                        
            elif model_type == "vae":
                # VAE models might have feature schema in different format
                config_file = os.path.join(model_path, "model_config.json")
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        return config.get("input_features") or config.get("trained_features")
                        
        except Exception as e:
            logger.debug(f"Error loading feature schema from artifacts at {model_path}: {e}")
            
        return None

    def update_active_models(self, new_model_configs: List[Dict[str, str]]):
        """Update active model configurations and refresh feature schemas."""
        logger.info("Updating active model configurations...")
        self.active_model_configs = new_model_configs
        self.model_feature_schemas.clear()
        self.model_feature_requirements.clear()
        self.unified_feature_schema.clear()
        
        self._initialize_model_feature_schemas()
        self.feature_adaptation_count += 1
        logger.info(f"Feature schemas updated. Adaptation count: {self.feature_adaptation_count}")

    def _extract_features_legacy(self, parsed_packet: ParsedPacket) -> Optional[FeatureVector]:
        """
        Legacy feature extraction method for backward compatibility.
        Extracts comprehensive features from a ParsedPacket.
        """
        try:
            packet_id_val = parsed_packet.message_id
            timestamp_str = str(time.time())  # Use current timestamp if not available
            
            # Access parsed data from the dataclass
            parsed_data = parsed_packet.parsed_data
            layers = parsed_data.get('layers', {})
            metadata = parsed_data.get('metadata', {})
            
            if not packet_id_val:
                logger.error(f"ParsedPacket missing message_id: {parsed_packet}")
                return None

            features: Dict[str, float] = {}
            flow_parts: List[str] = []

            # General features
            features['frame_length'] = float(metadata.get('original_length', 0) or 
                                           metadata.get('raw_frame_length', 0) or
                                           metadata.get('raw_frame_data_len', 0))

            # IP Layer
            if 'ip' in layers:
                ip_layer = layers['ip']
                features['ip_version'] = float(ip_layer.get('version', 0))
                features['ip_ihl'] = float(ip_layer.get('ihl', 0))
                features['ip_tos'] = float(ip_layer.get('tos', 0))
                features['dscp'] = float(ip_layer.get('tos', 0)) / 4.0  # DSCP is upper 6 bits
                features['ip_len'] = float(ip_layer.get('len', 0))
                features['ip_id'] = float(ip_layer.get('id', 0))
                features['ip_flags'] = float(ip_layer.get('flags_value', 0))
                features['ip_frag'] = float(ip_layer.get('frag', 0))
                features['ip_ttl'] = float(ip_layer.get('ttl', 0))
                features['ip_protocol'] = float(ip_layer.get('proto', 0))
                
                src_ip = ip_layer.get('src_ip', '0.0.0.0')
                dst_ip = ip_layer.get('dst_ip', '0.0.0.0')
                flow_parts.extend([src_ip, dst_ip])
                
                # Convert IP addresses to numerical features (simple hash-based approach)
                features['src_ip_hash'] = float(abs(hash(src_ip)) % 65536)
                features['dst_ip_hash'] = float(abs(hash(dst_ip)) % 65536)
            else:
                # Default IP features
                for key in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 
                           'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol', 'src_ip_hash', 'dst_ip_hash']:
                    features[key] = 0.0

            # TCP Layer
            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                features['tcp_sport'] = float(tcp_layer.get('sport', 0))
                features['tcp_dport'] = float(tcp_layer.get('dport', 0))
                features['tcp_seq'] = float(tcp_layer.get('seq', 0) % 4294967296)  # Modulo to handle large numbers
                features['tcp_ack'] = float(tcp_layer.get('ack', 0) % 4294967296)
                features['tcp_flags'] = float(tcp_layer.get('flags_value', 0))
                features['tcp_window'] = float(tcp_layer.get('window', 0))
                features['tcp_chksum'] = float(tcp_layer.get('chksum', 0))
                features['tcp_urgptr'] = float(tcp_layer.get('urgptr', 0))
                
                flow_parts.extend([str(tcp_layer.get('sport', 0)), str(tcp_layer.get('dport', 0))])
            else:
                for key in ['tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_flags', 
                           'tcp_window', 'tcp_chksum', 'tcp_urgptr']:
                    features[key] = 0.0

            # UDP Layer
            if 'udp' in layers:
                udp_layer = layers['udp']
                features['udp_sport'] = float(udp_layer.get('sport', 0))
                features['udp_dport'] = float(udp_layer.get('dport', 0))
                features['udp_len'] = float(udp_layer.get('len', 0))
                features['udp_chksum'] = float(udp_layer.get('chksum', 0))
                
                flow_parts.extend([str(udp_layer.get('sport', 0)), str(udp_layer.get('dport', 0))])
            else:
                for key in ['udp_sport', 'udp_dport', 'udp_len', 'udp_chksum']:
                    features[key] = 0.0

            # WiFi/802.11 Layer
            if 'wifi' in layers:
                wifi_layer = layers['wifi']
                features['wifi_type'] = float(wifi_layer.get('type', 0))
                features['wifi_subtype'] = float(wifi_layer.get('subtype', 0))
                features['wifi_ds'] = float(wifi_layer.get('ds', 0))
                features['wifi_id'] = float(wifi_layer.get('id', 0))
            else:
                for key in ['wifi_type', 'wifi_subtype', 'wifi_ds', 'wifi_id']:
                    features[key] = 0.0

            # ICMP Layer
            if 'icmp' in layers:
                icmp_layer = layers['icmp']
                features['icmp_type'] = float(icmp_layer.get('type', 0))
                features['icmp_code'] = float(icmp_layer.get('code', 0))
                features['icmp_chksum'] = float(icmp_layer.get('chksum', 0))
                features['icmp_id'] = float(icmp_layer.get('id', 0))
            else:
                for key in ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id']:
                    features[key] = 0.0

            # Payload features
            payload_info = layers.get('payload', {})
            features['payload_length'] = float(payload_info.get('length', 0))
            features['has_payload'] = 1.0 if features['payload_length'] > 0 else 0.0

            # Flow identifier (for potential future use)
            flow_id = "_".join(flow_parts) if flow_parts else "unknown_flow"
            
            # Additional derived features
            features['packet_size_category'] = self._categorize_packet_size(features['frame_length'])
            features['protocol_category'] = self._categorize_protocol(features.get('ip_protocol', 0))
            features['port_category'] = self._categorize_ports(features.get('tcp_dport', 0) or features.get('udp_dport', 0))
            
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
    def __init__(self, mq_client: RabbitMQClient,
                 input_exchange_name: str, input_queue_name: str,
                 output_exchange_name: str, output_routing_key: str):
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

        self._setup_messaging()

    def _setup_messaging(self):
        logger.info(f"Setting up messaging for FeatureExtractorService.")
        # Input: Consuming from parsed_packets_queue bound to parsed_packets_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        # Ensure the input queue is bound with the correct routing key, which is typically the queue name itself for direct exchanges
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name) # routing key = queue name
        
        # Output: Publishing to features_exchange
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        # The queue for features will be declared by its consumer(s) (e.g., MLInferenceService)
        # or can be declared here if this service is also responsible for it.
        # For robustness, let's ensure the output queue (if named the same as routing key) is declared by the producer too.
        # This helps if the consumer starts later.
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name} (bound to {self.input_exchange_name}), publishing to {self.output_exchange_name} with key {self.output_routing_key}")

    def _extract_features(self, parsed_packet: ParsedPacket) -> Optional[FeatureVector]:
        """
        Extracts features from a ParsedPacket, adapting logic from the old PacketFeatureExtractor.
        """
        packet_id_val = parsed_packet.get("packet_id") # Store for logging and use
        try:
            timestamp_str = parsed_packet.get('timestamp') # This is already ISO8601 string
            layers = parsed_packet.get('layers', {})
            
            if not packet_id_val or not timestamp_str:
                logger.error(f"ParsedPacket missing packet_id or timestamp: {parsed_packet}")
                return None

            features: Dict[str, float | int | str] = {}
            flow_parts: List[str] = [] # Initialize flow_parts

            # General features
            # Using parentheses for multi-line assignment to avoid issues with backslashes
            features['frame_length'] = (
                parsed_packet.get('metadata', {}).get('original_length', 0)
                if 'ethernet' in layers or 'wifi' in layers else
                parsed_packet.get('metadata', {}).get('raw_frame_length', 0)
            )
            if features['frame_length'] == 0 and 'raw_frame_data_len' in parsed_packet.get('metadata', {}): 
                 features['frame_length'] = parsed_packet['metadata']['raw_frame_data_len']


            # IP Layer
            if 'ip' in layers:
                ip_layer = layers['ip']
                features['ip_version'] = int(ip_layer.get('version', 0))
                features['ip_ihl'] = int(ip_layer.get('ihl', 0))
                features['ip_tos'] = int(ip_layer.get('tos', 0))
                features['dscp'] = int(ip_layer.get('tos', 0)) >> 2
                features['ip_len'] = int(ip_layer.get('len', 0))
                features['ip_id'] = int(ip_layer.get('id', 0))
                features['ip_flags'] = int(ip_layer.get('flags_value', 0)) 
                features['ip_frag'] = int(ip_layer.get('frag', 0))
                features['ip_ttl'] = int(ip_layer.get('ttl', 0))
                features['ip_protocol'] = int(ip_layer.get('proto', 0))
                features['ip_src'] = str(ip_layer.get('src_ip', '0.0.0.0'))
                features['ip_dst'] = str(ip_layer.get('dst_ip', '0.0.0.0'))
                features['is_ip'] = 1
                
                # Initialize flow_parts here if IP layer exists
                flow_parts = [str(ip_layer.get('src_ip')), str(ip_layer.get('dst_ip')), str(ip_layer.get('proto'))]
            else:
                features['is_ip'] = 0
                for col in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol']:
                    features[col] = 0
                features['ip_src'] = '0.0.0.0'
                features['ip_dst'] = '0.0.0.0'
                # flow_parts remains empty as initialized

            # Transport Layer (TCP/UDP/ICMP)
            features['is_tcp'] = 1 if 'tcp' in layers else 0
            features['is_udp'] = 1 if 'udp' in layers else 0
            features['is_icmp'] = 1 if 'icmp' in layers else 0

            transport_defaults = {
                'src_port': 0, 'dst_port': 0,
                'tcp_seq': 0.0, 'tcp_ack': 0.0, 'tcp_dataofs': 0.0, 'tcp_reserved': 0.0,
                'tcp_flags': 0.0, 'tcp_window': 0.0, 'tcp_chksum': 0.0, 'tcp_urgptr': 0.0,
                'udp_len': 0.0, 'udp_chksum': 0.0,
                'icmp_type': 0.0, 'icmp_code': 0.0, 'icmp_chksum': 0.0
            }
            for k, v in transport_defaults.items():
                features[k] = v

            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                features['src_port'] = int(tcp_layer.get('sport', 0))
                features['dst_port'] = int(tcp_layer.get('dport', 0))
                features['tcp_seq'] = float(tcp_layer.get('seq', 0))
                features['tcp_ack'] = float(tcp_layer.get('ack_val', 0)) 
                features['tcp_dataofs'] = float(tcp_layer.get('dataofs', 0))
                features['tcp_reserved'] = float(tcp_layer.get('reserved', 0))
                features['tcp_flags'] = float(tcp_layer.get('flags_value', 0)) 
                features['tcp_window'] = float(tcp_layer.get('window', 0))
                features['tcp_chksum'] = float(tcp_layer.get('chksum', 0))
                features['tcp_urgptr'] = float(tcp_layer.get('urgptr', 0))
                if flow_parts: # Check if flow_parts was initialized (it is, if IP layer was present)
                    flow_parts.extend([str(tcp_layer.get('sport')), str(tcp_layer.get('dport'))])
            elif 'udp' in layers:
                udp_layer = layers['udp']
                features['src_port'] = int(udp_layer.get('sport', 0))
                features['dst_port'] = int(udp_layer.get('dport', 0))
                features['udp_len'] = float(udp_layer.get('len', 0))
                features['udp_chksum'] = float(udp_layer.get('chksum', 0))
                if flow_parts: 
                     flow_parts.extend([str(udp_layer.get('sport')), str(udp_layer.get('dport'))])
            elif 'icmp' in layers:
                icmp_layer = layers['icmp']
                features['icmp_type'] = float(icmp_layer.get('type', 0))
                features['icmp_code'] = float(icmp_layer.get('code', 0))
                features['icmp_chksum'] = float(icmp_layer.get('chksum', 0))

            flow_identifier = "-".join(filter(None, flow_parts)) if flow_parts else None


            # Wi-Fi (802.11) Layer
            has_wifi = False
            if 'wifi' in layers: 
                has_wifi = True
                wifi_layer = layers['wifi']
                features['wifi_fc_type'] = int(wifi_layer.get('fc_type', 0))
                features['wifi_fc_subtype'] = int(wifi_layer.get('fc_subtype', 0))
                fc_flags = wifi_layer.get('fc_flags', {})
                features['wifi_fc_to_ds'] = 1 if fc_flags.get('to_ds') else 0
                features['wifi_fc_from_ds'] = 1 if fc_flags.get('from_ds') else 0
                features['wifi_fc_more_frag'] = 1 if fc_flags.get('more_frag') else 0
                features['wifi_fc_retry'] = 1 if fc_flags.get('retry') else 0
                features['wifi_fc_pwr_mgt'] = 1 if fc_flags.get('pwr_mgt') else 0
                features['wifi_fc_more_data'] = 1 if fc_flags.get('more_data') else 0
                features['wifi_fc_protected'] = 1 if fc_flags.get('wep') else 0 
                features['wifi_fc_order'] = 1 if fc_flags.get('order') else 0
                features['wifi_duration_id'] = int(wifi_layer.get('duration_id', 0))
                features['wifi_addr1'] = str(wifi_layer.get('addr1', "00:00:00:00:00:00"))
                features['wifi_addr2'] = str(wifi_layer.get('addr2', "00:00:00:00:00:00"))
                features['wifi_addr3'] = str(wifi_layer.get('addr3', "00:00:00:00:00:00"))
                features['wifi_addr4'] = str(wifi_layer.get('addr4', "00:00:00:00:00:00"))
                features['wifi_sc_frag'] = int(wifi_layer.get('sc_frag', 0)) 
                features['wifi_sc_seq'] = int(wifi_layer.get('sc_seq', 0))   
                features['wifi_tid'] = int(wifi_layer.get('qos_tid', 0)) if 'qos_tid' in wifi_layer else 0 
            
            features['is_wifi'] = 1 if has_wifi else 0
            if not has_wifi:
                for col in ['wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
                            'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                            'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id', 
                            'wifi_sc_frag', 'wifi_sc_seq', 'wifi_tid']:
                    features[col] = 0
                for col in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                    features[col] = "00:00:00:00:00:00"

            # Payload features
            features['payload_length'] = parsed_packet.get('metadata', {}).get('payload_len', 0)
            if 'raw_data' in layers and layers['raw_data'] and 'data' in layers['raw_data']: 
                 features['payload_length'] = len(layers['raw_data']['data']) // 2 

            final_features = {}
            for k, v in features.items():
                if isinstance(v, (int, float, str)):
                    final_features[k] = v
                else:
                    final_features[k] = str(v) 

            feature_vector: FeatureVector = {
                "packet_id": packet_id_val, 
                "timestamp": timestamp_str, 
                "flow_id": flow_identifier,
                "features": final_features,
                "metadata": {
                    "feature_extractor_version": "0.2.1", # Incremented version
                    "extraction_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime())
                }
            }
            return feature_vector

        except Exception as e:
            # Corrected f-string for logging
            logger.error(f"Error extracting features for packet_id '{packet_id_val}': {e}", exc_info=True)
            return None

    def _message_handler(self, parsed_packet_message: ParsedPacket):
        """
        Callback function to process a single ParsedPacket message.
        """
        try:
            # logger.debug(f"Received parsed packet message: {parsed_packet_message.get('packet_id')}")
            
            feature_vector = self._extract_features(parsed_packet_message)
            
            if feature_vector:
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=feature_vector
                )
                # logger.info(f"Successfully extracted features and published for packet_id: {feature_vector['packet_id']}")
            else:
                logger.warning(f"Failed to extract features for packet_id: {parsed_packet_message.get('packet_id')}. Message will not be published.")

        except KeyError as ke:
            logger.error(f"Missing key in parsed_packet_message: {ke}. Message: {parsed_packet_message}")
        except Exception as e:
            logger.error(f"Error in FeatureExtractorService message_handler: {e}", exc_info=True)

    def start_consuming(self):
        """
        Starts consuming messages from the input queue and processing them.
        """
        logger.info(f"FeatureExtractorService starting to consume from queue: '{self.input_queue_name}' bound to exchange '{self.input_exchange_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=True # Changed to True for simplicity in this example, consider manual ack for production
            )
        except Exception as e:
            logger.error(f"FeatureExtractorService failed to start consuming: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
            # raise # Commenting out raise to prevent crash in case of MQ issue during long run
        finally:
            logger.info("FeatureExtractorService consumption loop finished or was interrupted.")


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    # Use setup_logging from utils
    setup_logging()
    import os # Added

    # --- Configuration ---
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost') # Added
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672)) # Added
    RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'user') # Added
    RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', 'password') # Added

    PARSED_PACKETS_EXCHANGE_NAME = "parsed_packets_exchange"
    PARSED_PACKETS_QUEUE_NAME = "parsed_packets_queue" # Consumes from this queue
    
    FEATURES_EXCHANGE_NAME = "features_exchange"
    FEATURES_QUEUE_ROUTING_KEY = "features_queue" # Publishes with this routing key

    logger.info("Initializing Feature Extractor Service Example...")
    mq_client_instance = None
    try:
        mq_client_instance = RabbitMQClient(
            host=RABBITMQ_HOST, 
            port=RABBITMQ_PORT,
            username=RABBITMQ_USER, # Added
            password=RABBITMQ_PASSWORD # Added
        )
        
        # Declare output exchange and queue (consumers of features will also declare the queue)
        mq_client_instance.declare_exchange(FEATURES_EXCHANGE_NAME, exchange_type='direct')
        mq_client_instance.declare_queue(FEATURES_QUEUE_ROUTING_KEY, FEATURES_EXCHANGE_NAME, FEATURES_QUEUE_ROUTING_KEY)
        logger.info(f"Declared exchange '{FEATURES_EXCHANGE_NAME}' and queue '{FEATURES_QUEUE_ROUTING_KEY}' for output.")

        feature_service = FeatureExtractorService(
            mq_client=mq_client_instance,
            input_exchange_name=PARSED_PACKETS_EXCHANGE_NAME,
            input_queue_name=PARSED_PACKETS_QUEUE_NAME,
            output_exchange_name=FEATURES_EXCHANGE_NAME,
            output_routing_key=FEATURES_QUEUE_ROUTING_KEY
        )
        
        logger.info(f"Starting feature extraction. Consuming from '{PARSED_PACKETS_QUEUE_NAME}'. Press Ctrl+C to stop.")
        feature_service.start_consuming()

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Feature Extractor Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block of Feature Extractor: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("Feature Extractor Service Example finished.")
