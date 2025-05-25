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
        self.validation_enabled = len(self.active_model_configs) > 0
        
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
            logger.warning("No active model configurations provided. Using comprehensive feature extraction.")
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

    def update_active_models(self, new_model_configs: List[Dict[str, str]]):
        """Update active model configurations and refresh feature schemas."""
        logger.info("Updating active model configurations...")
        self.active_model_configs = new_model_configs
        self.model_feature_schemas.clear()
        self.model_feature_requirements.clear()
        self.unified_feature_schema.clear()
        
        self._initialize_model_feature_schemas()
        self.feature_adaptation_count += 1
        self.validation_enabled = len(new_model_configs) > 0
        logger.info(f"Feature schemas updated. Adaptation count: {self.feature_adaptation_count}")

    def _extract_features_comprehensive(self, parsed_packet: ParsedPacket) -> Optional[FeatureVector]:
        """
        Comprehensive feature extraction from a ParsedPacket with model-aware filtering.
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
            
            # Apply model-aware filtering if enabled
            if self.validation_enabled and self.unified_feature_schema:
                filtered_features = self._filter_features_for_models(features)
                features = filtered_features
                
            # Validate feature schema against model requirements
            validation_results = self._validate_feature_schema(features) if self.validation_enabled else []
            
            # Create feature vector with enhanced metadata
            feature_vector = FeatureVector(
                message_id=str(uuid.uuid4()),
                original_packet_id=packet_id_val,
                features=features,
                timestamp=timestamp_str,
                feature_names=list(features.keys())
            )
            
            self.extraction_count += 1
            
            # Log validation results if any issues found
            if validation_results:
                logger.debug(f"Feature validation results for packet {packet_id_val}: {validation_results}")
            
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
            features['dscp'] = float(ip_layer.get('tos', 0)) / 4.0
            features['ip_len'] = float(ip_layer.get('len', 0))
            features['ip_id'] = float(ip_layer.get('id', 0))
            features['ip_flags'] = float(ip_layer.get('flags_value', 0))
            features['ip_frag'] = float(ip_layer.get('frag', 0))
            features['ip_ttl'] = float(ip_layer.get('ttl', 0))
            features['ip_protocol'] = float(ip_layer.get('proto', 0))
            
            # Convert IP addresses to numerical features
            src_ip = ip_layer.get('src_ip', '0.0.0.0')
            dst_ip = ip_layer.get('dst_ip', '0.0.0.0')
            features['src_ip_hash'] = float(abs(hash(src_ip)) % 65536)
            features['dst_ip_hash'] = float(abs(hash(dst_ip)) % 65536)
        else:
            # Default IP features
            for key in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 
                       'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol', 'src_ip_hash', 'dst_ip_hash']:
                features[key] = 0.0

    def _extract_tcp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract TCP layer features."""
        if 'tcp' in layers:
            tcp_layer = layers['tcp']
            features['tcp_sport'] = float(tcp_layer.get('sport', 0))
            features['tcp_dport'] = float(tcp_layer.get('dport', 0))
            features['tcp_seq'] = float(tcp_layer.get('seq', 0) % 4294967296)
            features['tcp_ack'] = float(tcp_layer.get('ack', 0) % 4294967296)
            features['tcp_flags'] = float(tcp_layer.get('flags_value', 0))
            features['tcp_window'] = float(tcp_layer.get('window', 0))
            features['tcp_chksum'] = float(tcp_layer.get('chksum', 0))
            features['tcp_urgptr'] = float(tcp_layer.get('urgptr', 0))
        else:
            for key in ['tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_flags', 
                       'tcp_window', 'tcp_chksum', 'tcp_urgptr']:
                features[key] = 0.0

    def _extract_udp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract UDP layer features."""
        if 'udp' in layers:
            udp_layer = layers['udp']
            features['udp_sport'] = float(udp_layer.get('sport', 0))
            features['udp_dport'] = float(udp_layer.get('dport', 0))
            features['udp_len'] = float(udp_layer.get('len', 0))
            features['udp_chksum'] = float(udp_layer.get('chksum', 0))
        else:
            for key in ['udp_sport', 'udp_dport', 'udp_len', 'udp_chksum']:
                features[key] = 0.0

    def _extract_wifi_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract WiFi/802.11 layer features."""
        if 'wifi' in layers:
            wifi_layer = layers['wifi']
            features['wifi_type'] = float(wifi_layer.get('type', 0))
            features['wifi_subtype'] = float(wifi_layer.get('subtype', 0))
            features['wifi_ds'] = float(wifi_layer.get('ds', 0))
            features['wifi_id'] = float(wifi_layer.get('id', 0))
        else:
            for key in ['wifi_type', 'wifi_subtype', 'wifi_ds', 'wifi_id']:
                features[key] = 0.0

    def _extract_icmp_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract ICMP layer features."""
        if 'icmp' in layers:
            icmp_layer = layers['icmp']
            features['icmp_type'] = float(icmp_layer.get('type', 0))
            features['icmp_code'] = float(icmp_layer.get('code', 0))
            features['icmp_chksum'] = float(icmp_layer.get('chksum', 0))
            features['icmp_id'] = float(icmp_layer.get('id', 0))
        else:
            for key in ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id']:
                features[key] = 0.0

    def _extract_payload_features(self, features: Dict[str, float], layers: Dict[str, Any]):
        """Extract payload-related features."""
        payload_info = layers.get('payload', {})
        features['payload_length'] = float(payload_info.get('length', 0))
        features['has_payload'] = 1.0 if features['payload_length'] > 0 else 0.0

    def _extract_derived_features(self, features: Dict[str, float]):
        """Extract derived/calculated features."""
        features['packet_size_category'] = self._categorize_packet_size(features.get('frame_length', 0))
        features['protocol_category'] = self._categorize_protocol(features.get('ip_protocol', 0))
        
        # Determine port category from either TCP or UDP
        port = features.get('tcp_dport', 0) or features.get('udp_dport', 0)
        features['port_category'] = self._categorize_ports(port)

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

    def _filter_features_for_models(self, features: Dict[str, float]) -> Dict[str, float]:
        """Filter features based on active model requirements."""
        if not self.unified_feature_schema:
            return features
            
        # Keep only features that are required by at least one active model
        filtered_features = {}
        for feature_name, value in features.items():
            if feature_name in self.unified_feature_schema:
                filtered_features[feature_name] = value
                
        # Add missing required features with default values
        for required_feature in self.unified_feature_schema:
            if required_feature not in filtered_features:
                filtered_features[required_feature] = 0.0
                logger.debug(f"Added missing required feature '{required_feature}' with default value 0.0")
                
        return filtered_features

    def _validate_feature_schema(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Validate extracted features against model requirements."""
        validation_results = []
        
        for model_key, requirements in self.model_feature_requirements.items():
            required_features = set(requirements["required_features"])
            extracted_features = set(features.keys())
            
            missing_features = required_features - extracted_features
            extra_features = extracted_features - required_features
            
            if missing_features or extra_features:
                validation_results.append({
                    "model": model_key,
                    "model_type": requirements.get("model_type"),
                    "missing_features": list(missing_features),
                    "extra_features": list(extra_features),
                    "coverage": len(extracted_features & required_features) / len(required_features) if required_features else 1.0
                })
                
        return validation_results

    def _on_message_callback(self, message_data: Dict[str, Any]):
        """Callback function to process a single ParsedPacket message."""
        try:
            parsed_packet_message = ParsedPacket.from_json(json.dumps(message_data))
            logger.debug(f"Received ParsedPacket message: {parsed_packet_message.message_id}")
            
            # Extract features using comprehensive method
            feature_vector = self._extract_features_comprehensive(parsed_packet_message)
            
            if feature_vector:
                # Publish the feature vector
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=json.loads(feature_vector.to_json())
                )
                logger.debug(f"Published FeatureVector for packet {parsed_packet_message.message_id}")
            
        except Exception as e:
            logger.error(f"Error processing message in FeatureExtractorService: {e}", exc_info=True)

    def start_consuming(self):
        """Start consuming messages from the input queue."""
        logger.info("Enhanced FeatureExtractorService starting to consume messages...")
        
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._on_message_callback
            )
        except Exception as e:
            logger.error(f"Enhanced FeatureExtractorService failed to start consuming: {e}", exc_info=True)
            raise
        finally:
            try:
                self.mq_client.close()
            except Exception:
                pass
            logger.info("Enhanced FeatureExtractorService consumption finished.")

    def get_service_metrics(self) -> Dict[str, Any]:
        """Get service performance metrics."""
        return {
            "extraction_count": self.extraction_count,
            "error_count": self.error_count,
            "feature_adaptation_count": self.feature_adaptation_count,
            "active_models": len(self.model_feature_schemas),
            "unified_feature_count": len(self.unified_feature_schema),
            "validation_enabled": self.validation_enabled,
            "error_rate": self.error_count / max(self.extraction_count, 1)
        }


if __name__ == '__main__':
    # Use setup_logging from utils
    setup_logging()
    import pika.exceptions as pika_exceptions
    
    # --- Configuration ---
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    
    # --- Input Configuration ---
    INPUT_EXCHANGE_NAME = "parsed_packets_exchange"
    INPUT_QUEUE_NAME = "parsed_packets_queue"
    
    # --- Output Configuration ---
    OUTPUT_EXCHANGE_NAME = "features_exchange"
    OUTPUT_ROUTING_KEY = "features_queue"
    
    logger.info("Enhanced Feature Extractor Service Example starting...")
    
    # Example active model configurations
    ACTIVE_MODEL_CONFIGS = [
        {"model_name": "qos_anomaly_gmm_e2e_test", "model_version": "latest"},
        {"model_name": "qos_anomaly_vae_e2e_test", "model_version": "1.0.0"}
    ]
    
    mq_client_instance = None
    
    try:
        # Initialize Enhanced Model Registry Client
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        model_registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True
        )
        
        # Initialize RabbitMQ client
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST)
        
        # Create enhanced feature extractor service
        feature_extractor_service = EnhancedFeatureExtractorService(
            mq_client=mq_client_instance,
            model_registry_client=model_registry_client,
            input_exchange_name=INPUT_EXCHANGE_NAME,
            input_queue_name=INPUT_QUEUE_NAME,
            output_exchange_name=OUTPUT_EXCHANGE_NAME,
            output_routing_key=OUTPUT_ROUTING_KEY,
            active_model_configs=ACTIVE_MODEL_CONFIGS
        )
        
        logger.info("Enhanced Feature Extractor Service initialized successfully")
        
        # Start consuming (this will block)
        feature_extractor_service.start_consuming()
        
    except pika_exceptions.AMQPConnectionError as e:
        logger.error(f"Failed to connect to RabbitMQ at {RABBITMQ_HOST}: {e}")
    except Exception as e:
        logger.error(f"Error in Enhanced Feature Extractor Service: {e}", exc_info=True)
    finally:
        if mq_client_instance:
            try:
                mq_client_instance.close()
                logger.info("Closing RabbitMQ connection.")
            except Exception:
                pass
                
        logger.info("Enhanced Feature Extractor Service Example finished.")
