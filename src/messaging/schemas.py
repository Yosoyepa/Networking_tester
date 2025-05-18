from typing import TypedDict, Dict, Any, List
import datetime

class RawFrame(TypedDict):
    timestamp: str  # ISO8601 format
    interface: str
    frame_bytes: str  # base64_encoded_string
    metadata: Dict[str, Any] # Optional: e.g., capture source, original length

class ParsedPacket(TypedDict):
    packet_id: str # Unique identifier for the packet
    timestamp: str  # ISO8601 format from RawFrame or refined
    raw_frame_id: str # Reference to the original raw frame
    layers: Dict[str, Any] # e.g., {"ethernet": {...}, "ip": {...}, "tcp": {...}}
    # Potentially add other common fields like src_mac, dst_mac, src_ip, dst_ip, protocol, etc.
    metadata: Dict[str, Any] # Optional: e.g., parsing errors, original interface

class FeatureVector(TypedDict):
    packet_id: str      # Reference to the parsed packet
    timestamp: str      # ISO8601 format
    flow_id: str | None # Optional: Identifier for the flow this packet belongs to
    features: Dict[str, float | int | str] # Numerical or categorical features
    metadata: Dict[str, Any] # Optional: e.g., feature extraction version

class MLResult(TypedDict):
    packet_id: str      # Reference to the parsed packet or feature vector
    model_id: str       # Identifier of the ML model used (e.g., qos_anomaly_v1.2)
    timestamp: str      # ISO8601 format of processing
    anomaly_score: float | None
    is_anomaly: bool
    prediction: Any # Could be class label, regression value etc.
    details: Dict[str, Any] # Optional: e.g., contributing features, confidence

class AnalysisResult(TypedDict):
    analysis_id: str    # Unique identifier for this analysis outcome
    timestamp: str      # ISO8601 format of processing
    type: str           # Type of analysis (e.g., "flow_summary", "rule_violation", "correlation_event")
    source_packet_ids: List[str] # List of packet_ids that contributed to this result
    source_ml_result_ids: List[str] # List of ml_result_ids (if applicable)
    summary: str        # Brief summary of the analysis result
    details: Dict[str, Any] # Detailed findings, metrics, or correlated data
    severity: str | None # Optional: e.g., "info", "warning", "critical"

# Placeholder for a generic message queue client interface
class MessageQueueClient:
    def __init__(self, config):
        # Initialize client (e.g., connection to Kafka/RabbitMQ)
        self.config = config
        print(f"MessageQueueClient initialized with config: {config}")

    def publish(self, topic: str, message: Dict[str, Any]):
        # Logic to publish a message to a topic
        print(f"Publishing to {topic}: {message}")
        pass

    def consume(self, topic: str, callback_function):
        # Logic to consume messages from a topic and pass to callback_function
        # This would typically run in a loop or a separate thread
        print(f"Setting up consumer for {topic} with callback {callback_function.__name__}")
        pass

    def subscribe(self, topic: str, callback_function):
        # Alias for consume or specific subscribe logic
        self.consume(topic, callback_function)

# Example topics (constants)
RAW_FRAMES_TOPIC = "raw_frames"
PARSED_PACKETS_TOPIC = "parsed_packets"
FEATURES_TOPIC = "features"
ML_RESULTS_TOPIC = "ml_results"
ALERTS_TOPIC = "alerts"
COMMANDS_TOPIC_PREFIX = "commands." # e.g., commands.ingestor
ANALYSIS_RESULTS_TOPIC = "analysis_results" # New topic
