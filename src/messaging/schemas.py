"""
Message schemas for RabbitMQ communication between services.
This module defines the data structures for inter-service communication.
"""

import json
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib


@dataclass
class PacketMetadata:
    """Metadata for captured packets."""
    timestamp: str
    interface: str
    packet_size: int
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    protocol: Optional[str] = None
    packet_hash: Optional[str] = None


@dataclass
class RawPacketMessage:
    """Schema for raw packet messages sent from Packet Ingestor."""
    message_id: str
    packet_data: str  # base64 encoded packet
    metadata: PacketMetadata
    capture_session_id: str
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        data = asdict(self)
        return json.dumps(data, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'RawPacketMessage':
        """Create message from JSON string."""
        data = json.loads(json_str)
        metadata = PacketMetadata(**data['metadata'])
        return cls(
            message_id=data['message_id'],
            packet_data=data['packet_data'],
            metadata=metadata,
            capture_session_id=data['capture_session_id']
        )


@dataclass
class ParsedPacketMessage:
    """Schema for parsed packet messages sent from Packet Parser."""
    message_id: str
    original_message_id: str  # Reference to original raw packet
    parsed_data: Dict[str, Any]
    protocol_info: Dict[str, Any]
    qos_info: Optional[Dict[str, Any]] = None
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ParsedPacketMessage':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class StatisticsMessage:
    """Schema for statistics messages."""
    message_id: str
    timestamp: str
    statistics: Dict[str, Any]
    time_window: str
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'StatisticsMessage':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class MLInferenceMessage:
    """Schema for ML inference results."""
    message_id: str
    original_packet_id: str
    model_name: str
    inference_result: Dict[str, Any]
    confidence_score: float
    timestamp: str
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'MLInferenceMessage':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class ParsedPacket:
    """Schema for parsed packet data (alias for ParsedPacketMessage for backward compatibility)."""
    message_id: str
    original_message_id: str
    parsed_data: Dict[str, Any]
    protocol_info: Dict[str, Any]
    qos_info: Optional[Dict[str, Any]] = None
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ParsedPacket':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class FeatureVector:
    """Schema for feature vectors extracted from packets."""
    message_id: str
    original_packet_id: str
    features: Dict[str, float]
    timestamp: str
    feature_names: List[str]
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'FeatureVector':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class MLResult:
    """Schema for ML inference results."""
    message_id: str
    original_packet_id: str
    model_name: str
    prediction: Dict[str, Any]
    confidence: float
    timestamp: str
    anomaly_score: Optional[float] = None
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'MLResult':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class AnalysisResult:
    """Schema for analysis results from core analysis service."""
    message_id: str
    analysis_type: str
    results: Dict[str, Any]
    timestamp: str
    severity: str
    recommendations: Optional[List[str]] = None
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AnalysisResult':
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class ModelManagementMessage:
    """Schema for model management requests."""
    request_id: str
    action: str  # register, deploy, promote, list, get_details, sync
    model_name: str
    model_version: Optional[str] = None
    model_path: Optional[str] = None
    scaler_path: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    target_stage: Optional[str] = None  # Staging, Production, Archived
    target_services: Optional[List[str]] = None
    mlflow_run_id: Optional[str] = None
    response_queue: Optional[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        data = asdict(self)
        return json.dumps(data, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ModelManagementMessage':
        """Create message from JSON string."""
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class ModelDeploymentCommand:
    """Schema for model deployment commands."""
    command_id: str
    action: str  # load_model, unload_model, switch_model
    model_name: str
    model_version: str
    model_path: str
    scaler_path: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    target_services: Optional[List[str]] = None
    timestamp: Optional[str] = None
    priority: str = "normal"  # low, normal, high, critical
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        data = asdict(self)
        return json.dumps(data, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ModelDeploymentCommand':
        """Create message from JSON string."""
        data = json.loads(json_str)
        return cls(**data)


@dataclass
class ModelHealthStatus:
    """Schema for model health status messages."""
    model_name: str
    model_version: str
    service_name: str
    status: str  # healthy, degraded, failed, loading, unloaded
    health_score: Optional[float] = None
    last_inference_time: Optional[str] = None
    error_rate: Optional[float] = None
    latency_p95: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    timestamp: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        data = asdict(self)
        return json.dumps(data, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ModelHealthStatus':
        """Create message from JSON string."""
        data = json.loads(json_str)
        return cls(**data)


class MessageSchemas:
    """Central registry for message schemas and queue names."""
    
    # Queue names
    RAW_PACKETS_QUEUE = "raw_packets"
    PARSED_PACKETS_QUEUE = "parsed_packets"
    STATISTICS_QUEUE = "statistics"
    ML_INFERENCE_QUEUE = "ml_inference"
    ALERTS_QUEUE = "alerts"
    
    # Exchange names
    PACKETS_EXCHANGE = "packets_exchange"
    ANALYSIS_EXCHANGE = "analysis_exchange"
    
    @staticmethod
    def get_queue_names() -> List[str]:
        """Get all queue names."""
        return [
            MessageSchemas.RAW_PACKETS_QUEUE,
            MessageSchemas.PARSED_PACKETS_QUEUE,
            MessageSchemas.STATISTICS_QUEUE,
            MessageSchemas.ML_INFERENCE_QUEUE,
            MessageSchemas.ALERTS_QUEUE
        ]
    
    @staticmethod
    def create_packet_hash(packet_data: bytes) -> str:
        """Create a hash for packet deduplication."""
        return hashlib.md5(packet_data).hexdigest()


# Topic/Queue constants
PARSED_PACKETS_TOPIC = "parsed_packets"
FEATURES_TOPIC = "features"
ML_RESULTS_TOPIC = "ml_results"
ANALYSIS_RESULTS_TOPIC = "analysis_results"
