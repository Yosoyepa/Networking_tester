"""
Enhanced QoS ML Inference Service

This is an enhanced version of the QoS ML Inference Service that supports:
- Dynamic model loading/unloading
- Model health monitoring
- Integration with the enhanced model registry
- Support for multiple model types
"""
import logging
import asyncio
import time
import os
import joblib
import pandas as pd
import numpy as np
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import signal

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import (
    FeatureVector, MLResult, ModelDeploymentCommand, ModelHealthStatus,
    ServiceHealthMessage
)
from src.utils.logging_config import setup_logging
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.ai_monitoring.gmm_anomaly_detector import GMMAnomalyDetector
from src.ai_monitoring.vae_anomaly_detector import VAEAnomalyDetector
from config.config_loader import load_config

logger = logging.getLogger(__name__)


class EnhancedQoSMLInferenceService:
    """
    Enhanced QoS ML Inference Service with dynamic model management.
    
    Supports:
    - Dynamic model loading/unloading via deployment commands
    - Model health monitoring
    - Multiple model types (GMM, VAE, Isolation Forest)
    - Integration with enhanced model registry
    - Performance metrics tracking
    """
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """Initialize the Enhanced QoS ML Inference Service."""
        self.config = load_config(config_path)
        self.service_name = "enhanced_qos_ml_inference"
        self.is_running = False
        
        # Initialize logging
        setup_logging(self.config)
        logger.info("Initializing Enhanced QoS ML Inference Service")
        
        # Initialize enhanced model registry client
        mlflow_config = self.config.get("mlflow", {})
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        
        self.model_registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True,
            mlflow_tracking_uri=mlflow_config.get("tracking_uri"),
            experiment_name=mlflow_config.get("experiment_name")
        )
        
        # Initialize RabbitMQ client
        rabbitmq_config = self.config.get("rabbitmq", {})
        self.rabbitmq_client = RabbitMQClient(
            host=rabbitmq_config.get("host", "localhost"),
            port=rabbitmq_config.get("port", 5672),
            username=rabbitmq_config.get("username", "guest"),
            password=rabbitmq_config.get("password", "guest")
        )
        
        # Model state
        self.current_model = None
        self.current_model_name = None
        self.current_model_version = None
        self.current_model_id = None
        self.model_type = None
        self.model_loaded = False
        self.model_health = "unloaded"
        self.expected_features: Optional[List[str]] = None
        self.scaler = None
        
        # Performance metrics
        self.inference_count = 0
        self.error_count = 0
        self.last_inference_time = None
        self.inference_latencies = []
        self.start_time = datetime.utcnow()
        
        # Queue names
        self.features_queue = "features_queue"
        self.ml_results_queue = "ml_results_queue"
        self.deployment_queue = "model_deployment_commands"
        self.health_queue = "model_health_status"
        self.service_health_queue = "service_health"
        
        # Load initial model from config if specified
        ai_config = self.config.get("ai_monitoring", {})
        active_model_config = ai_config.get("active_anomaly_model", {})
        if active_model_config.get("model_name"):
            self._load_model(
                active_model_config["model_name"],
                active_model_config.get("model_version", "latest")
            )
    
    async def start(self):
        """Start the Enhanced QoS ML Inference Service."""
        try:
            logger.info("Starting Enhanced QoS ML Inference Service")
            self.is_running = True
            
            # Connect to RabbitMQ
            await self.rabbitmq_client.connect()
            
            # Declare queues
            await self._declare_queues()
            
            # Start consuming messages
            await asyncio.gather(
                self._consume_features(),
                self._consume_deployment_commands(),
                self._monitor_model_health(),
                self._publish_service_health()
            )
            
        except Exception as e:
            logger.error(f"Failed to start Enhanced QoS ML Inference Service: {e}", exc_info=True)
            await self.stop()
            
    async def stop(self):
        """Stop the Enhanced QoS ML Inference Service."""
        logger.info("Stopping Enhanced QoS ML Inference Service")
        self.is_running = False
        
        if self.rabbitmq_client:
            await self.rabbitmq_client.disconnect()
            
    async def _declare_queues(self):
        """Declare required RabbitMQ queues."""
        queues = [
            self.features_queue,
            self.ml_results_queue,
            self.deployment_queue,
            self.health_queue,
            self.service_health_queue
        ]
        
        for queue in queues:
            await self.rabbitmq_client.declare_queue(queue, durable=True)
            
    async def _consume_features(self):
        """Consume feature vectors for inference."""
        logger.info("Starting to consume feature vectors")
        
        async def process_feature_vector(message: Dict[str, Any]):
            try:
                feature_vector = FeatureVector(**message)
                await self._perform_inference(feature_vector)
            except Exception as e:
                logger.error(f"Error processing feature vector: {e}", exc_info=True)
                self.error_count += 1
                
        await self.rabbitmq_client.consume(
            queue=self.features_queue,
            callback=process_feature_vector
        )
        
    async def _consume_deployment_commands(self):
        """Consume model deployment commands."""
        logger.info("Starting to consume deployment commands")
        
        async def process_deployment_command(message: Dict[str, Any]):
            try:
                command = ModelDeploymentCommand(**message)
                await self._handle_deployment_command(command)
            except Exception as e:
                logger.error(f"Error processing deployment command: {e}", exc_info=True)
                
        await self.rabbitmq_client.consume(
            queue=self.deployment_queue,
            callback=process_deployment_command
        )
        
    async def _handle_deployment_command(self, command: ModelDeploymentCommand):
        """Handle model deployment commands."""
        logger.info(f"Processing deployment command: {command.action} for {command.model_name}")
        
        if command.action == "load_model":
            success = self._load_model(command.model_name, command.model_version)
            if success:
                logger.info(f"Successfully loaded model {command.model_name} v{command.model_version}")
                self.model_health = "healthy"
            else:
                logger.error(f"Failed to load model {command.model_name} v{command.model_version}")
                self.model_health = "failed"
                
        elif command.action == "unload_model":
            self._unload_model()
            logger.info("Model unloaded successfully")
            
        elif command.action == "switch_model":
            self._unload_model()
            success = self._load_model(command.model_name, command.model_version)
            if success:
                logger.info(f"Successfully switched to model {command.model_name} v{command.model_version}")
                self.model_health = "healthy"
            else:
                logger.error(f"Failed to switch to model {command.model_name} v{command.model_version}")
                self.model_health = "failed"
        
    def _load_model(self, model_name: str, model_version: str = "latest") -> bool:
        """Load a model from the registry."""
        try:
            logger.info(f"Loading model '{model_name}' version '{model_version}' from registry")
            
            model_details = self.model_registry_client.get_model_details(model_name, model_version)
            if not model_details:
                logger.error(f"Could not retrieve details for model '{model_name}' version '{model_version}'")
                return False
                
            model_path = model_details.get("model_path")
            model_metadata = model_details.get("metadata", {})
            model_type = model_metadata.get("model_type")
            
            if not model_type:
                logger.error(f"Model type not found in registry metadata for {model_name}")
                return False
                
            self.current_model_name = model_name
            self.current_model_version = model_details.get("version", model_version)
            self.current_model_id = f"{model_name}-{self.current_model_version}"
            self.model_type = model_type
            
            logger.info(f"Loading model {self.current_model_id} of type '{model_type}' from: {model_path}")
            
            if model_type == "gmm":
                self.current_model = GMMAnomalyDetector.load(model_path)
                if hasattr(self.current_model, 'feature_names'):
                    self.expected_features = self.current_model.feature_names
                logger.info(f"Successfully loaded GMM model")
                
            elif model_type == "vae":
                self.current_model = VAEAnomalyDetector.load(model_path)
                if hasattr(self.current_model, 'feature_names'):
                    self.expected_features = self.current_model.feature_names
                logger.info(f"Successfully loaded VAE model")
                
            elif model_type == "isolation_forest":
                model_file = os.path.join(model_path, f"{model_name}.iforest")
                scaler_file = os.path.join(model_path, f"{model_name}_scaler.joblib")
                features_file = os.path.join(model_path, f"{model_name}_features.json")
                
                if os.path.exists(model_file):
                    self.current_model = joblib.load(model_file)
                    logger.info(f"Loaded Isolation Forest model from {model_file}")
                else:
                    logger.error(f"Model file not found: {model_file}")
                    return False
                    
                if os.path.exists(scaler_file):
                    self.scaler = joblib.load(scaler_file)
                    logger.info(f"Loaded scaler from {scaler_file}")
                    
                if os.path.exists(features_file):
                    with open(features_file, 'r') as f:
                        feature_data = json.load(f)
                        self.expected_features = feature_data.get("features", [])
                        
            else:
                logger.error(f"Unsupported model type: {model_type}")
                return False
                
            self.model_loaded = True
            self.model_health = "healthy"
            logger.info(f"Successfully loaded model {self.current_model_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}", exc_info=True)
            self.model_loaded = False
            self.model_health = "failed"
            return False
            
    def _unload_model(self):
        """Unload the current model."""
        logger.info(f"Unloading current model: {self.current_model_id}")
        
        self.current_model = None
        self.current_model_name = None
        self.current_model_version = None
        self.current_model_id = None
        self.model_type = None
        self.model_loaded = False
        self.model_health = "unloaded"
        self.expected_features = None
        self.scaler = None
        
    async def _perform_inference(self, feature_vector: FeatureVector):
        """Perform ML inference on a feature vector."""
        start_time = time.time()
        
        try:
            if not self.model_loaded or not self.current_model:
                logger.warning("No model loaded, skipping inference")
                return
                
            # Extract features
            features_dict = feature_vector.features
            
            # Validate features
            if self.expected_features:
                missing_features = [f for f in self.expected_features if f not in features_dict]
                if missing_features:
                    logger.warning(f"Missing features: {missing_features}")
                    return
                    
                # Create DataFrame with expected features in correct order
                processed_df = pd.DataFrame([{f: features_dict.get(f, 0.0) for f in self.expected_features}])
            else:
                processed_df = pd.DataFrame([features_dict])
                
            # Perform inference based on model type
            prediction_result = None
            
            if self.model_type == "gmm":
                prediction_result = self.current_model.predict_anomaly(processed_df)
                anomaly_score = float(prediction_result.get("anomaly_score", 0.0))
                is_anomaly = bool(prediction_result.get("is_anomaly", False))
                
            elif self.model_type == "vae":
                prediction_result = self.current_model.predict_anomaly(processed_df)
                anomaly_score = float(prediction_result.get("anomaly_score", 0.0))
                is_anomaly = bool(prediction_result.get("is_anomaly", False))
                
            elif self.model_type == "isolation_forest":
                if self.scaler:
                    processed_df = pd.DataFrame(self.scaler.transform(processed_df), columns=processed_df.columns)
                    
                anomaly_score = float(self.current_model.decision_function(processed_df)[0])
                prediction_label = self.current_model.predict(processed_df)[0]
                is_anomaly = bool(prediction_label == -1)
                
            else:
                logger.error(f"Unknown model type: {self.model_type}")
                return
                
            # Create ML result
            ml_result = MLResult(
                packet_id=feature_vector.packet_id,
                model_id=self.current_model_id,
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                prediction_confidence=abs(anomaly_score),
                model_version=self.current_model_version,
                features_used=list(processed_df.columns),
                inference_timestamp=datetime.utcnow().isoformat(),
                processing_time_ms=round((time.time() - start_time) * 1000, 2),
                details={
                    "model_type": self.model_type,
                    "feature_count": len(processed_df.columns),
                    "original_timestamp": feature_vector.timestamp
                }
            )
            
            # Publish result
            await self.rabbitmq_client.publish(
                queue=self.ml_results_queue,
                message=ml_result.dict()
            )
            
            # Update metrics
            self.inference_count += 1
            self.last_inference_time = datetime.utcnow().isoformat()
            inference_latency = (time.time() - start_time) * 1000
            self.inference_latencies.append(inference_latency)
            
            # Keep only last 100 latencies for moving average
            if len(self.inference_latencies) > 100:
                self.inference_latencies = self.inference_latencies[-100:]\n                
            logger.debug(f"Processed inference for packet {feature_vector.packet_id}: anomaly_score={anomaly_score}, is_anomaly={is_anomaly}")
            
        except Exception as e:
            logger.error(f"Error during inference for packet {feature_vector.packet_id}: {e}", exc_info=True)
            self.error_count += 1
            
    async def _monitor_model_health(self):
        """Monitor and report model health status."""
        while self.is_running:
            try:
                if self.model_loaded and self.current_model:
                    # Calculate health metrics
                    error_rate = self.error_count / max(self.inference_count, 1)
                    avg_latency = np.mean(self.inference_latencies) if self.inference_latencies else 0.0
                    p95_latency = np.percentile(self.inference_latencies, 95) if self.inference_latencies else 0.0
                    
                    # Determine health status
                    if error_rate > 0.1:  # More than 10% errors
                        health_status = "degraded"
                    elif avg_latency > 1000:  # More than 1 second average latency
                        health_status = "degraded"
                    else:
                        health_status = "healthy"
                        
                    health_message = ModelHealthStatus(
                        model_name=self.current_model_name,
                        model_version=self.current_model_version,
                        service_name=self.service_name,
                        status=health_status,
                        health_score=max(0.0, 1.0 - error_rate),
                        last_inference_time=self.last_inference_time,
                        error_rate=error_rate,
                        latency_p95=p95_latency,
                        details={
                            "inference_count": self.inference_count,
                            "error_count": self.error_count,
                            "avg_latency_ms": avg_latency,
                            "model_type": self.model_type
                        }
                    )
                    
                    await self.rabbitmq_client.publish(
                        queue=self.health_queue,
                        message=health_message.dict()
                    )
                    
                await asyncio.sleep(30)  # Report health every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in model health monitoring: {e}", exc_info=True)
                await asyncio.sleep(60)
                
    async def _publish_service_health(self):
        """Publish service health status."""
        while self.is_running:
            try:
                uptime = (datetime.utcnow() - self.start_time).total_seconds()
                
                service_health = ServiceHealthMessage(
                    service_name=self.service_name,
                    status="healthy" if self.is_running else "stopped",
                    timestamp=datetime.utcnow().isoformat(),
                    metadata={
                        "model_loaded": self.model_loaded,
                        "current_model": self.current_model_id,
                        "model_health": self.model_health,
                        "inference_count": self.inference_count,
                        "error_count": self.error_count,
                        "uptime_seconds": uptime
                    }
                )
                
                await self.rabbitmq_client.publish(
                    queue=self.service_health_queue,
                    message=service_health.dict()
                )
                
                await asyncio.sleep(30)  # Publish health every 30 seconds
                
            except Exception as e:
                logger.error(f"Error publishing service health: {e}", exc_info=True)
                await asyncio.sleep(60)


async def main():
    """Main function to run the Enhanced QoS ML Inference Service."""
    service = EnhancedQoSMLInferenceService()
    
    # Handle shutdown signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        asyncio.create_task(service.stop())
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await service.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())
