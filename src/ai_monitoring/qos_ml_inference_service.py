"""
QoS ML Inference Service

Consumes FeatureVector messages, performs ML-based anomaly detection for QoS,
and publishes MLResult messages.
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
import signal
import pika  # For exception handling

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import (
    FeatureVector, MLResult, ModelDeploymentCommand, ModelHealthStatus,
    FEATURES_TOPIC, ML_RESULTS_TOPIC
)
from src.utils.logging_config import setup_logging
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.ai_monitoring.gmm_anomaly_detector import GMMAnomalyDetector
from src.ai_monitoring.vae_anomaly_detector import VAEAnomalyDetector

logger = logging.getLogger(__name__)

# Configuration for exchanges and queues (consistent with other services)
FEATURES_EXCHANGE_NAME = "features_exchange"
FEATURES_QUEUE_NAME = "features_queue"

ML_RESULTS_EXCHANGE_NAME = "ml_results_exchange"
ML_RESULTS_QUEUE_ROUTING_KEY = "ml_results_queue"

MODEL_DEPLOYMENT_QUEUE = "model_deployment_commands"
MODEL_HEALTH_QUEUE = "model_health_status"


class EnhancedQoSMLInferenceService:
    """
    Enhanced QoS ML Inference Service with dynamic model management.
    
    Supports:
    - Dynamic model loading/unloading
    - Model health monitoring
    - Multiple model types (GMM, VAE, Isolation Forest)
    - Integration with enhanced model registry
    """
    
    def __init__(self, 
                 mq_client: RabbitMQClient,
                 model_registry_client: EnhancedModelRegistryClient, 
                 initial_model_name: Optional[str] = None,
                 initial_model_version: Optional[str] = "latest"):
        """
        Initialize the Enhanced QoS ML Inference Service.

        Args:
            mq_client: RabbitMQ client instance.
            model_registry_client: Enhanced model registry client.
            initial_model_name: Initial model to load (optional).
            initial_model_version: Version of initial model to load.
        """
        self.mq_client = mq_client
        self.model_registry_client = model_registry_client
        self.service_name = "enhanced_qos_ml_inference"
        self.is_running = False
        
        # Model state
        self.current_model = None
        self.current_model_name = initial_model_name
        self.current_model_version = initial_model_version
        self.model_type = None
        self.model_loaded = False
        self.model_health = "unloaded"
        self.expected_features: Optional[List[str]] = None
        
        # Performance metrics
        self.inference_count = 0
        self.error_count = 0
        self.last_inference_time = None
        self.inference_latencies = []
        
        # Load initial model if specified
        if initial_model_name:
            self._load_model(initial_model_name, initial_model_version)

    def _load_model(self, model_name: str, model_version: str = "latest"):
        """
        Load a model by name and version.

        Args:
            model_name: Name of the model.
            model_version: Version of the model to load.

        Returns:
            bool: True if model loaded successfully, False otherwise.
        """
        logger.info(f"Attempting to load model '{model_name}' version '{model_version}' from registry.")
        model_details = self.model_registry_client.get_model_details(model_name, model_version)

        if not model_details:
            logger.error(f"Could not retrieve details for model '{model_name}' version '{model_version}' from registry.")
            return False

        model_path = model_details.get("model_path") # This will be a directory path
        model_id = f"{model_details.get('model_name', model_name)}-{model_details.get('version', model_version)}"
        
        model_metadata = model_details.get("metadata", {})
        model_type = model_metadata.get("model_type")

        if not model_type:
            logger.error(f"Model type not found in registry metadata for {model_id}. Cannot load model.")
            return False
        
        logger.info(f"Loading model {model_id} of type '{model_type}' from directory: {model_path}")

        if model_path and os.path.exists(model_path) and os.path.isdir(model_path):
            try:
                if model_type == "gmm":
                    self.current_model = GMMAnomalyDetector.load(model_path)
                    self.expected_features = self.current_model.trained_features_
                    logger.info(f"Successfully loaded GMM model and artifacts from: {model_path}")
                    logger.info(f"GMM model expects features: {self.expected_features}")
                elif model_type == "isolation_forest":
                    model_file = os.path.join(model_path, "model.iforest")
                    scaler_file = os.path.join(model_path, "model.scaler")
                    features_file = os.path.join(model_path, "model.features")

                    if not all(os.path.exists(f) for f in [model_file, scaler_file, features_file]):
                        logger.error(f"One or more artifact files (model.iforest, model.scaler, model.features) not found in {model_path} for Isolation Forest.")
                        raise FileNotFoundError("Missing Isolation Forest artifacts.")

                    self.current_model = joblib.load(model_file)
                    # Store the scaler as an attribute to be used in preprocessing
                    self.if_scaler = joblib.load(scaler_file) 
                    with open(features_file, 'r') as f:
                        self.expected_features = json.load(f)
                    logger.info(f"Successfully loaded Isolation Forest model and artifacts from: {model_path}")
                    logger.info(f"Isolation Forest model expects features: {self.expected_features}")
                elif model_type == "vae":
                    # VAEAnomalyDetector.load expects the prefix, which is self.model_path here
                    self.current_model = VAEAnomalyDetector.load(model_path_prefix=model_path) # Changed 'model_prefix' to 'model_path_prefix'
                    self.expected_features = self.current_model.trained_features # Assuming VAEAnomalyDetector stores this
                    self.scaler = self.current_model.scaler # Assuming VAEAnomalyDetector stores this
                    logger.info(f"Model and scaler for '{model_name}' version '{model_version}' loaded successfully.")
                    logger.info(f"Successfully loaded VAE model and artifacts using prefix: {model_path}")
                    logger.info(f"VAE model expects features: {self.expected_features}")
                    if self.expected_features is None:
                        logger.warning(f"VAE model {model_id} loaded but has no expected_features set. This might lead to issues if feature alignment is critical and not handled internally by VAE's predict method for all cases.")

                else:
                    logger.error(f"Unsupported model_type '{model_type}' specified in registry for model {model_id}.")
                    return False
                
                self.model_type = model_type
                self.model_loaded = True
                self.model_health = "healthy"
                return True
            except FileNotFoundError:
                logger.error(f"Artifact file(s) not found in directory {model_path} for model type {model_type}.")
                return False
            except Exception as e:
                logger.error(f"Error loading model artifacts from {model_path} for model type {model_type}: {e}", exc_info=True)
                return False
        else:
            logger.error(f"Model path '{model_path}' (from registry) is not a valid directory or does not exist. QoS ML Inference will not work.")
            return False

    async def _monitor_model_health(self):
        """
        Monitor the health of the current model and update the model_health status.
        """
        while self.is_running:
            if not self.current_model or not self.model_loaded:
                self.model_health = "unloaded"
            else:
                # Perform a health check (e.g., dummy prediction)
                try:
                    dummy_input = pd.DataFrame(columns=self.expected_features, index=[0]).fillna(0)
                    if self.model_type == "gmm":
                        self.current_model.predict(dummy_input)
                    elif self.model_type == "isolation_forest":
                        if hasattr(self, 'if_scaler'):
                            scaled_dummy_input = self.if_scaler.transform(dummy_input)
                            self.current_model.predict(pd.DataFrame(scaled_dummy_input, columns=dummy_input.columns))
                    elif self.model_type == "vae":
                        self.current_model.predict(dummy_input)
                    
                    self.model_health = "healthy"
                except Exception as e:
                    logger.error(f"Model health check failed: {e}", exc_info=True)
                    self.model_health = "unhealthy"
            
            # Sleep for a while before the next health check
            await asyncio.sleep(10)

    def _setup_messaging(self):
        logger.info(f"Setting up messaging for QoSMLInferenceService.")
        # Input: Consuming from features_queue bound to features_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name) # routing key = queue name
        
        # Output: Publishing to ml_results_exchange
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key) # routing key = queue name (convention)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name}, publishing to {self.output_exchange_name} with key {self.output_routing_key}")

    def _preprocess_and_predict(self, feature_vector_msg: FeatureVector) -> Optional[MLResult]:
        packet_id = feature_vector_msg.get("packet_id")
        original_timestamp = feature_vector_msg.get("timestamp")
        features_dict = feature_vector_msg.get("features")

        if not self.model_loaded or not self.current_model:
            logger.warning(f"Model '{self.current_model_name}' not loaded for packet_id: {packet_id}. Cannot perform inference.")
            return None

        if not features_dict:
            logger.warning(f"No features found in message for packet_id: {packet_id}.")
            return None

        try:
            input_df = pd.DataFrame([features_dict])
            
            # Feature alignment (common for both model types before their specific processing)
            aligned_df = pd.DataFrame(columns=self.expected_features, index=[0]).fillna(0)
            for col in self.expected_features:
                if col in input_df.columns:
                    aligned_df[col] = input_df[col].values
                else:
                    logger.debug(f"Packet_id {packet_id}: Expected feature '{col}' not found. Using default 0.")
            
            numeric_aligned_df = aligned_df.copy()
            for col in numeric_aligned_df.columns:
                try:
                    numeric_aligned_df[col] = pd.to_numeric(numeric_aligned_df[col])
                except ValueError:
                    logger.error(f"Packet_id {packet_id}: Could not convert feature '{col}' to numeric. Value: {numeric_aligned_df[col].iloc[0]}. Replacing with 0.")
                    numeric_aligned_df[col] = 0

            # Model-specific prediction
            if self.model_type == "gmm":
                # GMMAnomalyDetector's predict method handles scaling and uses its trained_features internally.
                # It expects a DataFrame.
                is_anomaly_list, anomaly_scores_list = self.current_model.predict(numeric_aligned_df) # Pass the single-row DataFrame
                
                if not is_anomaly_list or not anomaly_scores_list:
                    logger.warning(f"GMM prediction returned empty results for packet_id: {packet_id}")
                    return None

                is_anomaly = is_anomaly_list[0] 
                anomaly_score = float(anomaly_scores_list[0])

                return {
                    "packet_id": packet_id,
                    "model_id": self.current_model_id or "unknown_gmm_model",
                    "model_type": "gmm",
                    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
                    "anomaly_score": anomaly_score, # Log-likelihood for GMM
                    "is_anomaly": is_anomaly,
                    # For GMM, 'prediction' might not be a simple label like -1/1.
                    # 'is_anomaly' is the primary outcome. We can add raw score as 'anomaly_score'.
                    "prediction": -1 if is_anomaly else 1, # Align with IF's -1 for anomaly
                    "details": {
                        "original_packet_timestamp": original_timestamp,
                        "feature_count_input": len(features_dict),
                        "feature_count_processed": len(numeric_aligned_df.columns),
                        "log_likelihood": anomaly_score # Explicitly state it's log-likelihood for GMM
                    }
                }

            elif self.model_type == "isolation_forest":
                if not hasattr(self, 'if_scaler') or not self.if_scaler:
                    logger.error(f"Isolation Forest scaler not loaded for model {self.current_model_id}. Cannot predict.")
                    return None
                
                scaled_features_array = self.if_scaler.transform(numeric_aligned_df)
                processed_df = pd.DataFrame(scaled_features_array, columns=numeric_aligned_df.columns)
                
                prediction_label = self.current_model.predict(processed_df)[0]
                anomaly_score = float(self.current_model.decision_function(processed_df)[0])
                is_anomaly = True if prediction_label == -1 else False

                return {
                    "packet_id": packet_id,
                    "model_id": self.current_model_id or "unknown_if_model",
                    "model_type": "isolation_forest", # Add model_type
                    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
                    "anomaly_score": anomaly_score,
                    "is_anomaly": is_anomaly,
                    "prediction": int(prediction_label),
                    "details": {
                        "original_packet_timestamp": original_timestamp,
                        "feature_count_input": len(features_dict),
                        "feature_count_processed": len(processed_df.columns),
                    }
                }
            elif self.model_type == "vae":
                # VAEAnomalyDetector's predict method handles scaling and uses its trained_features internally.
                # It expects a DataFrame.
                is_anomaly_list, anomaly_scores_list = self.current_model.predict(numeric_aligned_df) # Pass the single-row DataFrame
                
                if not is_anomaly_list or anomaly_scores_list is None: # anomaly_scores_list can be empty if no prediction
                    logger.warning(f"VAE prediction returned empty or incomplete results for packet_id: {packet_id}")
                    return None

                is_anomaly = is_anomaly_list[0] 
                # anomaly_scores_list contains reconstruction errors
                reconstruction_error = float(anomaly_scores_list[0]) if len(anomaly_scores_list) > 0 else 0.0 

                return {
                    "packet_id": packet_id,
                    "model_id": self.current_model_id or "unknown_vae_model",
                    "model_type": "vae",
                    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
                    "anomaly_score": reconstruction_error, # Reconstruction error for VAE
                    "is_anomaly": is_anomaly,
                    "prediction": -1 if is_anomaly else 1, # Consistent with IF: -1 for anomaly
                    "details": {
                        "original_packet_timestamp": original_timestamp,
                        "feature_count_input": len(features_dict),
                        "feature_count_processed": len(numeric_aligned_df.columns),
                        "reconstruction_error": reconstruction_error,
                        "anomaly_threshold_used": getattr(self.current_model, 'anomaly_threshold_', 'N/A') # Log the threshold used
                    }
                }
            else:
                logger.error(f"Unsupported model type '{self.model_type}' for prediction.")
                return None
        except ValueError as ve:
            logger.error(f"ValueError during preprocessing/prediction for packet_id '{packet_id}': {ve}. Features might not match model expectations. Input features: {list(features_dict.keys())}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error during ML inference for packet_id '{packet_id}': {e}", exc_info=True)
            return None

    def _message_handler(self, feature_vector_msg: FeatureVector):
        packet_id = feature_vector_msg.get("packet_id", "unknown")
        # logger.debug(f"Received feature vector for packet_id: {packet_id}")
        
        ml_result = self._preprocess_and_predict(feature_vector_msg)
        
        if ml_result:
            try:
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=ml_result
                )
                # logger.info(f"Successfully processed and published ML result for packet_id: {ml_result['packet_id']}, Anomaly: {ml_result['is_anomaly']}")
            except Exception as e:
                logger.error(f"Failed to publish ML result for packet_id {packet_id}: {e}", exc_info=True)
        else:
            logger.warning(f"Failed to generate ML result for packet_id: {packet_id}. Message will not be published.")
        
        # Assuming auto_ack=True for simplicity, or add manual ack logic here
        # self.mq_client.acknowledge_message(delivery_tag) # If manual ack

    def start_consuming(self):
        logger.info(f"QoSMLInferenceService starting to consume from queue: '{self.input_queue_name}' bound to exchange '{self.input_exchange_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=True # Set to True for simplicity, consider False for production
            )
        except Exception as e:
            logger.error(f"QoSMLInferenceService failed to start consuming: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
        finally:
            logger.info("QoSMLInferenceService consumption loop finished or was interrupted.")

    def start(self):
        """
        Start the QoS ML Inference Service.
        """
        logger.info(f"Starting {self.service_name}...")
        self.is_running = True

        # Start the model health monitoring in a separate task
        asyncio.create_task(self._monitor_model_health())

        # Start consuming messages
        self.start_consuming()

    def stop(self):
        """
        Stop the QoS ML Inference Service.
        """
        logger.info(f"Stopping {self.service_name}...")
        self.is_running = False
        # Add any cleanup logic if needed

    def restart_model(self, model_name: str, model_version: str = "latest"):
        """
        Restart the current model with a new version.

        Args:
            model_name: Name of the model.
            model_version: Version of the model to load.
        """
        logger.info(f"Restarting model to {model_name} version {model_version}...")
        if self._load_model(model_name, model_version):
            logger.info(f"Model restarted successfully: {model_name} version {model_version}")
        else:
            logger.error(f"Failed to restart model: {model_name} version {model_version}")

    def handle_signal(self, sig, frame):
        """
        Handle termination signals to stop the service gracefully.
        """
        logger.info(f"Received signal {sig}. Stopping the service...")
        self.stop()
        # Optionally, wait for the service to stop and then exit
        # sys.exit(0)


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    setup_logging() # Setup basic logging for standalone execution
    import os # Added

    # --- Configuration for Standalone Execution ---

    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))
    RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'user') # Added
    RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', 'password') # Added
    
    # Model Registry and Model Configuration
    # Assumes model_registry_client.py creates a dummy manifest if none exists
    # and that this script is run from a context where 'data/models/model_registry.json' is accessible.
    # The project_root_dir for ModelRegistryClient should be the root of the 'networking_tester' project.
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")) # Adjust if structure changes
    
    MODEL_REGISTRY_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "models", "model_registry.json") # Default path used by client
    
    # Define which model to use from the registry
    # These can be overridden by environment variables QOS_MODEL_NAME and QOS_MODEL_VERSION
    # Or, ideally, read from a global settings.yaml file.

    # For this example, we'll keep the direct environment variable or default approach,
    # but a real service would load this from the shared YAML config.
    TARGET_MODEL_NAME = os.getenv("QOS_MODEL_NAME", "qos_anomaly_detector") # Default if not in settings
    TARGET_MODEL_VERSION = os.getenv("QOS_MODEL_VERSION", "latest") # Default if not in settings

    # --- Load configuration from settings.yaml ---
    settings_path = os.path.join(PROJECT_ROOT, "config", "settings.yaml")
    active_model_name_from_config = None
    active_model_version_from_config = None

    if os.path.exists(settings_path):
        try:
            import yaml
            with open(settings_path, 'r') as f:
                app_config = yaml.safe_load(f)
            active_model_config = app_config.get("ai_monitoring", {}).get("active_anomaly_model", {})
            active_model_name_from_config = active_model_config.get("model_name")
            active_model_version_from_config = active_model_config.get("model_version")
            
            if active_model_name_from_config:
                TARGET_MODEL_NAME = active_model_name_from_config
                logger.info(f"Loaded TARGET_MODEL_NAME from settings.yaml: {TARGET_MODEL_NAME}")
            if active_model_version_from_config:
                TARGET_MODEL_VERSION = active_model_version_from_config
                logger.info(f"Loaded TARGET_MODEL_VERSION from settings.yaml: {TARGET_MODEL_VERSION}")

        except Exception as e_conf:
            logger.error(f"Error loading model configuration from {settings_path}: {e_conf}. Using defaults or environment variables.")
    else:
        logger.warning(f"Settings file {settings_path} not found. Using defaults or environment variables for model selection.")

    logger.info(f"QoS ML Inference Service will use model: '{TARGET_MODEL_NAME}' version: '{TARGET_MODEL_VERSION}'")

    logger.info("Initializing QoS ML Inference Service Example with Model Registry...")
    mq_client_instance = None
    model_registry_client_instance = None
    
    try:        # Initialize Enhanced Model Registry Client
        # The EnhancedModelRegistryClient supports both MLflow and file-based registry
        model_registry_client_instance = EnhancedModelRegistryClient(
            project_root_dir=PROJECT_ROOT,
            use_mlflow=True  # Enable MLflow integration
        )        
        # Enhanced Model Registry Client handles initialization automatically
        # No need for manual manifest checks or dummy model creation
        
        mq_client_instance = RabbitMQClient(
            host=RABBITMQ_HOST, 
            port=RABBITMQ_PORT,
            username=RABBITMQ_USER, # Added
            password=RABBITMQ_PASSWORD # Added
        )
        
        qos_ml_service = EnhancedQoSMLInferenceService(
            mq_client=mq_client_instance,
            model_registry_client=model_registry_client_instance,
            initial_model_name=TARGET_MODEL_NAME,
            initial_model_version=TARGET_MODEL_VERSION
        )
        
        if not qos_ml_service.model_loaded:
            logger.warning(f"ML Model '{TARGET_MODEL_NAME}' version '{TARGET_MODEL_VERSION}' could not be loaded via registry.")
            logger.warning(f"Please ensure the model and version exist in the registry: {model_registry_client_instance.manifest_path}")
            logger.warning(f"And that the corresponding model/scaler files exist at paths specified in the registry.")
            # For now, it will run but log errors for each message.

        logger.info(f"Starting QoS ML Inference. Consuming from '{FEATURES_QUEUE_NAME}'. Press Ctrl+C to stop.")
        # Handle termination signals
        signal.signal(signal.SIGINT, lambda s, f: qos_ml_service.handle_signal(s, f))
        signal.signal(signal.SIGTERM, lambda s, f: qos_ml_service.handle_signal(s, f))
        qos_ml_service.start()

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("QoS ML Inference Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("QoS ML Inference Service Example finished.")

