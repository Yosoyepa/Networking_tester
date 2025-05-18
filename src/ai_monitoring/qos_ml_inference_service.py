"""
QoS ML Inference Service

Consumes FeatureVector messages, performs ML-based anomaly detection for QoS,
and publishes MLResult messages.
"""
import logging
import time
import os
import joblib
import pandas as pd
import numpy as np
import json # Added for loading IF features
from typing import Dict, Any, Optional, List

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import FeatureVector, MLResult, FEATURES_TOPIC, ML_RESULTS_TOPIC
from src.utils.logger_config import setup_logging
from src.ai_monitoring.model_registry_client import ModelRegistryClient
from src.ai_monitoring.gmm_anomaly_detector import GMMAnomalyDetector # Added for GMM
from src.ai_monitoring.vae_anomaly_detector import VAEAnomalyDetector # Added for VAE

logger = logging.getLogger(__name__)

# Configuration for exchanges and queues (consistent with other services)
FEATURES_EXCHANGE_NAME = "features_exchange"
FEATURES_QUEUE_NAME = "features_queue"  # Consumes from this queue

ML_RESULTS_EXCHANGE_NAME = "ml_results_exchange"
ML_RESULTS_QUEUE_ROUTING_KEY = "ml_results_queue" # Publishes with this routing key (queue name)


class QoSMLInferenceService:
    def __init__(self, mq_client: RabbitMQClient,
                 model_registry_client: ModelRegistryClient, 
                 model_name: str, 
                 input_exchange_name: str, 
                 input_queue_name: str,
                 output_exchange_name: str, 
                 output_routing_key: str,
                 model_version: Optional[str] = "latest"): # Moved model_version to the end
        """
        Initializes the QoSMLInferenceService.

        Args:
            mq_client: An instance of the message queue client.
            model_registry_client: Client to interact with the model registry.
            model_name: Name of the model to load from the registry.
            input_exchange_name: Exchange for the input queue.
            input_queue_name: Queue to consume FeatureVector messages from.
            output_exchange_name: Exchange to publish MLResult messages to.
            output_routing_key: Routing key for publishing MLResult messages.
            model_version: Version of the model to load (e.g., "1.0.0", "latest"). Defaults to "latest".
        """
        self.mq_client = mq_client
        self.model_registry_client = model_registry_client
        self.model_name = model_name
        self.model_version = model_version
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.output_exchange_name = output_exchange_name
        self.output_routing_key = output_routing_key
        
        self.model_id: Optional[str] = None # Will be set after loading model details
        self.model_path: Optional[str] = None
        # self.scaler_path: Optional[str] = None # Scaler path is part of the model directory for GMM
        self.model_type: Optional[str] = None # Added to store the type of model (e.g., 'gmm', 'isolation_forest')
        self.model = None
        # self.scaler = None # Scaler is handled by GMMAnomalyDetector or loaded for IF
        self.model_loaded = False
        self.expected_features: Optional[List[str]] = None

        self._load_model_and_scaler()
        self._setup_messaging()

    def _load_model_and_scaler(self):
        logger.info(f"Attempting to load model '{self.model_name}' version '{self.model_version}' from registry.")
        model_details = self.model_registry_client.get_model_details(self.model_name, self.model_version)

        if not model_details:
            logger.error(f"Could not retrieve details for model '{self.model_name}' version '{self.model_version}' from registry.")
            self.model_loaded = False
            return

        self.model_path = model_details.get("model_path") # This will be a directory path
        self.model_id = f"{model_details.get('model_name', self.model_name)}-{model_details.get('version', self.model_version)}"
        
        model_metadata = model_details.get("metadata", {})
        self.model_type = model_metadata.get("model_type")

        if not self.model_type:
            logger.error(f"Model type not found in registry metadata for {self.model_id}. Cannot load model.")
            self.model_loaded = False
            return
        
        logger.info(f"Loading model {self.model_id} of type '{self.model_type}' from directory: {self.model_path}")

        if self.model_path and os.path.exists(self.model_path) and os.path.isdir(self.model_path):
            try:
                if self.model_type == "gmm":
                    self.model = GMMAnomalyDetector.load(self.model_path)
                    self.expected_features = self.model.trained_features_
                    logger.info(f"Successfully loaded GMM model and artifacts from: {self.model_path}")
                    logger.info(f"GMM model expects features: {self.expected_features}")
                elif self.model_type == "isolation_forest":
                    model_file = os.path.join(self.model_path, "model.iforest")
                    scaler_file = os.path.join(self.model_path, "model.scaler")
                    features_file = os.path.join(self.model_path, "model.features")

                    if not all(os.path.exists(f) for f in [model_file, scaler_file, features_file]):
                        logger.error(f"One or more artifact files (model.iforest, model.scaler, model.features) not found in {self.model_path} for Isolation Forest.")
                        raise FileNotFoundError("Missing Isolation Forest artifacts.")

                    self.model = joblib.load(model_file)
                    # Store the scaler as an attribute to be used in preprocessing
                    self.if_scaler = joblib.load(scaler_file) 
                    with open(features_file, 'r') as f:
                        self.expected_features = json.load(f)
                    logger.info(f"Successfully loaded Isolation Forest model and artifacts from: {self.model_path}")
                    logger.info(f"Isolation Forest model expects features: {self.expected_features}")
                elif self.model_type == "vae":
                    # VAEAnomalyDetector.load expects the prefix, which is self.model_path here
                    self.model = VAEAnomalyDetector.load(model_prefix=self.model_path)
                    if not self.model:
                        raise RuntimeError(f"Failed to load VAEAnomalyDetector with prefix: {self.model_path}")
                    self.expected_features = self.model.trained_features_ # Assuming VAEAnomalyDetector stores this
                    logger.info(f"Successfully loaded VAE model and artifacts using prefix: {self.model_path}")
                    logger.info(f"VAE model expects features: {self.expected_features}")
                    if self.expected_features is None:
                        logger.warning(f"VAE model {self.model_id} loaded but has no expected_features set. This might lead to issues if feature alignment is critical and not handled internally by VAE's predict method for all cases.")

                else:
                    logger.error(f"Unsupported model_type '{self.model_type}' specified in registry for model {self.model_id}.")
                    self.model_loaded = False
                    return
                
                self.model_loaded = True
            except FileNotFoundError:
                logger.error(f"Artifact file(s) not found in directory {self.model_path} for model type {self.model_type}.")
                self.model_loaded = False
            except Exception as e:
                logger.error(f"Error loading model artifacts from {self.model_path} for model type {self.model_type}: {e}", exc_info=True)
                self.model_loaded = False
        else:
            logger.error(f"Model path '{self.model_path}' (from registry) is not a valid directory or does not exist. QoS ML Inference will not work.")
            self.model_loaded = False
        
        if not self.model_loaded:
            self.model = None # Ensure model is None if loading failed
            self.model_id = f"{self.model_name}-{self.model_version}-load_failed"

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

        if not self.model_loaded or not self.model:
            logger.warning(f"Model '{self.model_id}' not loaded for packet_id: {packet_id}. Cannot perform inference.")
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
                is_anomaly_list, anomaly_scores_list = self.model.predict(numeric_aligned_df) # Pass the single-row DataFrame
                
                if not is_anomaly_list or not anomaly_scores_list:
                    logger.warning(f"GMM prediction returned empty results for packet_id: {packet_id}")
                    return None

                is_anomaly = is_anomaly_list[0] 
                anomaly_score = float(anomaly_scores_list[0])

                return {
                    "packet_id": packet_id,
                    "model_id": self.model_id or "unknown_gmm_model",
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
                    logger.error(f"Isolation Forest scaler not loaded for model {self.model_id}. Cannot predict.")
                    return None
                
                scaled_features_array = self.if_scaler.transform(numeric_aligned_df)
                processed_df = pd.DataFrame(scaled_features_array, columns=numeric_aligned_df.columns)
                
                prediction_label = self.model.predict(processed_df)[0]
                anomaly_score = float(self.model.decision_function(processed_df)[0])
                is_anomaly = True if prediction_label == -1 else False

                return {
                    "packet_id": packet_id,
                    "model_id": self.model_id or "unknown_if_model",
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
                is_anomaly_list, anomaly_scores_list = self.model.predict(numeric_aligned_df) # Pass the single-row DataFrame
                
                if not is_anomaly_list or anomaly_scores_list is None: # anomaly_scores_list can be empty if no prediction
                    logger.warning(f"VAE prediction returned empty or incomplete results for packet_id: {packet_id}")
                    return None

                is_anomaly = is_anomaly_list[0] 
                # anomaly_scores_list contains reconstruction errors
                reconstruction_error = float(anomaly_scores_list[0]) if len(anomaly_scores_list) > 0 else 0.0 

                return {
                    "packet_id": packet_id,
                    "model_id": self.model_id or "unknown_vae_model",
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
                        "anomaly_threshold_used": getattr(self.model, 'anomaly_threshold_', 'N/A') # Log the threshold used
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


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    setup_logging() # Setup basic logging for standalone execution

    # --- Configuration for Standalone Execution ---\r
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))
    
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
    
    try:
        # Initialize Model Registry Client
        # The ModelRegistryClient's __main__ block should handle dummy manifest/model creation if needed.
        # We rely on that setup for this example.
        model_registry_client_instance = ModelRegistryClient(
            manifest_path=MODEL_REGISTRY_MANIFEST_PATH, # Explicitly pass for clarity
            project_root_dir=PROJECT_ROOT
        )
        
        # Verify the dummy manifest and model files are created by running model_registry_client.py if it hasn't been run.
        # For this script, we assume they might exist.
        # A simple check:
        if not os.path.exists(model_registry_client_instance.manifest_path):
            logger.warning(f"Model registry manifest {model_registry_client_instance.manifest_path} not found.")
            logger.warning("Please ensure model_registry_client.py has been run to create a dummy manifest and models,")
            logger.warning("or that a valid manifest exists.")
            # Attempt to run the main block of model_registry_client to create them
            try:
                logger.info("Attempting to initialize dummy model registry...")
                import subprocess
                model_registry_script_path = os.path.join(PROJECT_ROOT, "src", "ai_monitoring", "model_registry_client.py")
                subprocess.run(["python", model_registry_script_path], check=True, cwd=PROJECT_ROOT)
                logger.info("Dummy model registry initialization script executed.")
                # Re-check manifest existence
                if not os.path.exists(model_registry_client_instance.manifest_path):
                     logger.error("Manifest still not found after attempting to run model_registry_client.py. Exiting.")
                     exit(1) # or raise an error
                # Reload manifest in client if it was just created
                model_registry_client_instance._load_manifest()

            except Exception as e_reg:
                logger.error(f"Failed to run model_registry_client.py to create dummy manifest: {e_reg}")
                logger.error("Proceeding, but model loading will likely fail.")


        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        qos_ml_service = QoSMLInferenceService(
            mq_client=mq_client_instance,
            model_registry_client=model_registry_client_instance,
            model_name=TARGET_MODEL_NAME,
            input_exchange_name=FEATURES_EXCHANGE_NAME,
            input_queue_name=FEATURES_QUEUE_NAME,
            output_exchange_name=ML_RESULTS_EXCHANGE_NAME,
            output_routing_key=ML_RESULTS_QUEUE_ROUTING_KEY,
            model_version=TARGET_MODEL_VERSION
        )
        
        if not qos_ml_service.model_loaded:
            logger.warning(f"ML Model '{TARGET_MODEL_NAME}' version '{TARGET_MODEL_VERSION}' could not be loaded via registry.")
            logger.warning(f"Please ensure the model and version exist in the registry: {model_registry_client_instance.manifest_path}")
            logger.warning(f"And that the corresponding model/scaler files exist at paths specified in the registry.")
            # For now, it will run but log errors for each message.

        logger.info(f"Starting QoS ML Inference. Consuming from '{FEATURES_QUEUE_NAME}'. Press Ctrl+C to stop.")
        qos_ml_service.start_consuming()

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

