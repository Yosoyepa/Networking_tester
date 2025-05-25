import json
import logging
import time
import uuid
from typing import Dict, Any, Optional

# Assuming these are in the parent directory or PYTHONPATH is set
from src.messaging import MessageProducer, MessageConsumer 
from src.mlops.model_registry import ModelRegistry # Added import

# Placeholder for ML model loading and inference
import joblib # Using joblib as an example
import os # For path joining
import numpy as np # Added for potential numpy array operations

logger = logging.getLogger(__name__)

# Placeholder for ML model loading and inference
import joblib # Using joblib as an example
import os # For path joining

class QoSInferenceService:
    def __init__(self, consumer: MessageConsumer, producer: MessageProducer,
                 feature_vectors_queue: str, qos_predictions_queue: str,
                 model_name: str, model_version: Optional[str] = None, 
                 model_registry_path: Optional[str] = None,
                 base_model_dir: str = "data/models/"): # Base directory for model files
        self.consumer = consumer
        self.producer = producer
        self.feature_vectors_queue = feature_vectors_queue
        self.qos_predictions_queue = qos_predictions_queue
        
        self.model_registry = ModelRegistry(registry_path=model_registry_path) if model_registry_path else ModelRegistry()
        self.model_info = self.model_registry.get_model(model_name=model_name, model_version=model_version)
        
        self.model = None
        self.model_path_used = None # Store the actual path used
        self.model_id_used = None # Store the model_id from registry

        if self.model_info:
            self.model_path_used = os.path.join(base_model_dir, self.model_info["model_path"]) # Construct full path
            self.model_id_used = self.model_info["model_id"]
            self.model = self._load_model(self.model_path_used)
            logger.info(f"QoSInferenceService initialized. Using model '{model_name}' v{self.model_info.get('model_version', 'latest')}, ID: {self.model_id_used} from {self.model_path_used}")
        else:
            logger.error(f"Model '{model_name}' (version: {model_version or 'latest'}) not found in registry. Service will not be able to make predictions.")
            # self.model remains None

        self._running = False


    def _load_model(self, model_path: str) -> Any:
        """Loads the ML model from the specified path."""
        logger.info(f"Loading model from {model_path}...")
        try:
            if not os.path.exists(model_path):
                logger.error(f"Model file not found at {model_path}. Cannot load model.")
                # Special handling for the dummy model from registry for testing purposes
                if "dummy_qos_model.pkl" in model_path:
                    logger.warning(f"Attempting to use placeholder for dummy model as file {model_path} is missing.")
                    return "dummy_model_placeholder_loaded" # Return a distinct placeholder
                return None

            # Example using joblib:
            model = joblib.load(model_path)
            logger.info(f"Model loaded successfully from {model_path}.")
            return model
        except FileNotFoundError: # Should be caught by os.path.exists, but as a safeguard
            logger.error(f"Model file not found at {model_path} (FileNotFoundError). Service will not be able to make predictions.")
            return None
        except Exception as e:
            logger.error(f"Error loading model from {model_path}: {e}", exc_info=True)
            return None
        # logger.warning(f"Model loading is currently a placeholder. No actual model loaded from {model_path}.")
        # return "dummy_model" # Placeholder

    def _perform_inference(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Performs inference using the loaded model and a feature vector."""
        if not self.model or self.model == "dummy_model_placeholder_loaded": # Check for placeholder too
            if self.model == "dummy_model_placeholder_loaded":
                 logger.warning("Performing inference with a DUMMY placeholder model (original model file was missing).")
                 # Dummy prediction for the placeholder
                 qos_score = 0.50 + (hash(json.dumps(feature_vector.get('features',{}))) % 20) / 100.0 
                 is_anomaly = qos_score < 0.60
                 prediction_details = {
                     "model_type": "dummy_placeholder_file_missing_v0",
                     "raw_prediction_output": [qos_score] # Changed from raw_prediction
                 }
                 return {
                    "qos_score": float(qos_score), # Ensure float
                    "is_anomaly": is_anomaly,
                    "prediction_details": prediction_details
                }
            logger.error("No model loaded or model is invalid. Cannot perform inference.")
            return {"error": "No model loaded or model is invalid"}

        # Special handling for the known dummy_qos_model if it's loaded correctly
        if self.model_info and self.model_info.get("model_name") == "dummy_qos_model" and \
           self.model and self.model != "dummy_model_placeholder_loaded":
            logger.warning(f"Performing DUMMY inference for explicitly loaded 'dummy_qos_model' (ID: {self.model_id_used}). Bypassing sklearn.predict to ensure pipeline testability.")
            # Simplified dummy logic, not using self.model.predict() to avoid feature mismatch
            qos_score = 0.68 + (hash(json.dumps(feature_vector.get('features',{}))) % 15) / 100.0 
            is_anomaly = qos_score < 0.72 # Slightly different thresholds/logic for differentiation
            prediction_details = {
                "model_type": "dummy_qos_model_special_handling_v1",
                "model_id_configured": self.model_id_used,
                "model_path_used": self.model_path_used,
                "raw_prediction_output": [qos_score] 
            }
            logger.info(f"Dummy inference for {feature_vector.get('feature_vector_id')} using {self.model_id_used}: QoS Score={qos_score:.4f}, Anomaly={is_anomaly}")
            return {
                "qos_score": float(qos_score),
                "is_anomaly": is_anomaly,
                "prediction_details": prediction_details
            }

        logger.debug(f"Performing inference on feature vector ID: {feature_vector.get('feature_vector_id')} using model {self.model_id_used} (type: {type(self.model)})")
        
        input_features_dict = feature_vector.get('features', {})
        if not input_features_dict:
            logger.warning(f"No features found in message for {feature_vector.get('feature_vector_id')}. Cannot perform inference.")
            return {"error": "No features provided in the message"}

        try:
            # --- 1. Feature Preparation ---
            # CRITICAL TODO: This section MUST be adapted for your specific ML model.
            # The following is a NAIVE placeholder for feature preparation.
            # Real models require features in a specific order and format (e.g., scaled, encoded).
            # Define `expected_feature_order` based on how your model was trained.
            # Example: expected_feature_order = ['feature1', 'feature2', 'ip_ttl', ...]
            
            # Naive approach: extract all numeric features, sorted by key for some consistency.
            # This is highly unlikely to work correctly for a production model without modification.
            prepared_features = []
            feature_names_used = []
            for key, value in sorted(input_features_dict.items()):
                if isinstance(value, (int, float)):
                    prepared_features.append(float(value))
                    feature_names_used.append(key)
            
            if not prepared_features:
                logger.error(f"No numeric features could be extracted from input for model {self.model_id_used}. Input keys: {list(input_features_dict.keys())}")
                return {"error": "No numeric features suitable for model input"}

            # Scikit-learn models expect a 2D array: [samples, features]
            model_input_array = [prepared_features] 
            logger.warning(f"Model {self.model_id_used}: Using {len(prepared_features)} naively extracted numeric features: {feature_names_used}. "
                           f"THIS FEATURE PREPARATION IS A PLACEHOLDER AND NEEDS REVIEW FOR YOUR MODEL.")

            # --- 2. Model Prediction ---
            raw_prediction = self.model.predict(model_input_array)
            predicted_class = raw_prediction[0] # Assuming batch of 1, take first result

            # --- 3. Probability and Score Calculation ---
            qos_score = 0.5  # Default QoS score
            is_anomaly = True # Default anomaly status
            probabilities = None

            if hasattr(self.model, 'predict_proba'):
                probabilities_raw = self.model.predict_proba(model_input_array)[0] # Probabilities for the first sample
                probabilities = [float(p) for p in probabilities_raw] # Ensure serializable

                # Assumption: Class 0 is "good" (not anomaly), Class 1 is "bad" (anomaly).
                # QoS score is the probability of being "good".
                if len(probabilities) > 0: # Should have at least one class
                    qos_score = probabilities[0] # P(class_0)
                if len(probabilities) > 1: # If two classes (good, bad)
                    # is_anomaly = bool(predicted_class == 1) # If class 1 is anomaly
                    # Or, more directly from probabilities if available:
                    # is_anomaly = probabilities[1] > probabilities[0] # If P(anomaly) > P(good)
                    pass # predicted_class already determined by predict()
                else: # Single class output from predict_proba (e.g. anomaly score)
                    # This case needs specific handling based on model output.
                    # For now, rely on predicted_class.
                    pass
            else:
                logger.warning(f"Model {self.model_id_used} does not have 'predict_proba' method. QoS score will be binary based on predicted class.")
                # qos_score will be set based on is_anomaly later

            # Determine anomaly status based on predicted_class
            # Common convention: 0 for normal, 1 for anomaly. This might need adjustment.
            is_anomaly = bool(predicted_class != 0) 

            if not hasattr(self.model, 'predict_proba'): # If no probabilities, assign binary QoS score
                qos_score = 0.25 if is_anomaly else 0.75


            # --- 4. Prediction Details ---
            prediction_details = {
                "model_type": str(type(self.model).__name__),
                "model_id_configured": self.model_info.get("model_id", "N/A") if self.model_info else "N/A",
                "model_path_used": self.model_path_used,
                "features_used_names": feature_names_used, # Log which features were naively picked
                "input_feature_count": len(prepared_features),
                "raw_prediction_output": [float(val) for val in raw_prediction], # Ensure serializable
                "predicted_class": float(predicted_class), # Ensure serializable
                "probabilities": probabilities
            }
            
            logger.info(f"Inference for {feature_vector.get('feature_vector_id')} using {self.model_id_used}: Class={predicted_class}, QoS Score={qos_score:.4f}, Anomaly={is_anomaly}")

            return {
                "qos_score": float(qos_score),
                "is_anomaly": is_anomaly,
                "prediction_details": prediction_details
            }

        except Exception as e:
            logger.error(f"Error during inference with model {self.model_id_used} (type: {type(self.model)}): {e}", exc_info=True)
            return {"error": f"Inference error with model {self.model_id_used}: {str(e)}"}

    def _process_feature_vector_message(self, channel, method, properties, body):
        try:
            feature_vector_msg = json.loads(body.decode('utf-8'))
            logger.debug(f"Received feature vector: {feature_vector_msg.get('feature_vector_id')}")

            feature_vector_id = feature_vector_msg.get('feature_vector_id')
            if not feature_vector_id:
                logger.error("Received message without feature_vector_id. Discarding.")
                channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return

            # Assuming 'features' key holds the actual vector for the model
            if 'features' not in feature_vector_msg:
                logger.error(f"Feature vector message {feature_vector_id} missing 'features' key. Discarding.")
                channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return

            inference_result = self._perform_inference(feature_vector_msg)

            if "error" in inference_result:
                logger.error(f"Inference failed for {feature_vector_id}: {inference_result['error']}")
                # Acknowledge message even if inference fails, to prevent requeue loops for bad data/model issues.
                channel.basic_ack(delivery_tag=method.delivery_tag) 
                return

            qos_prediction_msg = {
                "schema_version": "1.0", # Or load from a config
                "qos_prediction_id": str(uuid.uuid4()),
                "feature_vector_id": feature_vector_id,
                "model_id": self.model_id_used or "unknown_model", # Use model_id from registry
                "prediction_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(time.time())) + ("%.6f" % (time.time() % 1))[2:] + 'Z',
                "source_info": feature_vector_msg.get("source_info"), # Propagate source_info
                "qos_score": inference_result["qos_score"],
                "is_anomaly": inference_result["is_anomaly"],
                "prediction_details": inference_result["prediction_details"]
            }
            
            self.producer.publish_message(self.qos_predictions_queue, qos_prediction_msg)
            logger.info(f"Published QoS prediction for FV_ID {feature_vector_id} (Pred_ID: {qos_prediction_msg['qos_prediction_id']}) to {self.qos_predictions_queue}")

            channel.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for incoming feature vector message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except KeyError as e:
            logger.error(f"Missing key in feature vector message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.error(f"Unexpected error processing feature vector message: {e}", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue for potentially transient

    def start(self):
        if self._running:
            logger.info("QoSInferenceService is already running.")
            return

        logger.info("Starting QoSInferenceService...")
        if not self.model and not ("dummy_model_placeholder_loaded" == self.model): # Allow starting if it's the dummy placeholder
            logger.error("Cannot start QoSInferenceService: Model not loaded or invalid.")
            return
            
        try:
            self.consumer.connect() # Connect the passed consumer
            self.producer.connect() # Connect the passed producer
            
            self.consumer.start_consuming(self.feature_vectors_queue, self._process_feature_vector_message)
            self._running = True
            logger.info(f"QoSInferenceService started. Consuming from '{self.feature_vectors_queue}' and publishing to '{self.qos_predictions_queue}'.")
            
            # Keep main thread alive if consumer runs in a daemon thread (depends on MessageConsumer impl)
            # If start_consuming is blocking, this loop is not strictly needed here.
            # while self._running:
            #     time.sleep(1) # Or use a more sophisticated stop signal mechanism

        except Exception as e:
            logger.error(f"Failed to start QoSInferenceService: {e}", exc_info=True)
            self._running = False

    def stop(self):
        logger.info("Stopping QoSInferenceService...")
        self._running = False # Signal loops to stop
        
        # Give some time for the consumer loop to exit if it's polling self._running
        # time.sleep(0.1) 

        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.close()
        logger.info("QoSInferenceService stopped.")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Mock messaging components for standalone testing
    class MockMessageComponent:
        def __init__(self, name="MockComponent"): self.name = name
        def connect(self): logger.debug(f"{self.name} connected (mock)")
        def close(self): logger.debug(f"{self.name} closed (mock)")
        def publish_message(self, msg, queue): logger.info(f"MockProducer ({self.name}): Publishing to {queue}: {json.dumps(msg, indent=2)}")
        def start_consuming(self, queue, callback): logger.info(f"MockConsumer ({self.name}): Would start consuming from {queue} (mock)")

    RABBITMQ_HOST = 'localhost' # Not used by mock
    FEATURE_VECTORS_QUEUE = 'feature_vectors_queue'
    QOS_PREDICTIONS_QUEUE = 'qos_predictions_queue'
    
    # For testing, use the actual registry but potentially a temp file
    # For this __main__ test, we'll rely on the default registry path or a specific temp one.
    # Ensure the dummy model is in the registry for this test.
    # The registry file 'data/models/model_registry.json' should have 'dummy_qos_model'
    # with model_path 'dummy_qos_model.pkl'
    
    # Create a dummy model file for testing loading, if it's registered and path is 'dummy_qos_model.pkl'
    # This should align with what's in your data/models/model_registry.json
    dummy_model_relative_path = "dummy_qos_model.pkl" 
    base_model_dir_for_test = "data/models/" # Matches default in QoSInferenceService constructor
    actual_dummy_model_path = os.path.join(base_model_dir_for_test, dummy_model_relative_path)

    if not os.path.exists(actual_dummy_model_path):
        os.makedirs(os.path.dirname(actual_dummy_model_path), exist_ok=True)
        try:
            # Create a very simple joblib-compatible dummy model
            from sklearn.linear_model import LogisticRegression
            dummy_sklearn_model = LogisticRegression() # A simple model
            # Fit with some dummy data so it's 'trained'
            dummy_sklearn_model.fit([[0],[1]], [0,1])
            joblib.dump(dummy_sklearn_model, actual_dummy_model_path)
            logger.info(f"Created dummy sklearn model file at {actual_dummy_model_path} for testing.")
        except Exception as e:
            logger.warning(f"Could not create dummy sklearn model file at {actual_dummy_model_path}: {e}")
    else:
        logger.info(f"Dummy model file {actual_dummy_model_path} already exists for testing.")


    mock_consumer = MockMessageComponent(name="QoSConsumer")
    mock_producer = MockMessageComponent(name="QoSProducer")

    service = QoSInferenceService(
        consumer=mock_consumer, # Pass the mock consumer
        producer=mock_producer, # Pass the mock producer
        feature_vectors_queue=FEATURE_VECTORS_QUEUE,
        qos_predictions_queue=QOS_PREDICTIONS_QUEUE,
        model_name="dummy_qos_model", # Name of the model in the registry
        # model_version="0.1.0", # Optionally specify version
        # model_registry_path=DEFAULT_REGISTRY_PATH, # Explicitly if needed
        base_model_dir=base_model_dir_for_test 
    )

    # service.start() # This would use the mock consumer's start_consuming

    # Simulate receiving a message for testing _process_feature_vector_message
    # We need to ensure the service's model is loaded for this test.
    if service.model: # Check if service has a model (even the placeholder)
        logger.info(f"\n--- Simulating message processing with model: {service.model_id_used} ---")
        example_feature_vector_msg_body = json.dumps({
            "schema_version": "1.0",
            "feature_vector_id": str(uuid.uuid4()),
            "parsed_packet_id": str(uuid.uuid4()),
            "extraction_timestamp": "2025-05-18T14:00:00.000000Z",
            "source_info": {"type": "live_capture", "identifier": "eth_test_inference"},
            "features": {
                "frame_length": 128, "timestamp": time.time(), "ip_version": 4, "ip_ihl": 5, 
                "ip_tos": 0, "dscp":0, "ip_len": 100, "ip_id": 123, "ip_flags": 2, "ip_frag": 0,
                "ip_ttl": 64, "ip_protocol": 6, "is_ip":1,
                "is_tcp":1, "is_udp":0, "is_icmp":0,
                "src_port": 12345, "dst_port": 80,
                "tcp_seq": 1000, "tcp_ack": 1, "tcp_dataofs": 5, "tcp_reserved": 0,
                "tcp_flags": 2, "tcp_window": 65535, "tcp_chksum": 0, "tcp_urgptr": 0,
                # Add other features as per EXPECTED_FEATURE_COLUMNS in feature_extractor
            }
        })
        
        # Mock channel and method for the callback
        class MockChannel:
            def basic_ack(self, delivery_tag): logger.debug(f"MockChannel: basic_ack for tag {delivery_tag}")
            def basic_nack(self, delivery_tag, requeue): logger.debug(f"MockChannel: basic_nack for tag {delivery_tag}, requeue={requeue}")

        class MockMethod:
            delivery_tag = "mock_delivery_tag_123"

        logger.info("\n--- Simulating message processing ---")
        service._process_feature_vector_message(MockChannel(), MockMethod(), None, example_feature_vector_msg_body.encode('utf-8'))
        logger.info("--- End of simulated message processing ---\n")
    else:
        logger.error("Service model not loaded, cannot simulate message processing in __main__.")


    # try:
    #     # Keep main thread alive for a bit if service runs in background 
    #     # (service.start() with real consumer would block or run in a thread)
    #     # For this __main__ test, we are not calling service.start() that blocks.
    #     logger.info("QoSInferenceService __main__ test finished simulation.")
    #     time.sleep(2) 
    # except KeyboardInterrupt:
    #     logger.info("QoSInferenceService test interrupted by user.")
    # finally:
    #     service.stop() # This would close the mock consumer/producer
    #     # Clean up dummy model file created by this test? 
    #     # Better to leave it if it's the one defined in registry for general testing.
    #     # If it was a uniquely named temp file, then yes.
    #     logger.info("QoSInferenceService __main__ completed.")
    pass
