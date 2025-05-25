import json
import logging
import os
from typing import List, Dict, Optional, Any
import uuid
import time

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY_PATH = "data/models/model_registry.json"

class ModelRegistry:
    def __init__(self, registry_path: str = DEFAULT_REGISTRY_PATH):
        self.registry_path = registry_path
        self.models = self._load_registry()
        logger.info(f"ModelRegistry initialized. Loaded {len(self.models)} models from {self.registry_path}")

    def _load_registry(self) -> List[Dict[str, Any]]:
        """Loads the model registry from a JSON file."""
        if not os.path.exists(self.registry_path):
            logger.warning(f"Model registry file not found at {self.registry_path}. Initializing an empty registry.")
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
            with open(self.registry_path, 'w') as f:
                json.dump([], f)
            return []
        try:
            with open(self.registry_path, 'r') as f:
                registry_data = json.load(f)
            return registry_data
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from model registry file {self.registry_path}: {e}", exc_info=True)
            return [] # Return empty list or raise an error
        except Exception as e:
            logger.error(f"Error loading model registry from {self.registry_path}: {e}", exc_info=True)
            return []

    def _save_registry(self):
        """Saves the current state of the model registry to the JSON file."""
        try:
            with open(self.registry_path, 'w') as f:
                json.dump(self.models, f, indent=4)
            logger.debug(f"Model registry saved to {self.registry_path}")
        except Exception as e:
            logger.error(f"Error saving model registry to {self.registry_path}: {e}", exc_info=True)

    def register_model(self, model_name: str, model_version: str, model_path: str, 
                       description: Optional[str] = None, tags: Optional[List[str]] = None, 
                       metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Registers a new model or a new version of an existing model."""
        model_id = str(uuid.uuid4())
        creation_timestamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'

        # Ensure model_path is relative to the models directory for portability
        # Assuming models are stored in a directory like data/models/
        # and model_path provided is relative to that, e.g., "my_model_v1.pkl"
        # If model_path is absolute, consider making it relative or storing a note.
        # For now, we store it as provided.

        new_model_entry = {
            "model_id": model_id,
            "model_name": model_name,
            "model_version": model_version,
            "model_path": model_path, # Path relative to a base model directory (e.g., data/models/)
            "creation_timestamp": creation_timestamp,
            "description": description or "",
            "tags": tags or [],
            "metrics": metrics or {}
        }
        self.models.append(new_model_entry)
        self._save_registry()
        logger.info(f"Registered new model: {model_name} v{model_version} (ID: {model_id})")
        return new_model_entry

    def get_model(self, model_id: Optional[str] = None, model_name: Optional[str] = None, 
                  model_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a model by its ID, or the latest version of a model by name."""
        if model_id:
            for model in self.models:
                if model["model_id"] == model_id:
                    return model
            logger.warning(f"Model with ID '{model_id}' not found.")
            return None
        
        if model_name:
            candidate_models = [m for m in self.models if m["model_name"] == model_name]
            if not candidate_models:
                logger.warning(f"No models found with name '{model_name}'.")
                return None
            
            # Sort by version (lexicographical for now, could be more robust with semver parsing)
            candidate_models.sort(key=lambda x: x["model_version"], reverse=True)
            
            if model_version:
                for model in candidate_models:
                    if model["model_version"] == model_version:
                        return model
                logger.warning(f"Model '{model_name}' version '{model_version}' not found.")
                return None
            else: # Return latest version
                return candidate_models[0]
        
        logger.warning("Must provide model_id or model_name to get_model.")
        return None

    def list_models(self, model_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all models, or all versions of a specific model."""
        if model_name:
            return [m for m in self.models if m["model_name"] == model_name]
        return self.models

    def update_model_metadata(self, model_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Updates metadata for an existing model."""
        for model in self.models:
            if model["model_id"] == model_id:
                # Prevent changing immutable fields like id, name, version, path directly here
                # This method is for mutable metadata like description, tags, metrics
                allowed_updates = ["description", "tags", "metrics"]
                for key, value in updates.items():
                    if key in allowed_updates:
                        model[key] = value
                    else:
                        logger.warning(f"Metadata field '{key}' cannot be updated directly or is not allowed.")
                self._save_registry()
                logger.info(f"Updated metadata for model ID '{model_id}'.")
                return model
        logger.warning(f"Model with ID '{model_id}' not found for metadata update.")
        return None

# Example Usage (for testing or direct script interaction)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Use a temporary registry for this example to avoid altering the main one
    temp_registry_path = "data/models/temp_model_registry.json"
    if os.path.exists(temp_registry_path):
        os.remove(temp_registry_path)

    registry = ModelRegistry(registry_path=temp_registry_path)

    # Register a new model
    registry.register_model(
        model_name="qos_predictor_rf",
        model_version="1.0.0",
        model_path="qos_models/rf_v1.0.0.pkl",
        description="Random Forest model for QoS prediction.",
        tags=["qos", "random_forest", "production"],
        metrics={"accuracy": 0.92, "f1_score": 0.91}
    )

    registry.register_model(
        model_name="qos_predictor_rf",
        model_version="1.0.1",
        model_path="qos_models/rf_v1.0.1.pkl",
        description="Updated Random Forest model with new features.",
        tags=["qos", "random_forest", "experimental"],
        metrics={"accuracy": 0.93, "f1_score": 0.92}
    )

    registry.register_model(
        model_name="anomaly_detector_vae",
        model_version="0.5.0",
        model_path="anomaly_models/vae_v0.5.0.h5",
        description="VAE model for network anomaly detection.",
        tags=["anomaly", "vae", "beta"],
        metrics={"reconstruction_error_threshold": 0.05}
    )

    # List all models
    print("\nAll models:")
    for m in registry.list_models():
        print(json.dumps(m, indent=2))

    # Get a specific model (latest version of qos_predictor_rf)
    print("\nLatest QoS RF model:")
    latest_rf = registry.get_model(model_name="qos_predictor_rf")
    if latest_rf:
        print(json.dumps(latest_rf, indent=2))

    # Get a specific version
    print("\nQoS RF model v1.0.0:")
    rf_v1 = registry.get_model(model_name="qos_predictor_rf", model_version="1.0.0")
    if rf_v1:
        print(json.dumps(rf_v1, indent=2))
        # Update its metadata
        registry.update_model_metadata(rf_v1["model_id"], {"tags": ["qos", "random_forest", "stable"], "description": "Stable Random Forest model for QoS prediction."})
        print("\nUpdated QoS RF model v1.0.0 metadata:")
        updated_rf_v1 = registry.get_model(model_id=rf_v1["model_id"])
        if updated_rf_v1:
            print(json.dumps(updated_rf_v1, indent=2))

    # Clean up temp registry
    if os.path.exists(temp_registry_path):
        os.remove(temp_registry_path)
        logger.info(f"Cleaned up temporary registry: {temp_registry_path}")
