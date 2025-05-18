"""
Client for interacting with a file-based ML Model Registry.

The registry is defined by a JSON manifest file that lists available models,
their versions, and paths to model/scaler files.
"""
import json
import os
import logging
from typing import List, Dict, Optional, Any
from packaging.version import parse as parse_version # For semantic version comparison
import datetime # Added for creation_date default

logger = logging.getLogger(__name__)

DEFAULT_MANIFEST_PATH = "data/models/model_registry.json"

class ModelRegistryClient:
    def __init__(self, manifest_path: Optional[str] = None, project_root_dir: Optional[str] = None):
        """
        Initializes the ModelRegistryClient.

        Args:
            manifest_path (Optional[str]): Path to the model registry manifest JSON file.
                                           Defaults to DEFAULT_MANIFEST_PATH.
            project_root_dir (Optional[str]): The absolute path to the project\'s root directory.
                                              If None, paths in the manifest are assumed to be
                                              absolute or resolvable from the current working directory.
                                              It\'s recommended to provide this for robust path resolution.
        """
        self.project_root_dir = project_root_dir if project_root_dir else os.getcwd()
        # Ensure manifest_path is resolved correctly using project_root_dir from the start
        self.manifest_path = manifest_path or DEFAULT_MANIFEST_PATH
        if not os.path.isabs(self.manifest_path):
            self.resolved_manifest_path = os.path.join(self.project_root_dir, self.manifest_path)
        else:
            self.resolved_manifest_path = self.manifest_path
            
        self.registry_data: Dict[str, Any] = {}
        self._load_manifest()

    def _make_path_relative(self, path_to_make_relative: str) -> str:
        """Converts an absolute path to be relative to the project root, if it\'s within the project."""
        if not path_to_make_relative or not os.path.isabs(path_to_make_relative):
            return path_to_make_relative # Already relative or empty
        if os.path.commonpath([self.project_root_dir, path_to_make_relative]) == self.project_root_dir:
            return os.path.relpath(path_to_make_relative, self.project_root_dir)
        return path_to_make_relative # Not under project root, keep absolute

    def _resolve_path(self, relative_path: str) -> str:
        """Resolves a path relative to the project root directory."""
        if os.path.isabs(relative_path):
            return relative_path
        return os.path.join(self.project_root_dir, relative_path)

    def _load_manifest(self):
        """Loads the model registry manifest file."""
        # resolved_manifest_path is now set in __init__
        try:
            with open(self.resolved_manifest_path, 'r') as f:
                self.registry_data = json.load(f)
            logger.info(f"Successfully loaded model registry manifest from: {self.resolved_manifest_path}")
        except FileNotFoundError:
            logger.warning(f"Model registry manifest file not found at: {self.resolved_manifest_path}. A new one will be created upon registration.")
            self.registry_data = {"models": []}
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from model registry manifest: {self.resolved_manifest_path}. Registry will be reset if registration occurs.")
            self.registry_data = {"models": []}
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading the manifest {self.resolved_manifest_path}: {e}", exc_info=True)
            self.registry_data = {"models": []}

    def _save_manifest(self):
        """Saves the current registry data to the manifest file."""
        # resolved_manifest_path is now set in __init__
        try:
            os.makedirs(os.path.dirname(self.resolved_manifest_path), exist_ok=True)
            with open(self.resolved_manifest_path, 'w') as f:
                json.dump(self.registry_data, f, indent=2)
            logger.info(f"Successfully saved model registry manifest to: {self.resolved_manifest_path}")
        except Exception as e:
            logger.error(f"Failed to save model registry manifest to {self.resolved_manifest_path}: {e}", exc_info=True)
            raise # Re-raise to indicate failure

    def list_models(self) -> List[str]:
        """Lists all available model names in the registry."""
        if "models" not in self.registry_data:
            return []
        return [model.get("model_name") for model in self.registry_data["models"] if model.get("model_name")]

    def get_model_versions(self, model_name: str) -> List[str]:
        """
        Lists all available versions for a given model name.

        Args:
            model_name (str): The name of the model.

        Returns:
            List[str]: A list of version strings, sorted from newest to oldest.
        """
        if "models" not in self.registry_data:
            return []
        for model_entry in self.registry_data["models"]:
            if model_entry.get("model_name") == model_name:
                versions = [v.get("version") for v in model_entry.get("versions", []) if v.get("version")]
                # Sort versions using semantic versioning, newest first
                versions.sort(key=parse_version, reverse=True)
                return versions
        return []

    def get_model_details(self, model_name: str, version: Optional[str] = "latest") -> Optional[Dict[str, Any]]:
        """
        Retrieves the details for a specific model and version.

        Args:
            model_name (str): The name of the model.
            version (Optional[str]): The desired version string (e.g., "1.0.0").
                                     If "latest", the highest semantic version is returned.
                                     Defaults to "latest".

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing model details (including resolved
                                      model_path and scaler_path), or None if not found.
        """
        if "models" not in self.registry_data:
            logger.warning(f"No models found in registry data when searching for model '{model_name}'")
            return None

        for model_entry in self.registry_data["models"]:
            if model_entry.get("model_name") == model_name:
                available_versions = model_entry.get("versions", [])
                if not available_versions:
                    logger.warning(f"No versions found for model '{model_name}'")
                    return None

                target_version_details = None
                if version == "latest":
                    sorted_versions = sorted(available_versions, key=lambda v: parse_version(v.get("version", "0.0.0")), reverse=True)
                    if sorted_versions:
                        target_version_details = sorted_versions[0]
                else:
                    for v_details in available_versions:
                        if v_details.get("version") == version:
                            target_version_details = v_details
                            break
                
                if target_version_details:
                    # Create a copy to avoid modifying the loaded registry_data
                    details_copy = target_version_details.copy()
                    if "model_path" in details_copy:
                        details_copy["model_path"] = self._resolve_path(details_copy["model_path"])
                    
                    # If scaler_path was explicitly registered for this version, resolve it.
                    # Otherwise, do not attempt to derive it. The consuming service
                    # will use model_path (directory) and model_type (from metadata)
                    # to locate specific artifacts like the scaler.
                    if "scaler_path" in details_copy: 
                        details_copy["scaler_path"] = self._resolve_path(details_copy["scaler_path"])

                    details_copy["model_name"] = model_name # Ensure model_name is part of the returned dict
                    return details_copy
                else:
                    logger.warning(f"Version '{version}' not found for model '{model_name}'. Available versions: {[v.get('version') for v in available_versions]}")
                    return None
        
        logger.warning(f"Model '{model_name}' not found in the registry.")
        return None

    def register_model(self, 
                       model_name: str, 
                       model_version: str, 
                       model_path: str, 
                       metadata: Optional[Dict[str, Any]] = None,
                       scaler_path: Optional[str] = None,
                       description: Optional[str] = None,
                       creation_date: Optional[str] = None) -> Dict[str, Any]:
        """
        Registers a new model or a new version of an existing model.

        Args:
            model_name (str): The name of the model.
            model_version (str): The version string (e.g., "1.0.0").
            model_path (str): Path to the model artifact. Will be stored relative to project_root_dir.
            metadata (Optional[Dict[str, Any]]): Arbitrary metadata for the model version.
            scaler_path (Optional[str]): Path to the scaler artifact, if any. Stored relative.
            description (Optional[str]): A description for this model version.
            creation_date (Optional[str]): ISO format string of creation date. Defaults to now.

        Returns:
            Dict[str, Any]: The details of the registered model version.
            
        Raises:
            ValueError: If the model version already exists for the given model name.
        """
        if "models" not in self.registry_data:
            self.registry_data["models"] = []

        model_entry = None
        for entry in self.registry_data["models"]:
            if entry.get("model_name") == model_name:
                model_entry = entry
                break
        
        if model_entry is None:
            model_entry = {
                "model_name": model_name,
                "versions": []
            }
            self.registry_data["models"].append(model_entry)

        # Check if version already exists
        for v_details in model_entry["versions"]:
            if v_details.get("version") == model_version:
                error_msg = f"Version \'{model_version}\' already exists for model \'{model_name}\'."
                logger.error(error_msg)
                raise ValueError(error_msg)

        relative_model_path = self._make_path_relative(model_path)
        relative_scaler_path = self._make_path_relative(scaler_path) if scaler_path else None

        version_details = {
            "version": model_version,
            "description": description or f"Model version {model_version}",
            "model_path": relative_model_path,
            "creation_date": creation_date or datetime.datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        if relative_scaler_path:
            version_details["scaler_path"] = relative_scaler_path
        
        model_entry["versions"].append(version_details)
        
        # Sort versions by semantic versioning, newest first, after adding
        model_entry["versions"].sort(key=lambda v: parse_version(v.get("version", "0.0.0")), reverse=True)

        self._save_manifest()
        
        # Return a copy of the details as they are in the registry (with relative paths)
        registered_details = version_details.copy()
        registered_details["model_name"] = model_name 
        logger.info(f"Successfully registered model \'{model_name}\' version \'{model_version}\'.")
        return registered_details

if __name__ == '__main__':
    # This assumes the script is run from the project root (networking_tester)
    # or that 'data/models/model_registry.json' is in the CWD.
    logging.basicConfig(level=logging.INFO)
    
    # Create a dummy manifest for testing if it doesn't exist
    dummy_manifest_content = {
        "models": [
            {
                "model_name": "qos_anomaly_default",
                "versions": [
                    {
                        "version": "1.0.0",
                        "description": "Initial Isolation Forest model.",
                        "model_path": "data/models/dummy_model_v1.0.0.joblib",
                        "scaler_path": "data/models/dummy_model_v1.0.0_scaler.joblib",
                        "creation_date": "2025-05-17T10:00:00Z",
                        "metadata": {"expected_features": ["feature1", "feature2"]}
                    },
                    {
                        "version": "0.9.0",
                        "description": "Older Isolation Forest model.",
                        "model_path": "data/models/dummy_model_v0.9.0.joblib",
                        "scaler_path": "data/models/dummy_model_v0.9.0_scaler.joblib",
                        "creation_date": "2025-04-17T10:00:00Z"
                    }
                ]
            },
            {
                "model_name": "performance_predictor",
                "versions": [
                    {
                        "version": "0.1.0-alpha",
                        "description": "Alpha version of performance predictor.",
                        "model_path": "data/models/perf_predictor_v0.1.0.joblib",
                        "creation_date": "2025-05-01T12:00:00Z"
                    }
                ]
            }
        ]
    }
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) # .. to get to src, then .. again for project root
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")) # Correct path from src/ai_monitoring to project root

    manifest_file = os.path.join(project_root, DEFAULT_MANIFEST_PATH)
    
    if not os.path.exists(manifest_file):
        os.makedirs(os.path.dirname(manifest_file), exist_ok=True)
        with open(manifest_file, 'w') as f:
            json.dump(dummy_manifest_content, f, indent=2)
        logger.info(f"Created dummy manifest at {manifest_file}")

        # Create dummy model/scaler files for the "latest" qos_anomaly_default
        os.makedirs(os.path.join(project_root, "data/models"), exist_ok=True)
        try:
            with open(os.path.join(project_root, "data/models/dummy_model_v1.0.0.joblib"), 'w') as f:
                f.write("dummy model content")
            with open(os.path.join(project_root, "data/models/dummy_model_v1.0.0_scaler.joblib"), 'w') as f:
                f.write("dummy scaler content")
        except IOError as e:
            logger.error(f"Could not create dummy model/scaler files: {e}")


    # Initialize client, assuming execution from project root for path resolution.
    # If running this file directly, project_root needs to be correctly set.
    
    client = ModelRegistryClient(manifest_path=DEFAULT_MANIFEST_PATH, project_root_dir=project_root)

    logger.info("Available models:")
    for model_name in client.list_models():
        logger.info(f"- {model_name}")
        versions = client.get_model_versions(model_name)
        logger.info(f"  Versions: {versions}")

    logger.info("\nDetails for qos_anomaly_default (latest):")
    details_latest = client.get_model_details("qos_anomaly_default")
    if details_latest:
        logger.info(json.dumps(details_latest, indent=2))
        # Check if paths are resolved
        logger.info(f"Resolved model path: {details_latest.get('model_path')}")
        logger.info(f"Resolved scaler path: {details_latest.get('scaler_path')}")


    logger.info("\nDetails for qos_anomaly_default (v0.9.0):")
    details_specific = client.get_model_details("qos_anomaly_default", "0.9.0")
    if details_specific:
        logger.info(json.dumps(details_specific, indent=2))

    logger.info("\nDetails for a non-existent model:")
    details_none = client.get_model_details("non_existent_model")
    if not details_none:
        logger.info("Correctly returned None for non_existent_model")

    logger.info("\nDetails for performance_predictor (latest, no explicit scaler in manifest):")
    details_perf = client.get_model_details("performance_predictor")
    if details_perf:
        logger.info(json.dumps(details_perf, indent=2))
        logger.info(f"Derived scaler path: {details_perf.get('scaler_path')}")


