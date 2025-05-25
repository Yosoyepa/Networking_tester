"""
Enhanced Client for interacting with a hybrid ML Model Registry.

The registry supports both:
1. File-based registry (JSON manifest) for lightweight operations
2. MLflow Model Registry for robust versioning and production deployment

This enhanced version provides seamless integration between both systems.
"""
import json
import os
import logging
from typing import List, Dict, Optional, Any, Union
from packaging.version import parse as parse_version
import datetime
import mlflow
import mlflow.sklearn
import mlflow.pyfunc
from mlflow.tracking import MlflowClient
from mlflow.exceptions import MlflowException
from .model_registry_client import ModelRegistryClient

logger = logging.getLogger(__name__)

class EnhancedModelRegistryClient(ModelRegistryClient):
    """
    Enhanced Model Registry Client with MLflow integration.
    
    Extends the base ModelRegistryClient to add MLflow backend support
    while maintaining compatibility with the file-based registry.
    """
    
    def __init__(self, 
                 manifest_path: Optional[str] = None, 
                 project_root_dir: Optional[str] = None,
                 use_mlflow: bool = True,
                 mlflow_tracking_uri: Optional[str] = None,
                 experiment_name: Optional[str] = None):
        """
        Initializes the enhanced ModelRegistryClient with MLflow integration.

        Args:
            manifest_path (Optional[str]): Path to the model registry manifest JSON file.
            project_root_dir (Optional[str]): The absolute path to the project's root directory.
            use_mlflow (bool): Whether to use MLflow Model Registry in addition to file-based registry.
            mlflow_tracking_uri (Optional[str]): MLflow tracking URI. If None, uses default from environment.
            experiment_name (Optional[str]): MLflow experiment name for tracking.
        """
        # Initialize parent class
        super().__init__(manifest_path, project_root_dir)
        
        self.use_mlflow = use_mlflow
        self.experiment_name = experiment_name
        
        # Initialize MLflow client if enabled
        self.mlflow_client: Optional[MlflowClient] = None
        if self.use_mlflow:
            try:
                if mlflow_tracking_uri:
                    mlflow.set_tracking_uri(mlflow_tracking_uri)
                    
                if experiment_name:
                    mlflow.set_experiment(experiment_name)
                    
                self.mlflow_client = MlflowClient()
                logger.info("MLflow Model Registry integration enabled")
                logger.info(f"MLflow Tracking URI: {mlflow.get_tracking_uri()}")
                if experiment_name:
                    logger.info(f"MLflow Experiment: {experiment_name}")
            except Exception as e:
                logger.warning(f"Failed to initialize MLflow client: {e}. Falling back to file-based registry only.")
                self.use_mlflow = False

    def list_models(self, source: str = "both") -> List[str]:
        """
        Lists all available model names from specified source(s).
        
        Args:
            source (str): Source to list from - "file", "mlflow", or "both"
            
        Returns:
            List[str]: List of unique model names
        """
        models = set()
        
        if source in ["file", "both"]:
            file_models = super().list_models()
            models.update(file_models)
            
        if source in ["mlflow", "both"] and self.use_mlflow:
            try:
                mlflow_models = self.mlflow_client.search_registered_models()
                mlflow_model_names = [model.name for model in mlflow_models]
                models.update(mlflow_model_names)
            except Exception as e:
                logger.warning(f"Failed to list models from MLflow: {e}")
                
        return sorted(list(models))

    def get_model_versions(self, model_name: str, source: str = "both") -> List[str]:
        """
        Lists all available versions for a given model name from specified source(s).

        Args:
            model_name (str): The name of the model.
            source (str): Source to search - "file", "mlflow", or "both"

        Returns:
            List[str]: A list of version strings, sorted from newest to oldest.
        """
        versions = set()
        
        if source in ["file", "both"]:
            file_versions = super().get_model_versions(model_name)
            versions.update(file_versions)
            
        if source in ["mlflow", "both"] and self.use_mlflow:
            try:
                mlflow_model = self.mlflow_client.get_registered_model(model_name)
                mlflow_versions = [mv.version for mv in mlflow_model.latest_versions]
                versions.update(mlflow_versions)
            except MlflowException as e:
                if e.error_code != "RESOURCE_DOES_NOT_EXIST":
                    logger.warning(f"Failed to get versions from MLflow for {model_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to get versions from MLflow for {model_name}: {e}")
                
        # Sort versions using semantic versioning, newest first
        version_list = list(versions)
        version_list.sort(key=parse_version, reverse=True)
        return version_list

    def get_model_details(self, 
                         model_name: str, 
                         version: Optional[str] = "latest", 
                         source: str = "both") -> Optional[Dict[str, Any]]:
        """
        Retrieves the details for a specific model and version from specified source(s).

        Args:
            model_name (str): The name of the model.
            version (Optional[str]): The desired version string. Defaults to "latest".
            source (str): Source to search - "file", "mlflow", or "both"

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing model details, or None if not found.
        """
        # Try file-based registry first if requested
        if source in ["file", "both"]:
            file_details = super().get_model_details(model_name, version)
            if file_details:
                file_details["source"] = "file"
                return file_details
                
        # Try MLflow registry if requested
        if source in ["mlflow", "both"] and self.use_mlflow:
            try:
                mlflow_model = self.mlflow_client.get_registered_model(model_name)
                
                # Get the appropriate version
                target_version = None
                if version == "latest":
                    if mlflow_model.latest_versions:
                        target_version = max(mlflow_model.latest_versions, 
                                           key=lambda v: parse_version(v.version))
                else:
                    for mv in mlflow_model.latest_versions:
                        if mv.version == version:
                            target_version = mv
                            break
                            
                if target_version:
                    model_uri = f"models:/{model_name}/{target_version.version}"
                    return {
                        "model_name": model_name,
                        "version": target_version.version,
                        "model_path": model_uri,
                        "description": target_version.description,
                        "creation_date": str(target_version.creation_timestamp),
                        "metadata": dict(target_version.tags) if target_version.tags else {},
                        "source": "mlflow",
                        "mlflow_uri": model_uri,
                        "run_id": target_version.run_id
                    }
                    
            except MlflowException as e:
                if e.error_code != "RESOURCE_DOES_NOT_EXIST":
                    logger.warning(f"Failed to get model details from MLflow for {model_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to get model details from MLflow for {model_name}: {e}")
                
        return None

    def register_model_enhanced(self, 
                               model_name: str, 
                               model_version: str, 
                               model_path: str, 
                               metadata: Optional[Dict[str, Any]] = None,
                               scaler_path: Optional[str] = None,
                               description: Optional[str] = None,
                               creation_date: Optional[str] = None,
                               register_to_mlflow: bool = True,
                               mlflow_run_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Registers a new model to both file-based and MLflow registries.

        Args:
            model_name (str): The name of the model.
            model_version (str): The version string (e.g., "1.0.0").
            model_path (str): Path to the model artifact.
            metadata (Optional[Dict[str, Any]]): Arbitrary metadata for the model version.
            scaler_path (Optional[str]): Path to the scaler artifact, if any.
            description (Optional[str]): A description for this model version.
            creation_date (Optional[str]): ISO format string of creation date.
            register_to_mlflow (bool): Whether to also register to MLflow.
            mlflow_run_id (Optional[str]): MLflow run ID to associate with the model.

        Returns:
            Dict[str, Any]: The details of the registered model version.
            
        Raises:
            ValueError: If the model version already exists.
        """
        registration_results = {}
        
        # Register to file-based registry first
        try:
            file_result = self.register_model(
                model_name=model_name,
                model_version=model_version,
                model_path=model_path,
                metadata=metadata,
                scaler_path=scaler_path,
                description=description,
                creation_date=creation_date
            )
            registration_results["file_registry"] = file_result
            logger.info(f"Successfully registered {model_name} v{model_version} to file registry")
        except Exception as e:
            logger.error(f"Failed to register to file registry: {e}")
            registration_results["file_registry"] = {"error": str(e)}
            
        # Register to MLflow if enabled and requested
        if self.use_mlflow and register_to_mlflow:
            try:
                mlflow_result = self._register_to_mlflow(
                    model_name=model_name,
                    model_version=model_version,
                    model_path=model_path,
                    metadata=metadata,
                    description=description,
                    mlflow_run_id=mlflow_run_id
                )
                registration_results["mlflow_registry"] = mlflow_result
                logger.info(f"Successfully registered {model_name} v{model_version} to MLflow registry")
            except Exception as e:
                logger.error(f"Failed to register to MLflow registry: {e}")
                registration_results["mlflow_registry"] = {"error": str(e)}
                
        return registration_results

    def _register_to_mlflow(self, 
                           model_name: str, 
                           model_version: str, 
                           model_path: str, 
                           metadata: Optional[Dict[str, Any]] = None,
                           description: Optional[str] = None,
                           mlflow_run_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Internal method to register a model to MLflow.
        
        Args:
            model_name (str): The name of the model.
            model_version (str): The version string.
            model_path (str): Path to the model artifact.
            metadata (Optional[Dict[str, Any]]): Metadata for the model.
            description (Optional[str]): Description for this model version.
            mlflow_run_id (Optional[str]): MLflow run ID to associate with the model.
            
        Returns:
            Dict[str, Any]: Registration result details.
        """
        # Ensure the registered model exists in MLflow
        try:
            mlflow_model = self.mlflow_client.get_registered_model(model_name)
        except MlflowException as e:
            if e.error_code == "RESOURCE_DOES_NOT_EXIST":
                # Create the registered model
                mlflow_model = self.mlflow_client.create_registered_model(
                    name=model_name,
                    tags={"created_by": "enhanced_model_registry_client"},
                    description=f"Model {model_name} registered via hybrid registry client"
                )
                logger.info(f"Created new registered model in MLflow: {model_name}")
            else:
                raise
                
        # Register the model version
        model_version_obj = None
        
        if mlflow_run_id:
            # Register from existing run
            model_uri = f"runs:/{mlflow_run_id}/model"
            model_version_obj = self.mlflow_client.create_model_version(
                name=model_name,
                source=model_uri,
                run_id=mlflow_run_id,
                description=description
            )
        else:
            # Log the model in a new run
            with mlflow.start_run():
                # Determine model type and log appropriately
                model_uri = self._log_model_to_mlflow(model_path, model_name)
                model_version_obj = mlflow.register_model(
                    model_uri=model_uri,
                    name=model_name,
                    description=description
                )
                
        # Add metadata as tags
        if metadata and model_version_obj:
            for key, value in metadata.items():
                try:
                    self.mlflow_client.set_model_version_tag(
                        name=model_name,
                        version=model_version_obj.version,
                        key=key,
                        value=str(value)
                    )
                except Exception as e:
                    logger.warning(f"Failed to set tag {key}: {e}")
                    
        return {
            "version": model_version_obj.version if model_version_obj else model_version,
            "mlflow_uri": f"models:/{model_name}/{model_version_obj.version if model_version_obj else model_version}",
            "run_id": model_version_obj.run_id if model_version_obj else mlflow_run_id,
            "description": description,
            "metadata": metadata or {}
        }

    def _log_model_to_mlflow(self, model_path: str, model_name: str) -> str:
        """
        Logs a model to MLflow based on its file extension.
        
        Args:
            model_path (str): Path to the model file.
            model_name (str): Name of the model.
            
        Returns:
            str: MLflow model URI.
        """
        resolved_path = self._resolve_path(model_path)
        
        if model_path.endswith('.joblib') or model_path.endswith('.pkl'):
            # Scikit-learn model
            import joblib
            model = joblib.load(resolved_path)
            return mlflow.sklearn.log_model(model, "model").model_uri
        elif model_path.endswith('.h5') or model_path.endswith('.keras'):
            # Keras/TensorFlow model
            import tensorflow as tf
            model = tf.keras.models.load_model(resolved_path)
            return mlflow.keras.log_model(model, "model").model_uri
        else:
            # Generic model using MLflow's pyfunc
            return mlflow.pyfunc.log_model(
                artifact_path="model",
                python_model=None,  # Would need a custom wrapper
                artifacts={"model_file": resolved_path}
            ).model_uri

    def load_model_from_mlflow(self, model_name: str, version: str = "latest", stage: Optional[str] = None):
        """
        Loads a model directly from MLflow.
        
        Args:
            model_name (str): Name of the model.
            version (str): Version of the model ("latest", "1", "2", etc.).
            stage (Optional[str]): Stage of the model ("Staging", "Production", etc.).
            
        Returns:
            The loaded model object.
        """
        if not self.use_mlflow:
            raise ValueError("MLflow is not enabled for this registry client")
            
        if stage:
            model_uri = f"models:/{model_name}/{stage}"
        else:
            model_uri = f"models:/{model_name}/{version}"
            
        try:
            # Try loading as sklearn first
            return mlflow.sklearn.load_model(model_uri)
        except Exception:
            try:
                # Try loading as keras
                return mlflow.keras.load_model(model_uri)
            except Exception:
                # Fall back to pyfunc
                return mlflow.pyfunc.load_model(model_uri)

    def promote_model_stage(self, model_name: str, version: str, stage: str) -> bool:
        """
        Promotes a model version to a specific stage in MLflow.
        
        Args:
            model_name (str): Name of the model.
            version (str): Version to promote.
            stage (str): Target stage ("Staging", "Production", "Archived").
            
        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.use_mlflow:
            logger.warning("MLflow is not enabled for this registry client")
            return False
            
        try:
            self.mlflow_client.transition_model_version_stage(
                name=model_name,
                version=version,
                stage=stage
            )
            logger.info(f"Successfully promoted {model_name} v{version} to {stage}")
            return True
        except Exception as e:
            logger.error(f"Failed to promote model {model_name} v{version} to {stage}: {e}")
            return False

    def get_model_metrics(self, model_name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves metrics for a model version from MLflow.
        
        Args:
            model_name (str): Name of the model.
            version (str): Version of the model.
            
        Returns:
            Optional[Dict[str, Any]]: Dictionary of metrics, or None if not found.
        """
        if not self.use_mlflow:
            return None
            
        try:
            model_version = self.mlflow_client.get_model_version(model_name, version)
            if model_version.run_id:
                run = self.mlflow_client.get_run(model_version.run_id)
                return run.data.metrics
        except Exception as e:
            logger.error(f"Failed to get metrics for {model_name} v{version}: {e}")
            
        return None

    def sync_registries(self) -> Dict[str, Any]:
        """
        Synchronizes models between file-based and MLflow registries.
        
        Returns:
            Dict[str, Any]: Synchronization results.
        """
        if not self.use_mlflow:
            return {"error": "MLflow is not enabled"}
            
        sync_results = {
            "file_to_mlflow": [],
            "mlflow_to_file": [],
            "errors": []
        }
        
        try:
            # Get models from both registries
            file_models = self.list_models(source="file")
            mlflow_models = self.list_models(source="mlflow")
            
            # Models only in file registry
            file_only = set(file_models) - set(mlflow_models)
            for model_name in file_only:
                sync_results["file_to_mlflow"].append(model_name)
                
            # Models only in MLflow registry  
            mlflow_only = set(mlflow_models) - set(file_models)
            for model_name in mlflow_only:
                sync_results["mlflow_to_file"].append(model_name)
                
            logger.info(f"Registry sync completed. File->MLflow: {len(file_only)}, MLflow->File: {len(mlflow_only)}")
            
        except Exception as e:
            error_msg = f"Failed to sync registries: {e}"
            logger.error(error_msg)
            sync_results["errors"].append(error_msg)
            
        return sync_results
