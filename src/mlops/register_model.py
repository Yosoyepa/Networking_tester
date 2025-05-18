"""
Script for registering trained ML models with the Model Registry.

This script would typically:
1. Take a trained model artifact (and its metadata) as input.
2. Interact with the ModelRegistryClient to add or update the model entry.
"""
import logging
import argparse
import os
import sys
import json
import shutil
from typing import Optional
import mlflow # Added import

# Ensure project root is in path BEFORE attempting to import from src
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_dir = os.path.abspath(os.path.join(current_script_dir, "..", ".."))
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

# Now, this import should work when the script is called from any CWD,
# especially when called by the orchestrator with CWD set to project_root.
from src.ai_monitoring.model_registry_client import ModelRegistryClient 
# from src.utils.logger_config import setup_logging # Example

logger = logging.getLogger(__name__)


def register_model_pipeline(config_path: str, model_type: str): # Added model_type
    """Main function to register a model based on the configuration and model type."""
    logger.info(f"Starting model registration process for model_type: {model_type}")

    active_mlflow_run = mlflow.start_run(run_id=os.environ.get("MLFLOW_RUN_ID"), nested=True)
    with active_mlflow_run as run:
        mlflow.log_param("registration_config_path", config_path)
        mlflow.log_param("registration_model_type", model_type)
        logger.info(f"Joined MLflow Run ID: {run.info.run_id} for model registration")

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded registration configuration from: {config_path}")
            mlflow.log_param("registration_config_load_status", "success")

        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}", exc_info=True)
            mlflow.log_param("registration_config_load_status", "failed")
            mlflow.log_param("registration_error", str(e))
            mlflow.set_tag("mlflow.runName", f"register_model_failed_config_load_{model_type}")
            raise

        model_name = config.get("model_name")
        model_version = config.get("model_version")
        model_artifacts_dir = config.get("output_model_path") # This is the source path from training
        
        # For GMM and VAE, the output_model_path from config is the specific model file or prefix
        # For Isolation Forest, it's the .iforest file.
        # The ModelRegistryClient expects a directory of artifacts to copy.
        # We need to ensure the artifacts are in a stageable directory structure.
        # The pipeline_orchestrator.py already creates a run-specific artifact directory.
        # Let's assume model_artifacts_dir IS the path to the primary model file (e.g., model.gmm, model.iforest, vae_prefix)
        # The ModelRegistryClient's register_model method copies the file or directory specified by model_path.
        # If model_path is a file, it copies that file. If it's a directory, it copies the directory.

        # The key is that all necessary files (model, scaler, metadata.json) for GMM/VAE 
        # should be co-located or their paths derivable if model_artifacts_dir is a prefix/main file.
        # The ModelRegistryClient handles copying these.
        # For MLflow logging, we want to log these artifacts if they haven't been logged by train_model.py already.
        # However, register_model.py's primary role is custom registry, not MLflow artifact logging of the model itself.
        # train_model.py should be the one logging the model artifacts to MLflow.
        # This script (register_model.py) can log metadata about the registration process.

        if not all([model_name, model_version, model_artifacts_dir]):
            err_msg = "Missing critical configuration: model_name, model_version, or output_model_path."
            logger.error(err_msg)
            mlflow.log_param("registration_validation_status", "failed")
            mlflow.log_param("registration_error", err_msg)
            mlflow.set_tag("mlflow.runName", f"register_model_failed_validation_{model_name}_{model_version}")
            raise ValueError(err_msg)
        
        mlflow.log_param("model_name", model_name)
        mlflow.log_param("model_version", model_version)
        mlflow.log_param("model_artifacts_dir_for_registration", model_artifacts_dir)

        # Log key artifacts to MLflow if they exist, to ensure they are captured in the run
        # This is somewhat redundant if train_model.py does it, but acts as a safeguard or for context.
        # These are logged under a "registration_context_artifacts" path to distinguish them.
        
        # For GMM: .gmm, _scaler.joblib, _metadata.json
        if model_type == "gmm":
            gmm_model_file = model_artifacts_dir # Assuming this is the .gmm file path
            gmm_scaler_file = gmm_model_file.replace(".gmm", "_scaler.joblib")
            gmm_metadata_file = gmm_model_file.replace(".gmm", "_metadata.json")
            if os.path.exists(gmm_model_file):
                mlflow.log_artifact(gmm_model_file, artifact_path="registration_context_artifacts/gmm_model")
            if os.path.exists(gmm_scaler_file):
                mlflow.log_artifact(gmm_scaler_file, artifact_path="registration_context_artifacts/gmm_model")
            if os.path.exists(gmm_metadata_file):
                mlflow.log_artifact(gmm_metadata_file, artifact_path="registration_context_artifacts/gmm_model")

        # For VAE: _model.weights.h5, _scaler.joblib, _metadata.json
        elif model_type == "vae":
            vae_prefix = model_artifacts_dir # Assuming this is the prefix
            vae_model_file = f"{vae_prefix}_model.weights.h5"
            vae_scaler_file = f"{vae_prefix}_scaler.joblib"
            vae_metadata_file = f"{vae_prefix}_metadata.json"
            if os.path.exists(vae_model_file):
                mlflow.log_artifact(vae_model_file, artifact_path="registration_context_artifacts/vae_model")
            if os.path.exists(vae_scaler_file):
                mlflow.log_artifact(vae_scaler_file, artifact_path="registration_context_artifacts/vae_model")
            if os.path.exists(vae_metadata_file):
                mlflow.log_artifact(vae_metadata_file, artifact_path="registration_context_artifacts/vae_model")

        # For Isolation Forest: .iforest (already model_artifacts_dir), potentially scaler and features if separate
        elif model_type == "isolation_forest":
            iforest_model_file = model_artifacts_dir # Assuming this is the .iforest file
            # If Isolation Forest in your setup saves separate scaler/features files that need registration, log them.
            # Example:
            # iforest_scaler_file = model_artifacts_dir.replace(".iforest", ".scaler") 
            # iforest_features_file = model_artifacts_dir.replace(".iforest", ".features")
            if os.path.exists(iforest_model_file):
                mlflow.log_artifact(iforest_model_file, artifact_path="registration_context_artifacts/isolation_forest_model")
            # if os.path.exists(iforest_scaler_file):
            #     mlflow.log_artifact(iforest_scaler_file, artifact_path="registration_context_artifacts/isolation_forest_model")
            # if os.path.exists(iforest_features_file):
            #     mlflow.log_artifact(iforest_features_file, artifact_path="registration_context_artifacts/isolation_forest_model")


        # Determine the project root to pass to ModelRegistryClient
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_script_dir, "..", ".."))

        registry_client = ModelRegistryClient(project_root_dir=project_root)

        registered_path = model_artifacts_dir
        mlflow.log_param("custom_registry_registered_path", registered_path)

        registration_metadata = {
            "model_type": model_type,
            "run_config_path": config_path, 
            "training_data_path": config.get("training_data_path"),
            "evaluation_data_path": config.get("evaluation_data_path"),
            "evaluation_metrics_path": config.get("output_metrics_path")
        }
        mlflow.log_params({f"custom_reg_meta_{k}": v for k, v in registration_metadata.items() if v is not None})
        
        logger.info(f"Registering model: {model_name} v{model_version}")
        logger.info(f"Artifacts directory: {registered_path}")
        logger.info(f"Registration metadata: {registration_metadata}")

        try:
            registration_details = registry_client.register_model(
                model_name=model_name,
                model_version=model_version,
                model_path=registered_path, 
                metadata=registration_metadata,
                description=f"{model_type.upper()} model version {model_version}"
            )
            logger.info(f"Model {model_name} v{model_version} registered successfully. Details: {registration_details}")
            mlflow.log_param("custom_registry_registration_status", "success")
            if isinstance(registration_details, dict):
                mlflow.log_params({f"custom_reg_details_{k}": v for k, v in registration_details.items() if isinstance(v, (str, int, float, bool))})

            # --- Production Transition Logic ---
            evaluation_metrics_path = config.get("output_metrics_path") # Path from run-specific config
            promote_to_production = False
            
            # Ensure evaluation_metrics_path is absolute if it came from config and might be relative
            abs_evaluation_metrics_path = evaluation_metrics_path
            # project_root is defined earlier in the script
            if not os.path.isabs(abs_evaluation_metrics_path) and os.path.exists(os.path.join(project_root_dir, abs_evaluation_metrics_path)):
                abs_evaluation_metrics_path = os.path.join(project_root_dir, abs_evaluation_metrics_path)
            elif not os.path.exists(abs_evaluation_metrics_path):
                logger.warning(f"Evaluation metrics file path does not exist: {abs_evaluation_metrics_path}")
                abs_evaluation_metrics_path = None # Mark as not found

            if abs_evaluation_metrics_path:
                try:
                    with open(abs_evaluation_metrics_path, 'r') as f:
                        metrics = json.load(f)
                    logger.info(f"Loaded evaluation metrics for production decision from {abs_evaluation_metrics_path}: {metrics}")
                    mlflow.log_dict(metrics, "evaluation_metrics_for_production_decision.json")

                    # Define your promotion criteria here.
                    primary_metric_name = config.get("promotion_metric_name", "f1_score") # Get from config or default
                    promotion_threshold = config.get("promotion_metric_threshold", 0.75)  # Get from config or default
                    
                    actual_metric_value = metrics.get(primary_metric_name)

                    if actual_metric_value is not None:
                        if actual_metric_value > promotion_threshold:
                            promote_to_production = True
                            logger.info(f"Model {model_name} v{model_version} meets criteria for production ({primary_metric_name}: {actual_metric_value} > {promotion_threshold}).")
                            mlflow.log_metric(f"production_{primary_metric_name}_at_promotion", actual_metric_value)
                        else:
                            logger.info(f"Model {model_name} v{model_version} does not meet criteria for production ({primary_metric_name}: {actual_metric_value} <= {promotion_threshold}). Will remain in default stage.")
                            mlflow.log_param("production_promotion_skipped_reason", f"{primary_metric_name} {actual_metric_value} <= {promotion_threshold}")
                    else:
                        logger.warning(f"Metric '{primary_metric_name}' not found in evaluation metrics. Cannot assess for production promotion based on it.")
                        mlflow.log_param("production_promotion_skipped_reason", f"Metric '{primary_metric_name}' not found")

                except Exception as e:
                    logger.error(f"Error processing evaluation metrics from {abs_evaluation_metrics_path} for production decision: {e}", exc_info=True)
                    mlflow.log_param("production_decision_error", str(e))
            else:
                logger.warning(f"Evaluation metrics file not found or path invalid. Cannot assess for production promotion.")
                mlflow.log_param("production_decision_status", "metrics_not_found_or_invalid_path")

            if promote_to_production:
                try:
                    logger.info(f"Promoting model {model_name} v{model_version} to Production in custom registry.")
                    registry_client.set_model_version_stage(model_name, model_version, "Production")
                    mlflow.set_tag("custom_registry_stage", "Production")
                    logger.info(f"Successfully transitioned {model_name} v{model_version} to Production.")

                    logger.info(f"Archiving other Production versions of model {model_name}.")
                    all_versions_details = registry_client.get_model_versions(model_name)
                    versions_to_archive = []
                    if all_versions_details:
                        for v_detail in all_versions_details:
                            if isinstance(v_detail, dict) and v_detail.get('stage') == "Production" and v_detail.get('version') != model_version:
                                registry_client.set_model_version_stage(model_name, v_detail.get('version'), "Archived")
                                versions_to_archive.append(v_detail.get('version'))
                    
                    if versions_to_archive:
                        logger.info(f"Archived previous production versions: {versions_to_archive}")
                        mlflow.log_param("archived_custom_production_versions", json.dumps(versions_to_archive))
                    else:
                        logger.info("No other production versions found to archive for this model.")
                except AttributeError as ae:
                    logger.error(f"ModelRegistryClient does not support stage transition (set_model_version_stage) or version listing (get_model_versions) methods: {ae}. Skipping production transition.")
                    mlflow.log_param("production_transition_error", f"Client method missing: {ae}")
                except Exception as e:
                    logger.error(f"Error during production transition or archiving in custom registry: {e}", exc_info=True)
                    mlflow.log_param("production_transition_error", str(e))
            else:
                logger.info(f"Model {model_name} v{model_version} will not be promoted to Production at this time.")
                current_stage_after_reg = 'Unknown'
                if hasattr(registry_client, 'get_model_version_details'):
                    version_details = registry_client.get_model_version_details(model_name, model_version)
                    if version_details:
                         current_stage_after_reg = version_details.get('stage', 'Staging') # Default to Staging if stage not set
                else:
                    current_stage_after_reg = 'Staging' # Fallback if method doesn't exist
                mlflow.set_tag("custom_registry_stage", current_stage_after_reg)
            # --- End of Production Transition Logic ---

        except ValueError as ve:
            logger.error(f"ValueError during model registration: {ve}", exc_info=True)
            mlflow.log_param("custom_registry_registration_status", "failed_value_error")
            mlflow.log_param("registration_error", str(ve))
            mlflow.set_tag("mlflow.runName", f"register_model_failed_value_error_{model_name}_{model_version}")
            raise
        except Exception as e:
            logger.error(f"Failed to register model {model_name} v{model_version}: {e}", exc_info=True)
            mlflow.log_param("custom_registry_registration_status", "failed_exception")
            mlflow.log_param("registration_error", str(e))
            mlflow.set_tag("mlflow.runName", f"register_model_failed_exception_{model_name}_{model_version}")
            raise

        logger.info("Model registration process finished successfully.")
        mlflow.set_tag("mlflow.runName", f"register_model_success_{model_name}_{model_version}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="Register ML models with the Model Registry.")
    # Changed from --model-path to --config as it contains all necessary paths and info
    parser.add_argument("--config", type=str, required=True, 
                        help="Path to the run-specific JSON configuration file generated by the orchestrator.")
    parser.add_argument("--model_type", type=str, required=True, choices=['isolation_forest', 'gmm', 'vae'],
                        help="Type of model being registered ('isolation_forest', 'gmm', or 'vae').")
    # model_name, model_version, and metadata_path are now derived from the config file.

    args = parser.parse_args()

    register_model_pipeline(args.config, args.model_type)
