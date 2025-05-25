"""
Script for training new ML models.

This script would typically:
1. Load training data (from PDS or specified datasets).
2. Preprocess the data and extract features.
3. Train one or more ML models.
4. Evaluate the trained models.
5. Save the trained model artifacts.
"""
import logging
import argparse
import os
import sys
import time
import json # Added
import pandas as pd # Added
import numpy as np # Added
from sklearn.ensemble import IsolationForest # Added
import joblib # Added
import mlflow # Added MLflow
import mlflow.sklearn # Added MLflow scikit-learn integration

# Assuming src is in PYTHONPATH or script is run from project root
# Adjust imports based on your project structure and how this script will be invoked
# from src.utils.logging_config import setup_logging # Example
# from src.ai_monitoring.model_registry_client import ModelRegistryClient # Example for saving
# from src.storage.data_loader import load_training_data # Example

# Import the new GMM detector
from src.ai_monitoring.gmm_anomaly_detector import GMMAnomalyDetector
# Import the new VAE detector
from src.ai_monitoring.vae_anomaly_detector import VAEAnomalyDetector

logger = logging.getLogger(__name__)

def load_training_config(config_path: str) -> dict:
    """Loads training configuration from a JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info(f"Successfully loaded training configuration from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Training configuration file not found: {config_path}")
        raise
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from training configuration file: {config_path}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading config: {e}")
        raise

def train_model_pipeline(config_path: str):
    """Main function to orchestrate model training based on a config file."""
    logger.info(f"Starting model training process with config: {config_path}")
    
    config = load_training_config(config_path)

    # Extract configuration parameters
    # Use 'training_data_source' as per the orchestrator-generated config
    data_source_path = config.get("training_data_source") 
    model_output_path = config.get("output_model_path") # For VAE, this will be a prefix
    model_name = config.get("model_name", "default_model_name")
    model_version = config.get("model_version", "0.0.0")
    feature_columns = config.get("feature_columns") # List of column names for features
    isolation_forest_params = config.get("isolation_forest_params", {"n_estimators": 100, "contamination": "auto", "random_state": 42})
    gmm_params = config.get("gmm_params", {"n_components": 3, "covariance_type": "full", "anomaly_threshold_percentile": 5.0})
    vae_params = config.get("vae_params", {
        "latent_dim": 2, 
        "intermediate_dim": 16, 
        "epochs": 50, 
        "batch_size": 32,
        "anomaly_threshold_std_dev": 2.0,
        "random_state": 42
    }) # Added VAE params
    model_type = config.get("model_type", "isolation_forest") # Default to isolation_forest

    # MLflow: Check if running inside an active MLflow run (e.g., started by orchestrator)
    # If so, log parameters and artifacts to that run.
    # The MLFLOW_RUN_ID environment variable can be used to resume a run if set.
    mlflow_run_id = os.environ.get("MLFLOW_RUN_ID")
    active_run_context = mlflow.start_run(run_id=mlflow_run_id, nested=True) if mlflow_run_id else mlflow.start_run(nested=True)

    with active_run_context as run: # Use the context manager for the run
        logger.info(f"MLflow Run ID (train_model.py): {run.info.run_id}")
        # Log configuration parameters to MLflow
        mlflow.log_param("config_path", config_path)
        # Log 'training_data_source' to MLflow, consistent with what is being used
        mlflow.log_param("training_data_source_path", data_source_path) 
        mlflow.log_param("model_output_path_config", model_output_path) # Log the configured path
        mlflow.log_param("model_name", model_name)
        mlflow.log_param("model_version", model_version)
        mlflow.log_param("model_type", model_type)
        mlflow.log_params({"feature_col_" + str(i): col for i, col in enumerate(feature_columns)}) # Log feature columns

        # Check for critical configurations using the correct key 'training_data_source'
        if not data_source_path or not model_output_path or not feature_columns:
            logger.error("Missing critical configuration: training_data_source, output_model_path, or feature_columns must be specified in the config.")
            raise ValueError("Missing critical configuration in training config file.")

        # Ensure output directory exists
        os.makedirs(os.path.dirname(model_output_path), exist_ok=True)

        # Load data
        try:
            logger.info(f"Loading training data from: {data_source_path}")
            # Ensure data_source_path is treated as an absolute path if it's not already.
            # The orchestrator should be writing an absolute path into the run-specific config.
            if not os.path.isabs(data_source_path):
                # This case should ideally not be hit if orchestrator works as expected.
                # For robustness, resolve it relative to project root if it's not absolute.
                project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
                data_source_path = os.path.join(project_root, data_source_path)
                logger.warning(f"data_source_path was not absolute, resolved to: {data_source_path}")

            df = pd.read_csv(data_source_path)
            logger.info(f"Data loaded successfully. Shape: {df.shape}")
        except FileNotFoundError:
            logger.error(f"Training data file not found: {data_source_path}")
            raise
        except Exception as e:
            logger.error(f"Error loading training data: {e}", exc_info=True)
            raise

        # Feature Engineering / Selection
        try:
            logger.info(f"Selecting feature columns: {feature_columns}")
            X_train = df[feature_columns]
            # Basic preprocessing: ensure numeric and handle NaNs (e.g., by filling with mean or median)
            X_train = X_train.apply(pd.to_numeric, errors='coerce') # Convert all to numeric, non-convertibles become NaN
            if X_train.isnull().any().any():
                logger.warning("NaN values found in feature columns. Filling with column means.")
                X_train = X_train.fillna(X_train.mean())
            logger.info(f"Feature engineering/selection complete. Training data shape: {X_train.shape}")
        except KeyError as e:
            logger.error(f"One or more feature columns not found in the dataset: {e}")
            raise
        except Exception as e:
            logger.error(f"Error during feature engineering: {e}", exc_info=True)
            raise

        # Model Training
        try:
            model = None
            if model_type == "isolation_forest":
                logger.info(f"Training IsolationForest model with parameters: {isolation_forest_params}")
                mlflow.log_params({"iso_forest_" + k: v for k, v in isolation_forest_params.items()})
                model = IsolationForest(**isolation_forest_params)
                model.fit(X_train)
            elif model_type == "gmm":
                logger.info(f"Training GMMAnomalyDetector with parameters: {gmm_params}")
                mlflow.log_params({"gmm_" + k: v for k, v in gmm_params.items()})
                # GMMAnomalyDetector handles its own scaler and saves it along with metadata
                # The model_output_path will be for the GMM model itself.
                # Scaler and metadata will be saved relative to this path by the detector.
                detector = GMMAnomalyDetector(
                    n_components=gmm_params.get("n_components", 3),
                    covariance_type=gmm_params.get("covariance_type", "full")
                    # anomaly_threshold_std_dev is used internally by the detector during training/prediction,
                    # not set at __init__ time directly based on current GMMAnomalyDetector structure.
                    # The gmm_params dict from config will still be available if detector.train needs it.
                )
                
                # Pass the full gmm_params to the train method if it needs more than n_components and covariance_type
                # For now, assuming train method will use its defaults or specific args for thresholding.
                # If GMMAnomalyDetector.train() needs anomaly_threshold_std_dev explicitly, it should be passed there.
                # However, GMMAnomalyDetector.train currently doesn't take it as an argument.
                # It's set during predict or when loading a model with metadata.
                # For training, it primarily fits the GMM. The threshold is for prediction.

                scaler_output_path = model_output_path.replace(".joblib", "_scaler.joblib")
                if model_output_path.endswith(".gmm"):
                     scaler_output_path = model_output_path.replace(".gmm", "_scaler.joblib")
                
                training_successful = detector.train(
                    features_df=X_train.copy(), 
                    model_save_path=model_output_path, # e.g., path/to/model.gmm
                    scaler_save_path=scaler_output_path
                    # anomaly_threshold_std_dev is now handled internally by GMMAnomalyDetector
                    # based on its initialization or loaded metadata.
                )
                if not training_successful:
                    raise Exception("GMMAnomalyDetector training failed.")
                model = detector 
                logger.info("GMMAnomalyDetector training complete. Model, scaler, and metadata saved by detector.")
            elif model_type == "vae": # Added VAE training block
                logger.info(f"Training VAEAnomalyDetector with parameters: {vae_params}")
                # Log VAE specific parameters
                mlflow.log_params({"vae_" + k: v for k, v in vae_params.items()})
                mlflow.log_param("vae_input_dim", X_train.shape[1])

                detector = VAEAnomalyDetector(
                    input_dim=X_train.shape[1], # Number of features
                    latent_dim=vae_params.get("latent_dim", 2),
                    intermediate_dim=vae_params.get("intermediate_dim", 16),
                    anomaly_threshold_std_dev=vae_params.get("anomaly_threshold_std_dev", 2.0),
                    random_state=vae_params.get("random_state", 42)
                )
                detector.train(
                    data=X_train.copy(), 
                    epochs=vae_params.get("epochs", 50),
                    batch_size=vae_params.get("batch_size", 32)
                )
                # Determine the correct prefix for saving VAE components
                model_save_prefix = model_output_path
                if model_output_path.endswith(".joblib"):
                    model_save_prefix = model_output_path[:-len(".joblib")]
                
                detector.save(model_save_prefix) 
                model = detector 
                logger.info(f"VAEAnomalyDetector training and saving complete. Model components saved with prefix: {model_save_prefix}")
            else:
                logger.error(f"Unsupported model_type: {model_type}")
                raise ValueError(f"Unsupported model_type: {model_type}")
            
            logger.info("Model training phase complete.")

        except Exception as e:
            logger.error(f"Error during model training: {e}", exc_info=True)
            raise

        # Save Model Artifact (only if not GMM, as GMM saves itself)
        if model_type == "isolation_forest":
            try:
                logger.info(f"Saving trained IsolationForest model to: {model_output_path}")
                joblib.dump(model, model_output_path)
                logger.info(f"IsolationForest model artifact saved successfully as {model_output_path}")
                # Log Isolation Forest model to MLflow
                # The 'registered_model_name' argument is removed from here.
                # Registration will be handled by the 'register_model.py' script.
                mlflow.sklearn.log_model(sk_model=model, artifact_path=model_type) # artifact_path is a directory within the run
                mlflow.log_artifact(model_output_path, artifact_path="trained_model_files") # Log the joblib file as well
            except Exception as e:
                logger.error(f"Error saving IsolationForest model artifact or logging to MLflow: {e}", exc_info=True) # Updated log
                raise
        elif model_type == "gmm":
            # GMMAnomalyDetector already saved its model, scaler, and metadata during its train() call.
            logger.info(f"GMM model, scaler, and metadata were saved by GMMAnomalyDetector. Main model path: {model_output_path}")
            # Log GMM related artifacts (model, scaler, metadata)
            # Assuming model_output_path is for the .gmm file
            if os.path.exists(model_output_path):
                mlflow.log_artifact(model_output_path, artifact_path=f"{model_type}/model_files")
            
            scaler_path_gmm = model_output_path.replace(".gmm", "_scaler.joblib") if model_output_path.endswith(".gmm") else model_output_path.replace(".joblib", "_scaler.joblib")
            metadata_path_gmm = model_output_path.replace(".gmm", "_metadata.json") if model_output_path.endswith(".gmm") else model_output_path.replace(".joblib", "_metadata.json")

            if os.path.exists(scaler_path_gmm):
                mlflow.log_artifact(scaler_path_gmm, artifact_path=f"{model_type}/model_files")
            if os.path.exists(metadata_path_gmm):
                mlflow.log_artifact(metadata_path_gmm, artifact_path=f"{model_type}/model_files")

        elif model_type == "vae":
            # VAEAnomalyDetector already saved its model components (weights, scaler, metadata) during its save() call.
            model_saved_prefix = model_output_path # This was the original path from config
            if model_output_path.endswith(".joblib"): # Adjust if .joblib was in config path
                model_saved_prefix = model_output_path[:-len(".joblib")]
            logger.info(f"VAE model components were saved by VAEAnomalyDetector with prefix: {model_saved_prefix}")
            
            # Log VAE artifacts (model weights, scaler, metadata)
            # These paths are constructed based on VAEAnomalyDetector.save() logic
            vae_model_path = f"{model_saved_prefix}_model.weights.h5"
            vae_scaler_path = f"{model_saved_prefix}_scaler.joblib"
            vae_metadata_path = f"{model_saved_prefix}_metadata.json"

            if os.path.exists(vae_model_path):
                mlflow.log_artifact(vae_model_path, artifact_path=f"{model_type}/model_files")
            if os.path.exists(vae_scaler_path):
                mlflow.log_artifact(vae_scaler_path, artifact_path=f"{model_type}/model_files")
            if os.path.exists(vae_metadata_path):
                mlflow.log_artifact(vae_metadata_path, artifact_path=f"{model_type}/model_files")

        # For simplicity, evaluation and registration are handled by separate scripts in the pipeline.
        # This script focuses solely on training and saving the model artifact.
        
        logger.info(f"Model training process for {model_name} v{model_version} finished successfully.")
        logger.info(f"Trained model artifact: {model_output_path}")

if __name__ == "__main__":
    # Basic logging setup for the script
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(description="Train ML models for network analysis.")
    parser.add_argument("--config", type=str, required=True, help="Path to the training configuration file.")
    # Add other arguments as needed (e.g., data paths, model output paths)
    
    args = parser.parse_args()
    
    # Example: Ensure project root is in path if running script directly for imports
    # current_dir = os.path.dirname(os.path.abspath(__file__))
    # project_root = os.path.abspath(os.path.join(current_dir, "..", "..")) # Adjust based on script location
    # if project_root not in sys.path:
    #     sys.path.insert(0, project_root)

    train_model_pipeline(args.config) # Renamed main function call
