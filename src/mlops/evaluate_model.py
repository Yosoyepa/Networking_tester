"""
Script for evaluating ML models.

This script would typically:
1. Load a trained model artifact.
2. Load an evaluation dataset.
3. Perform inference using the model on the dataset.
4. Calculate and report performance metrics.
"""
import logging
import argparse
import os
import sys
import json
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
from typing import Optional
from sklearn.preprocessing import StandardScaler 
import mlflow # Added MLflow

# Ensure src directory is in path for module imports if running as script
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), \'..\', \'..\'))) # Example, might not be needed

from src.ai_monitoring.gmm_anomaly_detector import GMMAnomalyDetector # Added
from src.ai_monitoring.vae_anomaly_detector import VAEAnomalyDetector # Added for VAE

logger = logging.getLogger(__name__)

def load_config(config_path: str) -> dict:
    """Loads the configuration file."""
    with open(config_path, 'r') as f:
        return json.load(f)

def evaluate_model(config_path: str, model_type: str, evaluation_data_override: Optional[str] = None):
    """
    Evaluates the trained model based on its type.
    Args:
        config_path: Path to the main MLOps training configuration file.
        model_type: The type of model being evaluated (e.g., 'gmm', 'isolation_forest').
        evaluation_data_override: Optional path to an evaluation dataset to use instead of the one in config.
    """
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", f"Config load error: {e}")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        # Optionally, create an error metrics file
        error_metrics_path = config.get("output_metrics_path", "metrics.json") # Fallback if config not loaded
        if not os.path.exists(os.path.dirname(error_metrics_path)):
             os.makedirs(os.path.dirname(error_metrics_path), exist_ok=True)
        with open(error_metrics_path, 'w') as f:
            json.dump({"error": f"Config load error: {e}", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}, f, indent=4)
        return

    model_artifacts_dir = config["output_model_path"] # This is a directory
    
    # Use override if provided, otherwise use path from config
    if evaluation_data_override:
        evaluation_data_path = evaluation_data_override
        logger.info(f"Using overridden evaluation data path: {evaluation_data_path}")
    elif "evaluation_data_source" in config: # Corrected key from evaluation_data_path
        evaluation_data_path = config["evaluation_data_source"]
    else:
        logger.error("No evaluation_data_source specified in config and no override provided.")
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", "No evaluation data source specified") # Corrected message
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        # Handle error: create an error metrics file
        output_metrics_path_error = config.get("output_metrics_path", "metrics.json") # Default name if not in config
        error_metrics_dir = os.path.dirname(output_metrics_path_error)
        if error_metrics_dir and not os.path.exists(error_metrics_dir):
             os.makedirs(error_metrics_dir, exist_ok=True)
        with open(output_metrics_path_error, 'w') as f:
            json.dump({"error": "No evaluation data source specified", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}, f, indent=4) # Corrected message
        return

    output_metrics_path = config["output_metrics_path"]

    if not os.path.exists(os.path.dirname(output_metrics_path)):
        os.makedirs(os.path.dirname(output_metrics_path), exist_ok=True)

    logger.info(f"Starting model evaluation for model_type: {model_type}")
    logger.info(f"Loading evaluation data from {evaluation_data_path}")
    try:
        eval_df = pd.read_csv(evaluation_data_path)
    except Exception as e:
        logger.error(f"Failed to load evaluation data from {evaluation_data_path}: {e}")
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", f"Evaluation data load error: {e}")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        with open(output_metrics_path, 'w') as f:
            json.dump({"error": f"Evaluation data load error: {e}", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}, f, indent=4)
        return

    if eval_df.empty:
        logger.warning("Evaluation data is empty. Skipping evaluation.")
        metrics = {"accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0, "notes": "No data to evaluate."}
        # MLflow: Log note and zero metrics if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_notes", "No data to evaluate.")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        with open(output_metrics_path, 'w') as f:
            json.dump(metrics, f, indent=4)
        logger.info(f"Saved empty metrics to {output_metrics_path}")
        return

    if 'is_anomaly' not in eval_df.columns:
        logger.error("'is_anomaly' column not found in evaluation data. Cannot evaluate.")
        error_metrics = {"error": "'is_anomaly' column missing", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", "'is_anomaly' column missing")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        with open(output_metrics_path, 'w') as f:
            json.dump(error_metrics, f, indent=4)
        return
    
    y_true = eval_df['is_anomaly'].copy()
    # Ensure y_true is 0 (normal) / 1 (anomaly)
    if y_true.dtype == bool:
        y_true = y_true.astype(int)
    elif set(y_true.unique()) == {-1, 1}: # If it's -1 for anomaly, 1 for normal
        logger.info("Mapping y_true from (-1 anomaly, 1 normal) to (1 anomaly, 0 normal)")
        y_true = y_true.map({-1: 1, 1: 0}) 
    # Assuming 0 for normal, 1 for anomaly is the target for y_true.
    # If it's something else, further mapping might be needed.
    
    # Prepare features (X_eval) by dropping ground truth and potential identifiers
    # This list of non-feature columns might need to be configurable or more robustly determined
    non_feature_cols = ['is_anomaly', 'timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_id', 'flow_id']
    feature_cols_to_drop = [col for col in non_feature_cols if col in eval_df.columns]
    X_eval = eval_df.drop(columns=feature_cols_to_drop)

    if X_eval.empty or X_eval.shape[1] == 0:
        logger.error("No feature columns found in evaluation data after dropping non-feature columns.")
        error_metrics = {"error": "No feature columns in evaluation data", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", "No feature columns in evaluation data")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})
        with open(output_metrics_path, 'w') as f:
            json.dump(error_metrics, f, indent=4)
        return

    predictions_raw = None
    
    try:
        # MLflow: Check if running inside an active MLflow run (e.g., started by orchestrator)
        mlflow_run_id = os.environ.get("MLFLOW_RUN_ID")
        active_run_context = mlflow.start_run(run_id=mlflow_run_id, nested=True) if mlflow_run_id else mlflow.start_run(nested=True)
        
        with active_run_context as run: # Use the context manager for the run
            logger.info(f"MLflow Run ID (evaluate_model.py): {run.info.run_id}")
            mlflow.log_param("evaluation_config_path", config_path)
            mlflow.log_param("evaluation_model_type", model_type)
            mlflow.log_param("evaluation_data_path_used", evaluation_data_path)
            mlflow.log_param("evaluation_output_metrics_path", output_metrics_path)

            if model_type == "gmm":
                logger.info(f"Loading GMM model and artifacts.")
                # config["output_model_path"] is the full path to the .gmm model file
                model_file_path_from_config = config["output_model_path"] 
                
                # The GMMAnomalyDetector.load method will derive scaler and metadata paths
                # based on the model_file_path_from_config.

                logger.info(f"Attempting to load GMM model using base path: {model_file_path_from_config}")

                if not os.path.exists(model_file_path_from_config):
                    raise FileNotFoundError(f"GMM model file not found: {model_file_path_from_config}")
                
                # GMMAnomalyDetector.load now only needs the model_path, it infers others.
                gmm_detector = GMMAnomalyDetector.load(model_path=model_file_path_from_config)
                if not gmm_detector:
                    raise RuntimeError(f"Failed to load GMMAnomalyDetector with model path: {model_file_path_from_config}")
                
                logger.info(f"GMM model expects features: {gmm_detector.trained_features}")
                
                is_anomaly_list, scores = gmm_detector.predict(X_eval)
                predictions_raw = np.array([1 if p else 0 for p in is_anomaly_list]) 

                logger.info(f"GMM Predictions (0 normal, 1 anomaly): {np.unique(predictions_raw, return_counts=True)}")
                logger.info(f"GMM Scores (log-likelihoods) sample (first 5): {scores[:5]}")

            elif model_type == "vae":
                logger.info(f"Loading VAE model and artifacts.")
                # config["output_model_path"] is the prefix used during training for VAE
                model_save_prefix_from_config = config["output_model_path"] # Use a different variable name
            
                # Construct paths based on the prefix
                # Corrected weights path to match how VAEAnomalyDetector saves it
                weights_path = f"{model_save_prefix_from_config}.weights.h5" 
                scaler_path = f"{model_save_prefix_from_config}_scaler.joblib"
                # Corrected metadata path to match how VAEAnomalyDetector saves it
                # VAEAnomalyDetector saves metadata as .json, not .joblib
                metadata_path = f"{model_save_prefix_from_config}_metadata.json"

                logger.info(f"Attempting to load VAE model components from prefix: {model_save_prefix_from_config}")
                logger.info(f"  Weights: {weights_path}")
                logger.info(f"  Scaler: {scaler_path}")
                logger.info(f"  Metadata: {metadata_path}")

                if not os.path.exists(weights_path) or \
                   not os.path.exists(scaler_path) or \
                   not os.path.exists(metadata_path):
                    raise FileNotFoundError(f"One or more VAE artifact files not found for prefix {model_save_prefix_from_config}. Searched for weights ({weights_path}), scaler ({scaler_path}), and metadata ({metadata_path}).")

                # Corrected parameter name to model_path_prefix
                vae_detector = VAEAnomalyDetector.load(model_path_prefix=model_save_prefix_from_config)
                if not vae_detector:
                    raise RuntimeError(f"Failed to load VAEAnomalyDetector with prefix: {model_save_prefix_from_config}")
            
                # Corrected attribute name to vae_detector.trained_features
                logger.info(f"VAE model expects features: {vae_detector.trained_features}") 
                
                # Ensure X_eval has the same columns as during training, in the same order
                # Corrected attribute name to vae_detector.trained_features
                if vae_detector.trained_features is not None:
                    if not set(vae_detector.trained_features).issubset(set(X_eval.columns)):
                        missing_features = list(set(vae_detector.trained_features) - set(X_eval.columns))
                        raise ValueError(f"Evaluation data is missing required features for VAE: {missing_features}")
                    # Corrected attribute name to vae_detector.trained_features
                    if list(X_eval.columns) != vae_detector.trained_features: 
                        logger.info("Reordering X_eval columns to match VAE trained feature order.")
                        # Corrected attribute name to vae_detector.trained_features
                        X_eval = X_eval[vae_detector.trained_features]

                is_anomaly_list, reconstruction_errors = vae_detector.predict(X_eval.copy()) # Use .copy() if predict modifies data
                predictions_raw = np.array([1 if p else 0 for p in is_anomaly_list]) 

                logger.info(f"VAE Predictions (0 normal, 1 anomaly): {np.unique(predictions_raw, return_counts=True)}")
                logger.info(f"VAE Reconstruction Errors sample (first 5): {reconstruction_errors[:5] if reconstruction_errors is not None and len(reconstruction_errors) > 0 else 'N/A'}")
                # Corrected attribute name to vae_detector.reconstruction_threshold
                logger.info(f"VAE Anomaly Threshold used: {vae_detector.reconstruction_threshold}")


            elif model_type == "isolation_forest":
                logger.info(f"Loading Isolation Forest model and artifacts from directory: {model_artifacts_dir}")
                model_file = os.path.join(model_artifacts_dir, "model.iforest")
                scaler_file = os.path.join(model_artifacts_dir, "model.scaler")
                features_file = os.path.join(model_artifacts_dir, "model.features")

                if not all(os.path.exists(f) for f in [model_file, scaler_file, features_file]):
                    raise FileNotFoundError(f"One or more artifact files not found in {model_artifacts_dir} for Isolation Forest.")

                model = joblib.load(model_file)
                scaler = joblib.load(scaler_file)
                with open(features_file, 'r') as f:
                    trained_features = json.load(f)
                
                logger.info(f"Isolation Forest model expects features: {trained_features}")
                if not set(trained_features).issubset(set(X_eval.columns)):
                    missing_features = list(set(trained_features) - set(X_eval.columns))
                    raise ValueError(f"Evaluation data is missing required features for Isolation Forest: {missing_features}")

                X_eval_selected = X_eval[trained_features]
                X_eval_scaled = scaler.transform(X_eval_selected)
                predictions_raw = model.predict(X_eval_scaled) # -1 for anomalies, 1 for normal
                logger.info(f"Isolation Forest Predictions (raw): {np.unique(predictions_raw, return_counts=True)}")
            else:
                logger.error(f"Unsupported model_type: {model_type}")
                error_metrics = {"error": f"Unsupported model_type: {model_type}", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
                with open(output_metrics_path, 'w') as f:
                    json.dump(error_metrics, f, indent=4)
                return
                
    except Exception as e:
        logger.error(f"Error during model loading or prediction for {model_type}: {e}")
        # MLflow: Log error if run is active
        if mlflow.active_run():
            mlflow.log_param("evaluation_error", f"Model error ({model_type}): {str(e)}")
            mlflow.log_metrics({"accuracy": 0, "precision_anomaly": 0, "recall_anomaly": 0, "f1_score_anomaly": 0})

        error_metrics = {"error": f"Model error ({model_type}): {str(e)}", "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
        with open(output_metrics_path, 'w') as f:
            json.dump(error_metrics, f, indent=4)
        return

    # Map predictions: model's -1 (anomaly) to 1, 1 (normal) to 0.
    # This assumes y_true is 0 for normal, 1 for anomaly.
    # For GMM, predictions_raw is already 0 for normal, 1 for anomaly.
    if model_type == "isolation_forest":
        y_pred = np.where(predictions_raw == -1, 1, 0)
    elif model_type == "gmm":
        y_pred = predictions_raw # Already in 0/1 format
    elif model_type == "vae":
        y_pred = predictions_raw # Already in 0/1 format
    else:
        # Should have been caught earlier, but as a safeguard:
        logger.error(f"Cannot determine y_pred mapping for unknown model_type: {model_type}")
        # Create a dummy y_pred to avoid crashing, error metrics will reflect the problem
        y_pred = np.zeros_like(y_true)


    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    # For precision, recall, f1_score, explicitly set pos_label=1 (anomaly)
    # and specify zero_division=0 to handle cases where a class is not predicted.
    precision_anomaly = precision_score(y_true, y_pred, pos_label=1, average='binary', zero_division=0)
    recall_anomaly = recall_score(y_true, y_pred, pos_label=1, average='binary', zero_division=0)
    f1_anomaly = f1_score(y_true, y_pred, pos_label=1, average='binary', zero_division=0)
    
    # Calculate macro and weighted averages for overall performance
    f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
    recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)


    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision (Anomaly/1): {precision_anomaly:.4f}")
    logger.info(f"Recall (Anomaly/1): {recall_anomaly:.4f}")
    logger.info(f"F1-score (Anomaly/1): {f1_anomaly:.4f}")
    logger.info(f"F1-score (Macro Avg): {f1_macro:.4f}")

    report = classification_report(y_true, y_pred, target_names=['Normal (0)', 'Anomaly (1)'], output_dict=True, zero_division=0)
    logger.info(f"Classification Report:\\n{classification_report(y_true, y_pred, target_names=['Normal (0)', 'Anomaly (1)'], zero_division=0)}")

    metrics = {
        "accuracy": accuracy,
        "precision_anomaly": precision_anomaly, # Specific to class 1
        "recall_anomaly": recall_anomaly,     # Specific to class 1
        "f1_score_anomaly": f1_anomaly,       # Specific to class 1 (this is what was logged before)
        "f1_score": f1_macro, # General F1-score (macro) for promotion check
        "f1_score_macro": f1_macro,
        "f1_score_weighted": f1_weighted,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist() # Convert to list for JSON
    }

    # MLflow logging
    mlflow.log_metric("accuracy", accuracy)
    mlflow.log_metric("precision_anomaly", precision_anomaly)
    mlflow.log_metric("recall_anomaly", recall_anomaly)
    mlflow.log_metric("f1_score_anomaly", f1_anomaly)
    mlflow.log_metric("f1_score", f1_macro) # Log the general f1_score
    mlflow.log_metric("f1_score_macro", f1_macro)
    mlflow.log_metric("f1_score_weighted", f1_weighted)
    mlflow.log_metric("precision_macro", precision_macro)
    mlflow.log_metric("recall_macro", recall_macro)
    
    # Log the classification report as a JSON artifact
    # Convert report to a string for logging as text or save as json artifact
    report_json_path = os.path.join(os.path.dirname(output_metrics_path), "classification_report.json")
    with open(report_json_path, 'w') as f:
        json.dump(report, f, indent=4)
    mlflow.log_artifact(report_json_path, artifact_path="evaluation_results")
    
    # Log confusion matrix as an image or csv if desired, here just saving to metrics.json
    # For example, to log as an artifact:
    cm_df = pd.DataFrame(metrics["confusion_matrix"], index=['Actual Normal', 'Actual Anomaly'], columns=['Predicted Normal', 'Predicted Anomaly'])
    cm_csv_path = os.path.join(os.path.dirname(output_metrics_path), "confusion_matrix.csv")
    cm_df.to_csv(cm_csv_path)
    mlflow.log_artifact(cm_csv_path, artifact_path="evaluation_results")


    with open(output_metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    logger.info(f"Saved metrics to {output_metrics_path}")
    mlflow.log_artifact(output_metrics_path, artifact_path="evaluation_results") # Log the main metrics file

    # Log parameters related to evaluation if not already done
    mlflow.log_param("evaluation_target_label_meaning", "0: Normal, 1: Anomaly")
    mlflow.log_param("evaluation_positive_class_for_f1", "1 (Anomaly)")
    
    # Set a run name tag for easier identification in MLflow UI
    mlflow.set_tag("mlflow.runName", f"evaluate_{model_type}_{run.info.run_id[:8]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate a trained machine learning model.")
    parser.add_argument("--config", type=str, required=True, help="Path to the MLOps training configuration JSON file.")
    parser.add_argument("--model_type", type=str, required=True, help="Type of the model to evaluate (e.g., gmm, isolation_forest).")
    parser.add_argument("--evaluation_data_override", type=str, required=False, default=None, help="Optional path to override the evaluation dataset specified in the config.")

    args = parser.parse_args()

    # Basic logging setup
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    logger.info(f"Starting evaluation script with config: {args.config}, model_type: {args.model_type}, override: {args.evaluation_data_override}")
    evaluate_model(args.config, args.model_type, args.evaluation_data_override)
