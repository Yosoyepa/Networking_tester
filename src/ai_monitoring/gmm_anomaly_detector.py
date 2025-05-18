from __future__ import annotations # Ensure this is the very first line

import logging
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List, Optional, Tuple, TYPE_CHECKING
import datetime

if TYPE_CHECKING:
    from src.messaging.schemas import MLResult
    # If setup_logging also needs to be conditionally imported for type checking:
    # from src.utils.logger_config import setup_logging 

# Runtime imports and fallbacks
try:
    from src.messaging.schemas import MLResult as ActualMLResult
    from src.utils.logger_config import setup_logging
except ImportError:
    print("Warning: Could not import 'src.messaging.schemas.MLResult' or 'src.utils.logger_config.setup_logging'. Using fallback type for MLResult.")
    # Define MLResult for runtime if import fails and it wasn't defined by TYPE_CHECKING for the linter
    # The type hints will use 'MLResult' as a string if TYPE_CHECKING is False and this path is taken.
    # However, with `from __future__ import annotations`, string literals are default.
    # To make it concrete for runtime when import fails:
    if 'ActualMLResult' not in globals(): # Check if the alias we tried to import exists
        ActualMLResult = Dict[str, Any] # This becomes the runtime MLResult
    
    # Fallback for setup_logging
    if 'setup_logging' not in globals():
        def setup_logging(level=logging.INFO):
            logging.basicConfig(level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

class GMMAnomalyDetector:
    """
    Anomaly detector using Gaussian Mixture Models (GMM).
    Assumes that normal data can be modeled by a mixture of Gaussian distributions.
    Anomalies are data points that have a low probability density under the fitted GMM.
    """
    def __init__(self, model_path: Optional[str] = None, scaler_path: Optional[str] = None,
                 n_components: int = 3, covariance_type: str = 'full',
                 anomaly_threshold_std_dev: float = 2.5):
        """
        Initializes the GMMAnomalyDetector.

        Args:
            model_path (Optional[str]): Path to load a pre-trained GMM model.
            scaler_path (Optional[str]): Path to load a pre-trained StandardScaler.
            n_components (int): Number of mixture components for the GMM.
                                This might be overridden if a model is loaded.
            covariance_type (str): Covariance type for GMM ('full', 'tied', 'diag', 'spherical').
                                   This might be overridden if a model is loaded.
            anomaly_threshold_std_dev (float): Number of standard deviations below the mean
                                               log-likelihood to set the anomaly threshold.
        """
        self.model: Optional[GaussianMixture] = None
        self.scaler: Optional[StandardScaler] = None
        self.model_loaded: bool = False
        self.trained_features: List[str] = []

        self.n_components = n_components
        self.covariance_type = covariance_type
        # Store anomaly_threshold_std_dev from init
        self.anomaly_threshold_std_dev = anomaly_threshold_std_dev
        self.log_likelihood_threshold: Optional[float] = None

        if model_path and scaler_path and os.path.exists(model_path) and os.path.exists(scaler_path):
            self.load_model(model_path, scaler_path)
        elif model_path or scaler_path:
            logger.warning(
                f"GMMAnomalyDetector: Both model_path ('{model_path}') and scaler_path ('{scaler_path}') "
                "must exist to load. Model will need training."
            )

    def _preprocess_data(self, features_df: pd.DataFrame, fit_scaler: bool = False) -> Optional[pd.DataFrame]:
        """
        Preprocesses the input DataFrame: handles NaNs, scales data.
        Ensures columns are in the same order as during training for prediction.

        Args:
            features_df (pd.DataFrame): DataFrame with features.
            fit_scaler (bool): If True, fits the scaler. Otherwise, transforms using existing scaler.

        Returns:
            Optional[pd.DataFrame]: Processed DataFrame or None if error.
        """
        if features_df.empty:
            logger.warning("Input DataFrame is empty for preprocessing.")
            return pd.DataFrame() # Return empty DF to avoid downstream errors with None

        # Handle potential all-NaN columns by dropping them
        df = features_df.dropna(axis=1, how='all').copy() # Use .copy() to avoid SettingWithCopyWarning
        # Fill remaining NaNs with 0 (or a more sophisticated strategy if needed)
        df.fillna(0, inplace=True)

        if fit_scaler:
            # Select only numeric columns for fitting the scaler
            numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
            if not numeric_cols:
                logger.error("No numeric columns found in the DataFrame to fit scaler.")
                return None
            self.scaler = StandardScaler()
            df_scaled_values = self.scaler.fit_transform(df[numeric_cols])
            self.trained_features = numeric_cols # Store feature names and order from numeric columns
            logger.info(f"Scaler fitted. Trained features (numeric): {self.trained_features}")
            df_processed = pd.DataFrame(df_scaled_values, index=df.index, columns=numeric_cols)
        else: # Predicting
            if not self.scaler:
                logger.error("Scaler not fitted or loaded. Cannot transform data for prediction.")
                return None
            if not self.trained_features:
                logger.error("Trained features not set. Cannot ensure column order for scaling during prediction.")
                return None

            # Ensure columns are in the same order as during training
            # Add missing columns (that were in training) with 0, and reorder
            current_numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
            
            # Create a DataFrame with the expected feature set, initialized to 0
            df_aligned = pd.DataFrame(0, index=df.index, columns=self.trained_features)

            # Populate with values from the input df for common columns
            common_cols = [col for col in self.trained_features if col in current_numeric_cols]
            for col in common_cols:
                df_aligned[col] = df[col]
            
            if not common_cols:
                logger.warning("No common numeric features between input data and trained features. Prediction might be unreliable.")
                # Still proceed with scaling on the df_aligned (which will be mostly zeros if no common cols)
                # This ensures the shape is correct for the model.

            try:
                df_scaled_values = self.scaler.transform(df_aligned[self.trained_features]) # Scale using all trained features
            except ValueError as e:
                logger.error(f"Error transforming data with scaler: {e}. "
                             f"Input columns for transform: {df_aligned[self.trained_features].columns.tolist()}, "
                             f"Scaler features: {self.scaler.feature_names_in_ if hasattr(self.scaler, 'feature_names_in_') else 'N/A'}")
                return None
            df_processed = pd.DataFrame(df_scaled_values, index=df_aligned.index, columns=self.trained_features)
            
        return df_processed

    def train(self, features_df: pd.DataFrame,
              model_save_path: Optional[str] = None,
              scaler_save_path: Optional[str] = None) -> bool:
        """
        Trains the GMM model and the scaler.

        Args:
            features_df (pd.DataFrame): DataFrame of NORMAL traffic features.
            model_save_path (Optional[str]): Path to save the trained GMM model.
            scaler_save_path (Optional[str]): Path to save the trained StandardScaler.

        Returns:
            bool: True if training was successful, False otherwise.
        """
        logger.info(f"Starting GMM training with n_components={self.n_components}, covariance_type='{self.covariance_type}'.")
        processed_df = self._preprocess_data(features_df, fit_scaler=True)

        if processed_df is None or processed_df.empty:
            logger.error("Data preprocessing failed or resulted in empty DataFrame. Cannot train GMM.")
            return False

        self.model = GaussianMixture(n_components=self.n_components,
                                     covariance_type=self.covariance_type,
                                     random_state=42,
                                     warm_start=False)
        try:
            self.model.fit(processed_df)
            self.model_loaded = True
            logger.info("GMM model training completed.")

            log_likelihoods_train = self.model.score_samples(processed_df)
            
            mean_log_likelihood = np.mean(log_likelihoods_train)
            std_log_likelihood = np.std(log_likelihoods_train)
            # Use self.anomaly_threshold_std_dev (set in __init__)
            self.log_likelihood_threshold = mean_log_likelihood - (self.anomaly_threshold_std_dev * std_log_likelihood)
            
            logger.info(f"Anomaly log-likelihood threshold set to: {self.log_likelihood_threshold:.4f} "
                        f"(based on mean - {self.anomaly_threshold_std_dev} * std_dev of training data scores).")
            logger.info(f"Mean log-likelihood: {mean_log_likelihood:.4f}, Std dev: {std_log_likelihood:.4f}")

        except Exception as e:
            logger.error(f"Error during GMM model fitting: {e}", exc_info=True)
            self.model = None
            self.model_loaded = False
            return False

        if model_save_path and self.model:
            self._save_joblib(self.model, model_save_path, "GMM model")
            metadata = {
                'n_components': self.model.n_components,
                'covariance_type': self.model.covariance_type,
                'trained_features': self.trained_features,
                'log_likelihood_threshold': self.log_likelihood_threshold,
                'anomaly_threshold_std_dev': self.anomaly_threshold_std_dev
            }
            self._save_joblib(metadata, model_save_path.replace(".joblib", "_metadata.joblib").replace(".gmm", "_metadata.joblib"), "GMM metadata")

        if scaler_save_path and self.scaler:
            self._save_joblib(self.scaler, scaler_save_path, "Scaler")

        return True

    def predict(self, features_df: pd.DataFrame) -> Tuple[List[bool], List[float]]:
        """
        Predicts anomalies for new data.

        Returns:
            Tuple[List[bool], List[float]]: (is_anomaly_list, anomaly_scores_list)
        """
        if not self.model_loaded or not self.scaler or self.log_likelihood_threshold is None:
            logger.error("Model not loaded, scaler not available, or threshold not set. Cannot make predictions.")
            # Return empty lists or lists of False/0.0 for each input row
            # Length of features_df rows
            num_rows = len(features_df)
            return [False] * num_rows, [0.0] * num_rows


        processed_df = self._preprocess_data(features_df, fit_scaler=False)
        if processed_df is None or processed_df.empty:
            logger.warning("Preprocessing resulted in no data for prediction. Returning False for all inputs.")
            num_rows = len(features_df) if features_df is not None else 0
            return [False] * num_rows, [0.0] * num_rows

        if processed_df.shape[1] != len(self.trained_features):
             logger.error(f"Mismatch in number of features for prediction. Expected {len(self.trained_features)}, got {processed_df.shape[1]}.")
             num_rows = len(processed_df)
             return [False] * num_rows, [0.0] * num_rows
        
        log_likelihoods = self.model.score_samples(processed_df)
        
        # Anomalies are those with log-likelihood below the threshold
        anomalies = log_likelihoods < self.log_likelihood_threshold
        return anomalies.tolist(), log_likelihoods.tolist()

    def load_model(self, model_path: str, scaler_path: str) -> bool:
        """Loads a GMM model, its scaler, and metadata from specified paths."""
        logger.info(f"Loading GMM model from {model_path} and scaler from {scaler_path}.")
        loaded_model = self._load_joblib(model_path, "GMM model")
        loaded_scaler = self._load_joblib(scaler_path, "Scaler")
        
        metadata_path = model_path.replace(".joblib", "_metadata.joblib").replace(".gmm", "_metadata.joblib")
        metadata = self._load_joblib(metadata_path, "GMM metadata")

        if loaded_model is not None and loaded_scaler is not None and metadata is not None:
            self.model = loaded_model
            self.scaler = loaded_scaler
            
            self.n_components = metadata.get('n_components', self.n_components)
            self.covariance_type = metadata.get('covariance_type', self.covariance_type)
            self.trained_features = metadata.get('trained_features', [])
            self.log_likelihood_threshold = metadata.get('log_likelihood_threshold')
            self.anomaly_threshold_std_dev = metadata.get('anomaly_threshold_std_dev', self.anomaly_threshold_std_dev)

            if not self.trained_features:
                logger.warning("Loaded model metadata does not contain 'trained_features'.")
            if self.log_likelihood_threshold is None:
                logger.warning("Loaded model metadata does not contain 'log_likelihood_threshold'.")
            else:
                logger.info(f"Restored log_likelihood_threshold: {self.log_likelihood_threshold}")
            logger.info(f"Restored anomaly_threshold_std_dev: {self.anomaly_threshold_std_dev}")

            self.model_loaded = True
            logger.info(f"GMM model, scaler, and metadata loaded successfully. Trained features: {self.trained_features}")
            return True
        else:
            logger.error("Failed to load GMM model, scaler, or metadata.")
            self.model_loaded = False
            return False

    def _save_joblib(self, obj: Any, path: str, description: str):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            joblib.dump(obj, path)
            logger.info(f"{description} saved to {path}")
        except Exception as e:
            logger.error(f"Error saving {description} to {path}: {e}", exc_info=True)

    def _load_joblib(self, path: str, description: str) -> Optional[Any]:
        try:
            obj = joblib.load(path)
            logger.info(f"{description} loaded from {path}")
            return obj
        except FileNotFoundError:
            logger.warning(f"{description} file not found at {path}.")
            return None
        except Exception as e:
            logger.error(f"Error loading {description} from {path}: {e}", exc_info=True)
            return None

    @classmethod
    def load(cls, model_path: str) -> Optional[GMMAnomalyDetector]:
        """
        Loads a GMM model, its scaler, and metadata from a base model path.
        The scaler and metadata paths are inferred from the model_path.

        Args:
            model_path (str): Path to the saved GMM model file (e.g., *.gmm or *.joblib).

        Returns:
            Optional[GMMAnomalyDetector]: An instance of GMMAnomalyDetector with loaded components, or None if loading fails.
        """
        logger.info(f"Attempting to load GMMAnomalyDetector from base model path: {model_path}")
        
        # Infer scaler and metadata paths
        base_path_no_ext, _ = os.path.splitext(model_path)
        scaler_path = f"{base_path_no_ext}_scaler.joblib"
        metadata_path = f"{base_path_no_ext}_metadata.joblib"

        if not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            return None
        if not os.path.exists(scaler_path):
            logger.error(f"Scaler file not found: {scaler_path}")
            return None
        if not os.path.exists(metadata_path):
            logger.error(f"Metadata file not found: {metadata_path}")
            return None

        # Create an instance of the class first
        # We need to provide default or dummy values for __init__ params that are usually set by metadata
        # These will be overwritten by loaded metadata shortly.
        detector = cls(n_components=1, covariance_type='full', anomaly_threshold_std_dev=0.0) 

        loaded_model_obj = detector._load_joblib(model_path, "GMM model")
        loaded_scaler_obj = detector._load_joblib(scaler_path, "Scaler")
        metadata = detector._load_joblib(metadata_path, "GMM metadata")

        if loaded_model_obj is not None and loaded_scaler_obj is not None and metadata is not None:
            detector.model = loaded_model_obj
            detector.scaler = loaded_scaler_obj
            
            detector.n_components = metadata.get('n_components', detector.n_components)
            detector.covariance_type = metadata.get('covariance_type', detector.covariance_type)
            detector.trained_features = metadata.get('trained_features', [])
            detector.log_likelihood_threshold = metadata.get('log_likelihood_threshold')
            detector.anomaly_threshold_std_dev = metadata.get('anomaly_threshold_std_dev', detector.anomaly_threshold_std_dev)

            if not detector.trained_features:
                logger.warning("Loaded model metadata does not contain 'trained_features'.")
            if detector.log_likelihood_threshold is None:
                logger.warning("Loaded model metadata does not contain 'log_likelihood_threshold'.")
            else:
                logger.info(f"Restored log_likelihood_threshold: {detector.log_likelihood_threshold}")
            logger.info(f"Restored anomaly_threshold_std_dev: {detector.anomaly_threshold_std_dev}")

            detector.model_loaded = True
            logger.info(f"GMM model, scaler, and metadata loaded successfully into new instance. Trained features: {detector.trained_features}")
            return detector
        else:
            logger.error("Failed to load one or more GMM components (model, scaler, or metadata).")
            return None

    # Type hints use 'MLResult' which is resolved by `from __future__ import annotations`
    # to refer to the MLResult defined in `if TYPE_CHECKING:` or the runtime ActualMLResult.
    def predict_and_create_results(self, packet_feature_list: List[Dict[str, Any]], model_id: str) -> List[MLResult]:
        """
        Predicts anomalies for a list of packet features and formats them as MLResult objects.
        MLResult is now globally defined (either imported or as fallback Dict[str, Any]).
        """
        if not self.model_loaded or not self.scaler:
            logger.error("Model or scaler not loaded. Cannot make predictions.")
            return [] 

        if not packet_feature_list:
            logger.info("Empty list of packet features received for prediction.")
            return []

        features_df = pd.DataFrame(packet_feature_list)
        processed_df = self._preprocess_data(features_df.copy(), fit_scaler=False)

        if processed_df is None or processed_df.empty:
            logger.warning("Preprocessing resulted in no data for prediction. Returning empty results.")
            return []

        is_anomaly_list, anomaly_scores = self.predict(processed_df)
        
        ml_results: List[MLResult] = [] # Use global MLResult
        original_features_list = features_df.to_dict(orient='records')

        for i in range(len(original_features_list)):
            if i < len(is_anomaly_list) and i < len(anomaly_scores):
                is_anomaly = is_anomaly_list[i]
                score = anomaly_scores[i]
                packet_features = original_features_list[i]
            else:
                logger.warning(f"Mismatch in prediction output length for packet index {i}. Original: {len(original_features_list)}, Predicted: {len(is_anomaly_list)}. Skipping.")
                continue
            
            result: MLResult = { # Use global MLResult
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "model_id": model_id,
                "algorithm": "gmm",
                "features": packet_features,
                "prediction": {"is_anomaly": bool(is_anomaly)},
                "confidence_score": float(score),
                "threshold": self.log_likelihood_threshold,
                "metadata": {
                    "n_components": self.n_components,
                    "covariance_type": self.covariance_type,
                    "anomaly_threshold_std_dev": self.anomaly_threshold_std_dev
                }
            }
            ml_results.append(result)
            
        return ml_results

    def get_metadata(self) -> Dict[str, Any]:
        """Returns metadata about the model."""
        if not self.model_loaded:
            return {
                "status": "Model not loaded or trained.",
                "n_components_configured": self.n_components,
                "covariance_type_configured": self.covariance_type,
                "anomaly_threshold_std_dev_configured": self.anomaly_threshold_std_dev
            }
        
        return {
            "status": "Model loaded.",
            "n_components": self.model.n_components if self.model else self.n_components,
            "covariance_type": self.model.covariance_type if self.model else self.covariance_type,
            "trained_features": self.trained_features,
            "log_likelihood_threshold": self.log_likelihood_threshold,
            "anomaly_threshold_std_dev": self.anomaly_threshold_std_dev,
            "scaler_mean": self.scaler.mean_.tolist() if self.scaler and hasattr(self.scaler, 'mean_') else None,
            "scaler_scale": self.scaler.scale_.tolist() if self.scaler and hasattr(self.scaler, 'scale_') else None,
        }

# Example usage (optional, for testing)
if __name__ == '__main__':
    # Setup logging for standalone execution. 
    # This will use the imported setup_logging or the fallback if the import failed.
    try:
        setup_logging(logging.DEBUG) # Attempt to call the (potentially imported) setup_logging
    except NameError: # If setup_logging itself is not defined (e.g. import failed and fallback also failed)
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logging.getLogger(__name__).info("Using basicConfig for logging due to setup_logging not being available.")

    logger.info("GMMAnomalyDetector script started for standalone testing.")
    
    n_samples = 200
    n_features = 5
    rng = np.random.RandomState(0)
    X_train = pd.DataFrame(rng.randn(n_samples, n_features), columns=[f'feature_{j}' for j in range(n_features)])
    X_test_normal = pd.DataFrame(rng.randn(50, n_features), columns=[f'feature_{j}' for j in range(n_features)])
    X_test_anomalies = pd.DataFrame(rng.rand(10, n_features) * 10 - 5, columns=[f'feature_{j}' for j in range(n_features)])
    X_test = pd.concat([X_test_normal, X_test_anomalies], ignore_index=True)

    # Test with specific paths to avoid cluttering the current directory if not desired
    model_dir = "./test_gmm_artifacts"
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    model_path = os.path.join(model_dir, 'gmm_model.joblib')
    scaler_path = os.path.join(model_dir, 'gmm_scaler.joblib')
    metadata_model_path = model_path.replace(".joblib", "_metadata.joblib") # Path for metadata file

    detector = GMMAnomalyDetector(n_components=2, anomaly_threshold_std_dev=2.0)
    
    logger.info("Training GMM model...")
    train_success = detector.train(X_train, model_save_path=model_path, scaler_save_path=scaler_path)
    if train_success:
        logger.info("Training successful.")
        test_packet_features = X_test.to_dict(orient='records')
        # Ensure MLResult is the correct type for this call based on import success or fallback
        ml_results: List[MLResult] = detector.predict_and_create_results(test_packet_features, model_id="gmm_test_v1")
        anomalies_detected = sum(1 for res in ml_results if res['prediction']['is_anomaly'])
        logger.info(f"Anomalies detected in test set: {anomalies_detected} out of {len(X_test)}")

        logger.info("Testing model loading...")
        detector_loaded = GMMAnomalyDetector.load(model_path)
        if detector_loaded and detector_loaded.model_loaded:
            logger.info("Model loaded successfully.")
            logger.info(f"Loaded model metadata: {detector_loaded.get_metadata()}")
            ml_results_loaded: List[MLResult] = detector_loaded.predict_and_create_results(test_packet_features, model_id="gmm_loaded_test_v1")
            anomalies_detected_loaded = sum(1 for res in ml_results_loaded if res['prediction']['is_anomaly'])
            logger.info(f"Anomalies detected with loaded model: {anomalies_detected_loaded} out of {len(X_test)}")
            if anomalies_detected == anomalies_detected_loaded:
                logger.info("Prediction consistency check passed.")
            else:
                logger.warning("Prediction consistency check FAILED.")
        else:
            logger.error("Failed to load the model.")
    else:
        logger.error("Training failed.")

    # Clean up dummy files and directory
    for f_path in [model_path, scaler_path, metadata_model_path]: # Include metadata file path for cleanup
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
                logger.info(f"Cleaned up {f_path}")
            except OSError as e:
                logger.error(f"Error removing file {f_path}: {e.strerror}")
    if os.path.exists(model_dir):
        try:
            if not os.listdir(model_dir): # Check if directory is empty
                 os.rmdir(model_dir)
                 logger.info(f"Cleaned up directory {model_dir}")
            else:
                logger.info(f"Directory {model_dir} not empty, not removed.") # Or handle removal of non-empty dir if desired
        except OSError as e:
            logger.error(f"Error removing directory {model_dir}: {e.strerror}")
