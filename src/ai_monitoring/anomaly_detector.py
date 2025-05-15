#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para AnomalyDetector dentro de networking_tester."""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib
import os
import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Detects anomalies in network traffic features using a pre-trained model.
    """
    def __init__(self, model_path=None, scaler_path=None):
        self.model = None
        self.scaler = None
        self.model_loaded = False

        if model_path and os.path.exists(model_path):
            self.load_model(model_path, scaler_path)
        else:
            logger.warning(
                f"AnomalyDetector: Model path '{model_path}' not provided or not found. "
                "Anomaly detection will not be performed unless a model is loaded or trained."
            )

    def load_model(self, model_path, scaler_path=None):
        """Carga un modelo previamente entrenado y su scaler."""
        try:
            self.model = joblib.load(model_path)
            logger.info(f"AnomalyDetector model loaded from: {model_path}")

            # Try to load scaler from provided path or default naming convention
            if scaler_path and os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Scaler loaded from: {scaler_path}")
            else:
                default_scaler_path = model_path.replace(".joblib", "_scaler.joblib")
                if os.path.exists(default_scaler_path):
                    self.scaler = joblib.load(default_scaler_path)
                    logger.info(f"Scaler loaded from default path: {default_scaler_path}")
                else:
                    logger.warning("Scaler not found. Preprocessing might be affected if the model expects scaled data.")
            self.model_loaded = True
        except FileNotFoundError:
            logger.error(f"AnomalyDetector: Model file not found at {model_path} or associated scaler not found.")
            self.model = None
            self.scaler = None
            self.model_loaded = False
        except Exception as e:
            logger.error(f"AnomalyDetector: Error loading model or scaler: {e}")
            self.model = None
            self.scaler = None
            self.model_loaded = False

    def _preprocess_features(self, features_list_of_dicts: list) -> pd.DataFrame:
        """
        Converts a list of feature dictionaries to a Pandas DataFrame and scales it.
        """
        if not features_list_of_dicts:
            return pd.DataFrame()

        df = pd.DataFrame(features_list_of_dicts)
        # Ensure all numeric columns are indeed numeric, convert if possible, else fill with 0
        for col in df.columns:
            if df[col].dtype == 'object':
                try:
                    df[col] = pd.to_numeric(df[col])
                except ValueError:
                    logger.debug(f"Could not convert column {col} to numeric, will be filled with 0 or dropped if not numeric.")
        
        df = df.fillna(0) # Fill NaNs that might arise from missing features or conversion failures

        numeric_cols = df.select_dtypes(include=np.number).columns
        if not numeric_cols.empty:
            if self.scaler:
                try:
                    # Ensure the DataFrame for scaling only contains columns the scaler was fitted on, in the correct order.
                    # This requires knowing the scaler's expected features.
                    # For simplicity, we assume the input df has all necessary numeric columns.
                    # A more robust approach would involve aligning df columns with self.scaler.feature_names_in_
                    df_scaled_values = self.scaler.transform(df[numeric_cols])
                    df_scaled = pd.DataFrame(df_scaled_values, index=df.index, columns=numeric_cols)
                    # Update original dataframe with scaled values
                    for col in numeric_cols:
                        df[col] = df_scaled[col]
                except ValueError as ve:
                    logger.error(f"Error scaling features: {ve}. This might be due to column mismatch or new columns not seen during training. Features: {df.columns.tolist()}")
                    return pd.DataFrame() # Return empty if scaling fails
                except Exception as ex:
                    logger.error(f"Unexpected error during scaling: {ex}")
                    return pd.DataFrame()
            else:
                logger.debug("Scaler not available for preprocessing. Using raw numeric features.")
        return df

    def predict_anomalies(self, features_list_of_dicts: list) -> list:
        """
        Predicts if the provided feature sets are anomalies.
        Args:
            features_list_of_dicts (list): List of feature dictionaries.
        Returns:
            list: List of predictions (-1 for anomaly, 1 for normal), or list of 1s on error/no model.
        """
        if not self.model_loaded or self.model is None:
            logger.debug("AnomalyDetector: Model not loaded. Defaulting all predictions to 'normal'.")
            return [1] * len(features_list_of_dicts)

        if not features_list_of_dicts:
            return []

        df_features = self._preprocess_features(features_list_of_dicts)
        
        if df_features.empty and features_list_of_dicts:
            logger.warning("AnomalyDetector: Feature preprocessing resulted in empty data. Defaulting predictions to 'normal'.")
            return [1] * len(features_list_of_dicts)

        try:
            predictions = self.model.predict(df_features)
            return predictions.tolist()
        except ValueError as ve:
             logger.error(f"ValueError during anomaly prediction: {ve}. This often means the input features do not match the model's expectations. Input columns: {df_features.columns.tolist()}")
             return [1] * len(features_list_of_dicts)
        except Exception as e:
            logger.error(f"Error during anomaly prediction: {e}")
            return [1] * len(features_list_of_dicts) # Default to normal on error

    def train_model(self, normal_traffic_features_list_of_dicts: list, model_save_path: str, scaler_save_path: str):
        """
        Entrena un modelo de detección de anomalías (ej. Isolation Forest) y su scaler.
        Args:
            normal_traffic_features_list_of_dicts (list): Lista de diccionarios de características de tráfico normal.
            model_save_path (str): Ruta para guardar el modelo entrenado.
            scaler_save_path (str): Ruta para guardar el scaler entrenado.
        """
        if not normal_traffic_features_list_of_dicts:
            logger.error("No data provided for training AnomalyDetector model.")
            return

        df_normal = pd.DataFrame(normal_traffic_features_list_of_dicts)
        df_normal = df_normal.fillna(0) # Simple NaN filling

        numeric_cols = df_normal.select_dtypes(include=np.number).columns
        if numeric_cols.empty:
            logger.error("No numeric columns found in the training data. Cannot train model.")
            return

        # Fit a new scaler
        self.scaler = StandardScaler()
        df_normal_scaled_values = self.scaler.fit_transform(df_normal[numeric_cols])
        df_normal_scaled = pd.DataFrame(df_normal_scaled_values, index=df_normal.index, columns=numeric_cols)
        
        # For training, use only the scaled numeric columns
        df_train = df_normal_scaled

        logger.info("Training anomaly detector model...")
        # Adjust IsolationForest parameters as needed
        self.model = IsolationForest(contamination='auto', random_state=42, n_estimators=100)
        self.model.fit(df_train)
        self.model_loaded = True
        logger.info("AnomalyDetector model training completed.")

        # Guardar el modelo y el scaler
        try:
            model_dir = os.path.dirname(model_save_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir, exist_ok=True)
            joblib.dump(self.model, model_save_path)
            logger.info(f"Model saved to: {model_save_path}")

            scaler_dir = os.path.dirname(scaler_save_path)
            if scaler_dir and not os.path.exists(scaler_dir):
                os.makedirs(scaler_dir, exist_ok=True)
            joblib.dump(self.scaler, scaler_save_path)
            logger.info(f"Scaler saved to: {scaler_save_path}")
        except Exception as e:
            logger.error(f"Error saving model or scaler: {e}")

    def interpret_prediction_results(self, original_data_list: list, predictions: list):
        """
        Interpreta y registra los resultados de la predicción de anomalías.
        """
        logger.info("--- AI Anomaly Detection Results ---")
        anomalies_found = 0
        if not predictions:
            logger.info("No predictions to interpret.")
            return

        for i, pred in enumerate(predictions):
            summary = "N/A"
            if i < len(original_data_list): # Safety check
                # Try to get a meaningful summary from the original data
                record = original_data_list[i]
                summary = record.get('summary', 
                                     record.get('source_ip_resolved', 
                                                f"Data Record {i+1} at {record.get('timestamp_iso', '')}"))
            
            if pred == -1:  # Anomalía
                anomalies_found += 1
                logger.info(f"[ANOMALY DETECTED] for: {summary}")
            # else: # pred == 1 (Normal)
            #     logger.debug(f"[NORMAL] for: {summary}") # Optional: log normal cases at debug level

        if anomalies_found == 0:
            logger.info("No anomalies detected by the AI model in this batch.")
        else:
            logger.info(f"Total anomalies detected in this batch: {anomalies_found}")
