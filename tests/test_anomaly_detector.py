#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the AnomalyDetector class."""

import os
import unittest
import tempfile
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.ai_monitoring.anomaly_detector import AnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    """Test cases for the AnomalyDetector class."""

    def setUp(self):
        """Set up test environment before each test method."""
        # Create temporary directory for test models
        self.test_dir = tempfile.mkdtemp()
        
        # Create a sample training dataset with expected features
        self.training_data = pd.DataFrame({
            'frame_length': [100, 200, 300, 400, 500],
            'timestamp': [1000, 2000, 3000, 4000, 5000],
            'ip_version': [4, 4, 4, 4, 4],
            'ip_len': [60, 80, 100, 120, 140],
            'tcp_flags': [16, 24, 16, 24, 16]
        })
        
        # Train a model for testing
        self.model_path = os.path.join(self.test_dir, 'test_model.joblib')
        self.scaler_path = os.path.join(self.test_dir, 'test_model_scaler.joblib')
        
        # Create and save test model and scaler
        model = IsolationForest(contamination=0.1, random_state=42)
        scaler = StandardScaler()
        
        # Fit the scaler and model
        scaled_data = scaler.fit_transform(self.training_data)
        model.fit(scaled_data)
        
        # Save model and scaler
        joblib.dump(model, self.model_path)
        joblib.dump(scaler, self.scaler_path)
        
        # Create detector instance
        self.detector = AnomalyDetector(self.model_path, self.scaler_path)

    def tearDown(self):
        """Clean up after each test method."""
        # Remove test files
        if os.path.exists(self.model_path):
            os.remove(self.model_path)
        if os.path.exists(self.scaler_path):
            os.remove(self.scaler_path)
        
        # Remove the test directory
        os.rmdir(self.test_dir)

    def test_initialization(self):
        """Test the initialization of AnomalyDetector."""
        # Test with valid paths
        detector = AnomalyDetector(self.model_path, self.scaler_path)
        self.assertTrue(detector.is_trained())
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.scaler)
        
        # Test with invalid paths
        detector = AnomalyDetector("non_existent_path.joblib", "non_existent_scaler.joblib")
        self.assertFalse(detector.is_trained())
        self.assertIsNone(detector.model)
        self.assertIsNone(detector.scaler)
        
        # Test with no paths
        detector = AnomalyDetector()
        self.assertFalse(detector.is_trained())

    def test_load_model(self):
        """Test the load_model method."""
        # Create a new detector without a model
        detector = AnomalyDetector()
        self.assertFalse(detector.is_trained())
        
        # Load model
        detector.load_model(self.model_path, self.scaler_path)
        self.assertTrue(detector.is_trained())
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.scaler)
        
        # Test with only model path (should try to load default scaler path)
        detector = AnomalyDetector()
        detector.load_model(self.model_path)
        self.assertTrue(detector.is_trained())

    def test_predict_with_expected_features(self):
        """Test prediction with expected features."""
        # Create test data with expected features
        test_data = pd.DataFrame({
            'frame_length': [250],
            'timestamp': [2500],
            'ip_version': [4],
            'ip_len': [90],
            'tcp_flags': [16]
        })
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)  # One prediction for one row
        
        # Should be either -1 (anomaly) or 1 (normal)
        self.assertTrue(result[0] == -1 or result[0] == 1)

    def test_predict_with_new_features(self):
        """Test prediction with new features that weren't in the training data."""
        # Create test data with new features
        test_data = pd.DataFrame({
            'frame_length': [250],
            'timestamp': [2500],
            'icmp_code': [0],  # New feature
            'icmp_chksum': [12345]  # New feature
        })
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)  # One prediction for one row
        
        # Should be either -1 (anomaly) or 1 (normal)
        self.assertTrue(result[0] == -1 or result[0] == 1)

    def test_predict_with_mixed_features(self):
        """Test prediction with a mix of expected and new features."""
        # Create test data with mixed features
        test_data = pd.DataFrame({
            'frame_length': [250],
            'timestamp': [2500],
            'ip_version': [4],
            'ip_len': [90],
            'tcp_flags': [16],
            'icmp_code': [0],  # New feature
            'icmp_chksum': [12345]  # New feature
        })
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)  # One prediction for one row
        
        # Should be either -1 (anomaly) or 1 (normal)
        self.assertTrue(result[0] == -1 or result[0] == 1)

    def test_predict_with_missing_features(self):
        """Test prediction with missing features from the training data."""
        # Create test data with only a subset of expected features
        test_data = pd.DataFrame({
            'frame_length': [250],
            'timestamp': [2500]
            # Missing: 'ip_version', 'ip_len', 'tcp_flags'
        })
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)  # One prediction for one row
        
        # Should be either -1 (anomaly) or 1 (normal)
        self.assertTrue(result[0] == -1 or result[0] == 1)

    def test_predict_empty_dataframe(self):
        """Test prediction with an empty DataFrame."""
        # Create empty DataFrame
        test_data = pd.DataFrame()
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 0)  # Empty result for empty input

    def test_train(self):
        """Test the on-the-fly training method."""
        # Create a new detector without a model
        detector = AnomalyDetector()
        self.assertFalse(detector.is_trained())
        
        # Train the model
        detector.train(self.training_data)
        self.assertTrue(detector.is_trained())
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.scaler)
        
        # Test prediction after training
        test_data = pd.DataFrame({
            'frame_length': [250],
            'timestamp': [2500],
            'ip_version': [4],
            'ip_len': [90],
            'tcp_flags': [16]
        })
        
        result = detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)

    def test_train_model_and_save(self):
        """Test training a model and saving it to disk."""
        # Create new paths for saving
        new_model_path = os.path.join(self.test_dir, 'new_model.joblib')
        new_scaler_path = os.path.join(self.test_dir, 'new_model_scaler.joblib')
        
        # Create a new detector without a model
        detector = AnomalyDetector()
        
        # Train and save the model
        detector.train_model(self.training_data, new_model_path, new_scaler_path)
        
        # Verify files were created
        self.assertTrue(os.path.exists(new_model_path))
        self.assertTrue(os.path.exists(new_scaler_path))
        
        # Verify model can be loaded
        new_detector = AnomalyDetector(new_model_path, new_scaler_path)
        self.assertTrue(new_detector.is_trained())
        
        # Clean up
        os.remove(new_model_path)
        os.remove(new_scaler_path)

    def test_predict_anomalies(self):
        """Test the predict_anomalies method with list of dicts."""
        # Create test data as list of dicts
        test_data = [
            {'frame_length': 250, 'timestamp': 2500, 'ip_version': 4, 'ip_len': 90, 'tcp_flags': 16},
            {'frame_length': 350, 'timestamp': 3500, 'ip_version': 4, 'ip_len': 110, 'tcp_flags': 24}
        ]
        
        # Test prediction
        result = self.detector.predict_anomalies(test_data)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)  # Two predictions for two dicts
        
        # Should be either -1 (anomaly) or 1 (normal) for each prediction
        for r in result:
            self.assertTrue(r == -1 or r == 1)

    def test_interpret_prediction_results(self):
        """Test the interpretation of prediction results."""
        # Create test data and corresponding predictions
        test_data = [
            {'summary': 'Packet 1', 'source_ip_resolved': '192.168.1.1', 'timestamp_iso': '2025-05-15T12:00:00'},
            {'summary': 'Packet 2', 'source_ip_resolved': '192.168.1.2', 'timestamp_iso': '2025-05-15T12:01:00'}
        ]
        predictions = [-1, 1]  # One anomaly, one normal
        
        # Call the method (it only logs results, doesn't return anything)
        # We're just testing that it runs without errors
        self.detector.interpret_prediction_results(test_data, predictions)


if __name__ == '__main__':
    unittest.main()
