#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Integration tests for the AnomalyDetector feature mismatch fix."""

import os
import unittest
import pandas as pd
import numpy as np
import logging

from src.ai_monitoring.anomaly_detector import AnomalyDetector

# Suppress logging for cleaner test output
logging.basicConfig(level=logging.ERROR)


class TestAnomalyDetectorFeatureMismatch(unittest.TestCase):
    """
    Integration tests specifically for verifying the feature mismatch fix
    in the AnomalyDetector class using the real pre-trained model.
    """

    def setUp(self):
        """Set up test environment before each test method."""
        # Path to the real model and scaler
        self.model_path = 'data/models/ai_anomaly_detector.joblib'
        self.scaler_path = 'data/models/ai_anomaly_detector_scaler.joblib'
        
        # Skip tests if model doesn't exist
        if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
            self.skipTest("Trained model files not found. Skipping tests.")
        
        # Create detector instance with the real model
        self.detector = AnomalyDetector(self.model_path, self.scaler_path)

    def test_model_loaded(self):
        """Test that the model is properly loaded."""
        self.assertTrue(self.detector.is_trained())
        self.assertIsNotNone(self.detector.model)
        self.assertIsNotNone(self.detector.scaler)
        
        # Check that scaler has feature_names_in_ attribute
        self.assertTrue(hasattr(self.detector.scaler, 'feature_names_in_'))
        
        # Print the expected features for debugging
        expected_features = self.detector.scaler.feature_names_in_
        self.assertGreater(len(expected_features), 0)

    def test_predict_with_expected_features(self):
        """Test prediction with a subset of expected features."""
        # Get some known features from the scaler
        expected_features = self.detector.scaler.feature_names_in_
        
        # Take first 5 features if there are enough
        feature_subset = expected_features[:min(5, len(expected_features))]
        
        # Create test data with only these features
        test_data = pd.DataFrame({feature: [100] for feature in feature_subset})
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)

    def test_predict_with_new_features(self):
        """Test prediction with completely new features."""
        # Create test data with new features
        test_data = pd.DataFrame({
            'icmp_code': [0],
            'icmp_chksum': [12345],
            'new_feature_1': [500],
            'new_feature_2': [600]
        })
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)
        
        # We expect a normal result (1) because with no matching features,
        # the detector should default to normal
        self.assertEqual(result[0], 1)

    def test_predict_with_mixed_features(self):
        """Test prediction with both expected and new features."""
        # Get some known features from the scaler
        expected_features = self.detector.scaler.feature_names_in_
        
        # Take first 2 features if there are enough
        feature_subset = expected_features[:min(2, len(expected_features))]
        
        # Create test data with both known and new features
        test_data = pd.DataFrame()
        for i, feature in enumerate(feature_subset):
            test_data[feature] = [100 + i * 10]
        
        # Add new features
        test_data['icmp_code'] = [0]
        test_data['icmp_chksum'] = [12345]
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)
        
        # Should be either -1 (anomaly) or 1 (normal)
        self.assertTrue(result[0] == -1 or result[0] == 1)

    def test_predict_with_multiple_rows(self):
        """Test prediction with multiple rows of data."""
        # Get some known features from the scaler
        expected_features = self.detector.scaler.feature_names_in_
        
        # Take first 3 features if there are enough
        feature_subset = expected_features[:min(3, len(expected_features))]
        
        # Create multi-row test data with both known and new features
        test_data = pd.DataFrame()
        for i, feature in enumerate(feature_subset):
            test_data[feature] = [100 + i * 10, 200 + i * 20, 300 + i * 30]
        
        # Add new features
        test_data['icmp_code'] = [0, 1, 2]
        test_data['icmp_chksum'] = [12345, 23456, 34567]
        
        # Test prediction
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 3)
        
        # Each result should be either -1 (anomaly) or 1 (normal)
        for r in result:
            self.assertTrue(r == -1 or r == 1)

    def test_extreme_missing_features(self):
        """Test prediction with extreme cases of missing expected features."""
        # Get some known features from the scaler
        expected_features = self.detector.scaler.feature_names_in_
        
        # Take just the first feature if there is one
        if len(expected_features) > 0:
            test_data = pd.DataFrame({expected_features[0]: [100]})
            
            # Test prediction with just one expected feature
            result = self.detector.predict(test_data)
            self.assertIsInstance(result, np.ndarray)
            self.assertEqual(len(result), 1)
        
        # Test with a single new feature that's not in the expected features
        test_data = pd.DataFrame({'completely_new_feature': [999]})
        
        # This should default to normal (1) since no expected features are present
        result = self.detector.predict(test_data)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 1)


if __name__ == '__main__':
    unittest.main()
