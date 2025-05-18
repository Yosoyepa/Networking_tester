#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the PerformanceMLAnalyzer class."""

import unittest
import pandas as pd
import numpy as np

from src.ai_monitoring.performance_analyzer_ml import PerformanceMLAnalyzer


class TestPerformanceMLAnalyzer(unittest.TestCase):
    """Test cases for the PerformanceMLAnalyzer class."""

    def setUp(self):
        """Set up test environment before each test method."""
        self.analyzer = PerformanceMLAnalyzer()
        
        # Create sample data for testing
        self.sample_features = pd.DataFrame({
            'frame_length': [100, 200, 300, 400, 500],
            'timestamp': [1000, 2000, 3000, 4000, 5000],
            'ip_version': [4, 4, 4, 4, 4],
            'ip_len': [60, 80, 100, 120, 140],
            'tcp_flags': [16, 24, 16, 24, 16],
            'icmp_code': [0, 1, 0, 1, 0]  # New feature not in original training
        })

    def test_initialization(self):
        """Test the initialization of PerformanceMLAnalyzer."""
        self.assertIsNotNone(self.analyzer)
        description = self.analyzer.get_description()
        self.assertIsInstance(description, dict)
        self.assertEqual(description['name'], "Performance Feature Analyzer")

    def test_analyze_performance_features(self):
        """Test the analyze_performance_features method."""
        # Test with our sample features
        result = self.analyzer.analyze_performance_features(self.sample_features)
        
        # Check result structure
        self.assertIsInstance(result, dict)
        self.assertIn('summary', result)
        self.assertIn('quality_value', result)
        self.assertIn('details', result)
        
        # Check quality value is within expected range
        self.assertGreaterEqual(result['quality_value'], 0)
        self.assertLessEqual(result['quality_value'], 100)
        
        # Check details contains expected information
        details = result['details']
        self.assertIsInstance(details, list)
        
        # Check the dataframe was returned
        self.assertIn('dataframe', result)
        self.assertIsInstance(result['dataframe'], pd.DataFrame)

    def test_with_empty_dataframe(self):
        """Test with an empty DataFrame."""
        empty_df = pd.DataFrame()
        result = self.analyzer.analyze_performance_features(empty_df)
        
        # Even with empty data, should return a structured result
        self.assertIsInstance(result, dict)
        self.assertIn('summary', result)
        self.assertIn('quality_value', result)
        self.assertIn('details', result)
        self.assertEqual(result['quality_value'], 0.0)
        self.assertEqual(result['summary'], "No data to analyze")

    def test_with_invalid_data(self):
        """Test with invalid data types."""
        # Test with None - should handle this gracefully
        try:
            result = self.analyzer.analyze_performance_features(None)
            self.fail("Should have raised an AttributeError for None input")
        except AttributeError:
            # This is the expected behavior
            pass
        
        # Test with non-DataFrame
        try:
            result = self.analyzer.analyze_performance_features("not a dataframe")
            self.fail("Should have raised an AttributeError for string input")
        except (AttributeError, TypeError):
            # This is the expected behavior
            pass


if __name__ == '__main__':
    unittest.main()
