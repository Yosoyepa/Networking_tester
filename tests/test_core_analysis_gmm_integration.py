import unittest
from unittest.mock import MagicMock, patch
import time
import os
import sys
import datetime # Added for timezone-aware timestamps

# Add project root to Python path to allow direct imports of src modules
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from src.analysis.core_analysis_service import CoreAnalysisService
from src.messaging.schemas import MLResult, AnalysisResult # Assuming schemas are accessible
from src.utils.logging_config import setup_logging

# Setup logging for the test
setup_logging() # Removed level argument

class TestCoreAnalysisGMMIntegration(unittest.TestCase):

    def setUp(self):
        # Mock RabbitMQClient
        self.mock_mq_client = MagicMock()

        # Instantiate CoreAnalysisService with mock client and dummy names
        self.core_service = CoreAnalysisService(
            mq_client=self.mock_mq_client,
            parsed_packets_exchange="dummy_parsed_exchange",
            parsed_packets_queue="dummy_parsed_queue",
            ml_results_exchange="dummy_ml_exchange",
            ml_results_queue="dummy_ml_queue",
            output_exchange="dummy_analysis_exchange",
            output_routing_key="dummy_analysis_routing_key"
        )

        # Mock the _publish_analysis_result method to capture its output
        self.core_service._publish_analysis_result = MagicMock()

    def test_handle_gmm_ml_result(self):
        # 1. Define a sample GMM MLResult
        sample_gmm_ml_result: MLResult = {
            "packet_id": "test_packet_gmm_001",
            "model_id": "qos_anomaly_gmm_e2e_test-1.0.0",
            "model_type": "gmm",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), # Corrected timestamp
            "anomaly_score": -15.723,  # Example log-likelihood score (low, indicating anomaly)
            "is_anomaly": True,
            "prediction": -1, # Consistent with is_anomaly
            "details": {
                "original_packet_timestamp": "2025-05-17T10:00:00.123Z",
                "feature_count_input": 5,
                "feature_count_processed": 5,
                "log_likelihood": -15.723
            }
        }

        # 2. Call _handle_ml_result
        print(f"\nSending sample GMM MLResult to CoreAnalysisService: {sample_gmm_ml_result}")
        self.core_service._handle_ml_result(sample_gmm_ml_result)

        # 3. Assert that _publish_analysis_result was called
        self.core_service._publish_analysis_result.assert_called_once()

        # 4. Get the AnalysisResult passed to _publish_analysis_result
        published_analysis_result: AnalysisResult = self.core_service._publish_analysis_result.call_args[0][0]

        print(f"\nGenerated AnalysisResult: {published_analysis_result}")

        # 5. Perform assertions on the AnalysisResult
        self.assertEqual(published_analysis_result["type"], "ml_anomaly_detected")
        self.assertIn("test_packet_gmm_001", published_analysis_result["source_packet_ids"])
        self.assertIn("qos_anomaly_gmm_e2e_test-1.0.0", published_analysis_result["summary"])
        self.assertIn("Log-Likelihood: -15.7230", published_analysis_result["summary"]) # Check score interpretation
        self.assertEqual(published_analysis_result["details"]["model_type"], "gmm")
        self.assertEqual(published_analysis_result["details"]["ml_anomaly_score"], -15.723)
        # Based on the current logic in CoreAnalysisService for GMM: score < -10 is 'high'
        self.assertEqual(published_analysis_result["severity"], "high") 

    def test_handle_gmm_ml_result_normal(self):
        # 1. Define a sample GMM MLResult for a normal prediction
        sample_gmm_ml_result_normal: MLResult = {
            "packet_id": "test_packet_gmm_002",
            "model_id": "qos_anomaly_gmm_e2e_test-1.0.0",
            "model_type": "gmm",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), # Corrected timestamp
            "anomaly_score": 2.5,  # Example log-likelihood score (higher, indicating normal)
            "is_anomaly": False,
            "prediction": 1, 
            "details": {
                "original_packet_timestamp": "2025-05-17T10:00:05.456Z",
                "feature_count_input": 5,
                "feature_count_processed": 5,
                "log_likelihood": 2.5
            }
        }

        print(f"\nSending sample GMM MLResult (normal) to CoreAnalysisService: {sample_gmm_ml_result_normal}")
        self.core_service._handle_ml_result(sample_gmm_ml_result_normal)
        self.core_service._publish_analysis_result.assert_called_once()
        published_analysis_result: AnalysisResult = self.core_service._publish_analysis_result.call_args[0][0]
        print(f"\nGenerated AnalysisResult (normal): {published_analysis_result}")

        self.assertEqual(published_analysis_result["type"], "ml_prediction_normal") # Type should indicate normal
        self.assertIn("test_packet_gmm_002", published_analysis_result["source_packet_ids"])
        self.assertIn("Log-Likelihood: 2.5000", published_analysis_result["summary"])
        self.assertEqual(published_analysis_result["details"]["model_type"], "gmm")
        self.assertEqual(published_analysis_result["severity"], "info") # Default for normal

if __name__ == '__main__':
    unittest.main()
