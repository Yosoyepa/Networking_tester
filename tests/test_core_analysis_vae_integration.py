import unittest
from unittest.mock import MagicMock, patch
import time
import os
import sys
import datetime
import uuid

# Add project root to Python path to allow direct imports of src modules
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from src.analysis.core_analysis_service import CoreAnalysisService
from src.messaging.schemas import MLResult, AnalysisResult
from src.utils.logger_config import setup_logging

# Setup logging for the test
setup_logging()

class TestCoreAnalysisVAEIntegration(unittest.TestCase):

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

    def test_handle_vae_ml_result_anomaly(self):
        # 1. Define a sample VAE MLResult for an anomaly
        sample_vae_ml_result_anomaly: MLResult = {
            "packet_id": f"test_packet_vae_{uuid.uuid4()}_anomaly",
            "model_id": "qos_anomaly_vae_e2e_test-1.0.0", # Example VAE model ID
            "model_type": "vae",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "anomaly_score": 0.85,  # Example reconstruction error (high, indicating anomaly)
            "is_anomaly": True,
            "prediction": 1, # Consistent with is_anomaly (1 for anomaly)
            "details": {
                "original_packet_timestamp": "2025-05-17T11:00:00.123Z",
                "feature_count_input": 5,
                "feature_count_processed": 5,
                "reconstruction_error": 0.85,
                "threshold": 0.6 # Example threshold used by VAE
            }
        }

        # 2. Call _handle_ml_result
        print(f"\nSending sample VAE MLResult (anomaly) to CoreAnalysisService: {sample_vae_ml_result_anomaly}")
        self.core_service._handle_ml_result(sample_vae_ml_result_anomaly)

        # 3. Assert that _publish_analysis_result was called
        self.core_service._publish_analysis_result.assert_called_once()

        # 4. Get the AnalysisResult passed to _publish_analysis_result
        published_analysis_result: AnalysisResult = self.core_service._publish_analysis_result.call_args[0][0]

        print(f"\nGenerated AnalysisResult (VAE anomaly): {published_analysis_result}")

        # 5. Perform assertions on the AnalysisResult
        self.assertEqual(published_analysis_result["type"], "ml_anomaly_detected")
        self.assertIn(sample_vae_ml_result_anomaly["packet_id"], published_analysis_result["source_packet_ids"])
        self.assertIn("qos_anomaly_vae_e2e_test-1.0.0", published_analysis_result["summary"])
        self.assertIn("Reconstruction Error: 0.8500", published_analysis_result["summary"]) # Check score interpretation
        self.assertIn("Threshold: 0.6000", published_analysis_result["summary"])
        self.assertEqual(published_analysis_result["details"]["model_type"], "vae")
        self.assertEqual(published_analysis_result["details"]["ml_anomaly_score"], 0.85)
        # Assuming VAE: score > 0.75 is 'high', 0.5 < score <= 0.75 is 'medium' (example logic)
        self.assertEqual(published_analysis_result["severity"], "high") 

    def test_handle_vae_ml_result_normal(self):
        # 1. Define a sample VAE MLResult for a normal prediction
        sample_vae_ml_result_normal: MLResult = {
            "packet_id": f"test_packet_vae_{uuid.uuid4()}_normal",
            "model_id": "qos_anomaly_vae_e2e_test-1.0.0",
            "model_type": "vae",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "anomaly_score": 0.15,  # Example reconstruction error (low, indicating normal)
            "is_anomaly": False,
            "prediction": 0, # Consistent with is_anomaly (0 for normal)
            "details": {
                "original_packet_timestamp": "2025-05-17T11:00:05.456Z",
                "feature_count_input": 5,
                "feature_count_processed": 5,
                "reconstruction_error": 0.15,
                "threshold": 0.6
            }
        }

        print(f"\nSending sample VAE MLResult (normal) to CoreAnalysisService: {sample_vae_ml_result_normal}")
        self.core_service._handle_ml_result(sample_vae_ml_result_normal)
        self.core_service._publish_analysis_result.assert_called_once()
        published_analysis_result: AnalysisResult = self.core_service._publish_analysis_result.call_args[0][0]
        print(f"\nGenerated AnalysisResult (VAE normal): {published_analysis_result}")

        self.assertEqual(published_analysis_result["type"], "ml_prediction_normal")
        self.assertIn(sample_vae_ml_result_normal["packet_id"], published_analysis_result["source_packet_ids"])
        self.assertIn("Reconstruction Error: 0.1500", published_analysis_result["summary"])
        self.assertEqual(published_analysis_result["details"]["model_type"], "vae")
        self.assertEqual(published_analysis_result["severity"], "info")

if __name__ == '__main__':
    unittest.main()
