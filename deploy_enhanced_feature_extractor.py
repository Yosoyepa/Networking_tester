#!/usr/bin/env python3
"""
Phase 2 Task 2.1: Enhanced Feature Extractor Service Deployment

This script deploys the Enhanced Feature Extractor Service with model-aware capabilities,
replacing the basic Phase 1 service with advanced model registry integration.

Features:
- Dynamic model-aware feature extraction
- Feature schema validation against model requirements
- Model-specific feature filtering and transformation
- Integration with Enhanced Model Registry Client
"""
import os
import sys
import logging
import asyncio
from typing import List, Dict

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.messaging.rabbitmq_client import RabbitMQClient
from src.ai_monitoring.enhanced_feature_extractor_service import EnhancedFeatureExtractorService
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)

def main():
    """Deploy Enhanced Feature Extractor Service for Phase 2."""
    
    # Setup logging
    setup_logging()
    logger.info("🚀 Starting Phase 2 Task 2.1: Enhanced Feature Extractor Service Deployment")
    
    # Configuration
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    
    # Exchange and Queue Configuration
    INPUT_EXCHANGE_NAME = "parsed_packets_exchange"
    INPUT_QUEUE_NAME = "parsed_packets_queue_enhanced_features"  # Separate queue for enhanced service
    OUTPUT_EXCHANGE_NAME = "features_exchange"
    OUTPUT_ROUTING_KEY = "enhanced_features_queue"  # Enhanced features output
    
    # Model Configuration - Active models for feature extraction
    ACTIVE_MODEL_CONFIGS = [
        {"model_name": "qos_anomaly_gmm_e2e_test", "model_version": "latest"},
        {"model_name": "dummy_qos_model", "model_version": "latest"}
    ]
    
    mq_client_instance = None
    model_registry_client = None
    
    try:
        logger.info("Initializing Enhanced Model Registry Client...")
        # Initialize Enhanced Model Registry Client with MLflow support
        model_registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True,  # Enable MLflow integration for Phase 2
            experiment_name="networking_tester_qos_anomaly"
        )
        
        logger.info("Initializing RabbitMQ client...")
        # Initialize RabbitMQ client
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST)
        
        logger.info("Creating Enhanced Feature Extractor Service...")
        # Create Enhanced Feature Extractor Service
        enhanced_feature_extractor = EnhancedFeatureExtractorService(
            mq_client=mq_client_instance,
            model_registry_client=model_registry_client,
            input_exchange_name=INPUT_EXCHANGE_NAME,
            input_queue_name=INPUT_QUEUE_NAME,
            output_exchange_name=OUTPUT_EXCHANGE_NAME,
            output_routing_key=OUTPUT_ROUTING_KEY,
            active_model_configs=ACTIVE_MODEL_CONFIGS
        )
        
        logger.info("✅ Enhanced Feature Extractor Service initialized successfully")
        logger.info(f"📥 Consuming from: {INPUT_EXCHANGE_NAME}/{INPUT_QUEUE_NAME}")
        logger.info(f"📤 Publishing to: {OUTPUT_EXCHANGE_NAME}/{OUTPUT_ROUTING_KEY}")
        logger.info(f"🤖 Active models: {len(ACTIVE_MODEL_CONFIGS)} configured")
        
        # Display active model configurations
        for i, config in enumerate(ACTIVE_MODEL_CONFIGS, 1):
            logger.info(f"   {i}. {config['model_name']} v{config['model_version']}")
        
        logger.info("🔄 Starting Enhanced Feature Extractor Service consumption...")
        # Start consuming (this will block)
        enhanced_feature_extractor.start_consuming()
        
    except Exception as e:
        logger.error(f"❌ Error in Enhanced Feature Extractor Service deployment: {e}", exc_info=True)
        return 1
    finally:
        if mq_client_instance:
            try:
                mq_client_instance.close()
                logger.info("🔌 Closed RabbitMQ connection")
            except Exception:
                pass
        logger.info("🏁 Enhanced Feature Extractor Service deployment finished")
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("🛑 Enhanced Feature Extractor Service stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Fatal error in Enhanced Feature Extractor Service: {e}", exc_info=True)
        sys.exit(1)
