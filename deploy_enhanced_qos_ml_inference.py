#!/usr/bin/env python3
"""
Phase 2 Task 2.2: Enhanced QoS ML Inference Service Deployment

This script deploys the Enhanced QoS ML Inference Service with advanced capabilities:
- Dynamic model loading/unloading
- Model health monitoring  
- Integration with enhanced model registry
- Support for multiple model types (GMM, VAE, Isolation Forest)
- Robust feature mismatch handling

This replaces the basic Phase 1 ML inference service with enterprise-grade capabilities.
"""
import os
import sys
import logging
import asyncio
import signal
from typing import Optional

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.messaging.rabbitmq_client import RabbitMQClient
from src.ai_monitoring.enhanced_qos_ml_inference_service import EnhancedQoSMLInferenceService
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)

class EnhancedQoSMLInferenceDeployment:
    """Manages deployment of Enhanced QoS ML Inference Service."""
    
    def __init__(self):
        self.service = None
        self.mq_client = None
        self.model_registry_client = None
        self.running = False
    
    async def deploy(self):
        """Deploy the Enhanced QoS ML Inference Service."""
        
        # Setup logging
        setup_logging()
        logger.info("🚀 Starting Phase 2 Task 2.2: Enhanced QoS ML Inference Service Deployment")
        
        # Configuration
        RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
        
        # Model Configuration
        INITIAL_MODEL_NAME = os.getenv('QOS_MODEL_NAME', 'qos_anomaly_gmm_e2e_test')
        INITIAL_MODEL_VERSION = os.getenv('QOS_MODEL_VERSION', 'latest')
        
        try:
            logger.info("🔧 Initializing Enhanced Model Registry Client...")
            # Initialize Enhanced Model Registry Client with MLflow support
            self.model_registry_client = EnhancedModelRegistryClient(
                project_root_dir=project_root,
                use_mlflow=True,  # Enable MLflow integration for Phase 2
                experiment_name="networking_tester_qos_anomaly"
            )
            
            logger.info("🔌 Initializing RabbitMQ client...")
            # Initialize RabbitMQ client
            self.mq_client = RabbitMQClient(host=RABBITMQ_HOST)
            
            logger.info("🤖 Creating Enhanced QoS ML Inference Service...")
            # Create Enhanced QoS ML Inference Service
            self.service = EnhancedQoSMLInferenceService(
                rabbitmq_client=self.mq_client,
                model_registry_client=self.model_registry_client,
                initial_model_name=INITIAL_MODEL_NAME,
                initial_model_version=INITIAL_MODEL_VERSION
            )
            
            logger.info("✅ Enhanced QoS ML Inference Service initialized successfully")
            logger.info(f"🎯 Initial model: {INITIAL_MODEL_NAME} v{INITIAL_MODEL_VERSION}")
            logger.info(f"🔄 Model health monitoring: ENABLED")
            logger.info(f"📊 Supported model types: GMM, VAE, Isolation Forest")
            
            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            logger.info("🔄 Starting Enhanced QoS ML Inference Service...")
            self.running = True
            
            # Start the service (this will run the async event loop)
            await self.service.start()
            
        except Exception as e:
            logger.error(f"❌ Error in Enhanced QoS ML Inference Service deployment: {e}", exc_info=True)
            await self.cleanup()
            return 1
        
        return 0
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals for graceful shutdown."""
        logger.info(f"🛑 Received signal {signum}, initiating graceful shutdown...")
        self.running = False
        if self.service:
            asyncio.create_task(self.service.stop())
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.service:
            try:
                await self.service.stop()
                logger.info("🔄 Enhanced QoS ML Inference Service stopped")
            except Exception as e:
                logger.error(f"Error stopping service: {e}")
        
        if self.mq_client:
            try:
                await self.mq_client.close()
                logger.info("🔌 Closed RabbitMQ connection")
            except Exception as e:
                logger.error(f"Error closing RabbitMQ connection: {e}")
        
        logger.info("🏁 Enhanced QoS ML Inference Service deployment finished")

async def main():
    """Main deployment function."""
    deployment = EnhancedQoSMLInferenceDeployment()
    try:
        return await deployment.deploy()
    except KeyboardInterrupt:
        logger.info("🛑 Enhanced QoS ML Inference Service stopped by user")
        await deployment.cleanup()
        return 0
    except Exception as e:
        logger.error(f"💥 Fatal error in Enhanced QoS ML Inference Service: {e}", exc_info=True)
        await deployment.cleanup()
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"💥 Failed to start Enhanced QoS ML Inference Service: {e}", exc_info=True)
        sys.exit(1)
