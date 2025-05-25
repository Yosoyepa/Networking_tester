"""
Model Management Service for the distributed networking_tester architecture.

This service provides centralized model management capabilities including:
- Model registration and versioning
- Model deployment and promotion
- Model health monitoring
- Model synchronization between registries

The service acts as a bridge between the MLOps pipeline and the inference services.
"""
import logging
import asyncio
import json
import os
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime
import signal

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import ModelManagementMessage, ServiceHealthMessage
from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.utils.logging_config import setup_logging
from config.config_loader import load_config

logger = logging.getLogger(__name__)

class ModelManagementService:
    """
    Service for managing ML models in the distributed architecture.
    
    Handles model registration, deployment, versioning, and health monitoring.
    Integrates with both file-based and MLflow model registries.
    """
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """Initialize the Model Management Service."""
        self.config = load_config(config_path)
        self.service_name = "model_management_service"
        self.is_running = False
        
        # Initialize logging
        setup_logging(self.config)
        logger.info("Initializing Model Management Service")
        
        # Initialize enhanced model registry client
        mlflow_config = self.config.get("mlflow", {})
        self.registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True,
            mlflow_tracking_uri=mlflow_config.get("tracking_uri"),
            experiment_name=mlflow_config.get("experiment_name")
        )
        
        # Initialize RabbitMQ client
        rabbitmq_config = self.config.get("rabbitmq", {})
        self.rabbitmq_client = RabbitMQClient(
            host=rabbitmq_config.get("host", "localhost"),
            port=rabbitmq_config.get("port", 5672),
            username=rabbitmq_config.get("username", "guest"),
            password=rabbitmq_config.get("password", "guest")
        )
        
        # Service state
        self.current_models = {}  # Track currently deployed models
        self.model_health = {}    # Track model health status
        
        # Queue names
        self.model_management_queue = "model_management_requests"
        self.model_deployment_queue = "model_deployment_commands"
        self.service_health_queue = "service_health"
        
    async def start(self):
        """Start the Model Management Service."""
        try:
            logger.info("Starting Model Management Service")
            self.is_running = True
            
            # Connect to RabbitMQ
            await self.rabbitmq_client.connect()
            
            # Declare queues
            await self._declare_queues()
            
            # Start consuming messages
            await asyncio.gather(
                self._consume_model_requests(),
                self._monitor_model_health(),
                self._publish_service_health()
            )
            
        except Exception as e:
            logger.error(f"Failed to start Model Management Service: {e}", exc_info=True)
            await self.stop()
            
    async def stop(self):
        """Stop the Model Management Service."""
        logger.info("Stopping Model Management Service")
        self.is_running = False
        
        if self.rabbitmq_client:
            await self.rabbitmq_client.disconnect()
            
    async def _declare_queues(self):
        """Declare required RabbitMQ queues."""
        queues = [
            self.model_management_queue,
            self.model_deployment_queue,
            self.service_health_queue
        ]
        
        for queue in queues:
            await self.rabbitmq_client.declare_queue(queue, durable=True)
            
    async def _consume_model_requests(self):
        """Consume model management requests."""
        logger.info("Starting to consume model management requests")
        
        async def process_request(message: Dict[str, Any]):
            try:
                request = ModelManagementMessage(**message)
                await self._handle_model_request(request)
            except Exception as e:
                logger.error(f"Error processing model request: {e}", exc_info=True)
                
        await self.rabbitmq_client.consume(
            queue=self.model_management_queue,
            callback=process_request
        )
        
    async def _handle_model_request(self, request: ModelManagementMessage):
        """Handle incoming model management requests."""
        logger.info(f"Processing model request: {request.action} for {request.model_name}")
        
        response = {
            "request_id": request.request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "service": self.service_name,
            "success": False,
            "data": {},
            "error": None
        }
        
        try:
            if request.action == "register":
                result = await self._register_model(request)
                response["success"] = True
                response["data"] = result
                
            elif request.action == "deploy":
                result = await self._deploy_model(request)
                response["success"] = True
                response["data"] = result
                
            elif request.action == "promote":
                result = await self._promote_model(request)
                response["success"] = True
                response["data"] = result
                
            elif request.action == "list":
                result = await self._list_models(request)
                response["success"] = True
                response["data"] = result
                
            elif request.action == "get_details":
                result = await self._get_model_details(request)
                response["success"] = True
                response["data"] = result
                
            elif request.action == "sync":
                result = await self._sync_registries(request)
                response["success"] = True
                response["data"] = result
                
            else:
                response["error"] = f"Unknown action: {request.action}"
                
        except Exception as e:
            logger.error(f"Error handling model request {request.action}: {e}", exc_info=True)
            response["error"] = str(e)
            
        # Send response back if response_queue is specified
        if hasattr(request, 'response_queue') and request.response_queue:
            await self.rabbitmq_client.publish(
                queue=request.response_queue,
                message=response
            )
            
    async def _register_model(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """Register a new model version."""
        logger.info(f"Registering model {request.model_name} version {request.model_version}")
        
        result = self.registry_client.register_model_enhanced(
            model_name=request.model_name,
            model_version=request.model_version,
            model_path=request.model_path,
            metadata=request.metadata or {},
            scaler_path=request.scaler_path,
            description=request.description,
            register_to_mlflow=True,
            mlflow_run_id=request.mlflow_run_id
        )
        
        logger.info(f"Successfully registered {request.model_name} v{request.model_version}")
        return result
        
    async def _deploy_model(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """Deploy a model version to inference services."""
        logger.info(f"Deploying model {request.model_name} version {request.model_version}")
        
        # Get model details
        model_details = self.registry_client.get_model_details(
            model_name=request.model_name,
            version=request.model_version or "latest"
        )
        
        if not model_details:
            raise ValueError(f"Model {request.model_name} version {request.model_version} not found")
            
        # Create deployment command
        deployment_command = {
            "action": "load_model",
            "model_name": request.model_name,
            "model_version": model_details["version"],
            "model_path": model_details["model_path"],
            "scaler_path": model_details.get("scaler_path"),
            "metadata": model_details.get("metadata", {}),
            "timestamp": datetime.utcnow().isoformat(),
            "target_services": request.target_services or ["qos_ml_inference", "feature_extractor"]
        }
        
        # Publish deployment command
        await self.rabbitmq_client.publish(
            queue=self.model_deployment_queue,
            message=deployment_command
        )
        
        # Update tracking
        self.current_models[request.model_name] = {
            "version": model_details["version"],
            "deployed_at": datetime.utcnow().isoformat(),
            "target_services": deployment_command["target_services"]
        }
        
        logger.info(f"Successfully deployed {request.model_name} v{model_details['version']}")
        return deployment_command
        
    async def _promote_model(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """Promote a model version to a specific stage."""
        logger.info(f"Promoting model {request.model_name} version {request.model_version} to {request.target_stage}")
        
        success = self.registry_client.promote_model_stage(
            model_name=request.model_name,
            version=request.model_version,
            stage=request.target_stage
        )
        
        if not success:
            raise ValueError(f"Failed to promote {request.model_name} v{request.model_version}")
            
        # If promoting to Production, auto-deploy
        if request.target_stage == "Production":
            deploy_request = ModelManagementMessage(
                action="deploy",
                model_name=request.model_name,
                model_version=request.model_version
            )
            await self._deploy_model(deploy_request)
            
        return {
            "model_name": request.model_name,
            "version": request.model_version,
            "stage": request.target_stage,
            "promoted_at": datetime.utcnow().isoformat()
        }
        
    async def _list_models(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """List available models."""
        source = request.metadata.get("source", "both") if request.metadata else "both"
        models = self.registry_client.list_models(source=source)
        
        model_details = []
        for model_name in models:
            versions = self.registry_client.get_model_versions(model_name, source=source)
            latest_details = self.registry_client.get_model_details(model_name, "latest", source=source)
            
            model_info = {
                "name": model_name,
                "versions": versions,
                "latest_version": versions[0] if versions else None,
                "latest_details": latest_details,
                "is_deployed": model_name in self.current_models
            }
            
            if model_name in self.current_models:
                model_info["deployment_info"] = self.current_models[model_name]
                
            model_details.append(model_info)
            
        return {
            "models": model_details,
            "total_count": len(models),
            "source": source
        }
        
    async def _get_model_details(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """Get detailed information about a specific model."""
        source = request.metadata.get("source", "both") if request.metadata else "both"
        
        details = self.registry_client.get_model_details(
            model_name=request.model_name,
            version=request.model_version or "latest",
            source=source
        )
        
        if not details:
            raise ValueError(f"Model {request.model_name} not found")
            
        # Add deployment status
        details["is_deployed"] = request.model_name in self.current_models
        if request.model_name in self.current_models:
            details["deployment_info"] = self.current_models[request.model_name]
            
        # Add health status
        details["health_status"] = self.model_health.get(request.model_name, "unknown")
        
        # Add metrics if available from MLflow
        if details.get("source") == "mlflow":
            metrics = self.registry_client.get_model_metrics(
                request.model_name, 
                details["version"]
            )
            if metrics:
                details["training_metrics"] = metrics
                
        return details
        
    async def _sync_registries(self, request: ModelManagementMessage) -> Dict[str, Any]:
        """Synchronize file-based and MLflow registries."""
        logger.info("Synchronizing model registries")
        
        sync_results = self.registry_client.sync_registries()
        
        logger.info(f"Registry synchronization completed: {sync_results}")
        return sync_results
        
    async def _monitor_model_health(self):
        """Monitor health of deployed models."""
        while self.is_running:
            try:
                # Check health of deployed models
                for model_name, deployment_info in self.current_models.items():
                    # For now, mark as healthy if recently deployed
                    # In a full implementation, this would check actual model performance
                    deployed_at = datetime.fromisoformat(deployment_info["deployed_at"])
                    age_minutes = (datetime.utcnow() - deployed_at).total_seconds() / 60
                    
                    if age_minutes < 60:  # Consider healthy if deployed within last hour
                        self.model_health[model_name] = "healthy"
                    else:
                        self.model_health[model_name] = "needs_check"
                        
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in model health monitoring: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait longer on error
                
    async def _publish_service_health(self):
        """Publish service health status."""
        while self.is_running:
            try:
                health_message = ServiceHealthMessage(
                    service_name=self.service_name,
                    status="healthy",
                    timestamp=datetime.utcnow().isoformat(),
                    metadata={
                        "deployed_models": len(self.current_models),
                        "healthy_models": len([m for m in self.model_health.values() if m == "healthy"]),
                        "registry_type": "hybrid" if self.registry_client.use_mlflow else "file_only"
                    }
                )
                
                await self.rabbitmq_client.publish(
                    queue=self.service_health_queue,
                    message=health_message.dict()
                )
                
                await asyncio.sleep(30)  # Publish health every 30 seconds
                
            except Exception as e:
                logger.error(f"Error publishing health status: {e}", exc_info=True)
                await asyncio.sleep(60)
                

async def main():
    """Main function to run the Model Management Service."""
    service = ModelManagementService()
    
    # Handle shutdown signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        asyncio.create_task(service.stop())
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await service.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        await service.stop()
        

if __name__ == "__main__":
    asyncio.run(main())
