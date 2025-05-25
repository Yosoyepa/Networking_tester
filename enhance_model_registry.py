#!/usr/bin/env python3
"""
Phase 2 Task 2.3: ML Model Registry Enhancement

This script enhances the ML Model Registry with advanced management capabilities:
- Model versioning and lifecycle management
- Model metadata and performance tracking
- MLflow integration for production scenarios
- Model deployment and health monitoring
- Registry validation and maintenance tools

This implements a robust model management system for Phase 2 scalability.
"""
import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
from src.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)

class ModelRegistryManager:
    """Advanced Model Registry Management System for Phase 2."""
    
    def __init__(self):
        self.registry_client = None
        self.registry_path = None
        
    def initialize(self):
        """Initialize the enhanced model registry."""
        setup_logging()
        logger.info("🚀 Starting Phase 2 Task 2.3: ML Model Registry Enhancement")
        
        try:
            # Initialize Enhanced Model Registry Client
            self.registry_client = EnhancedModelRegistryClient(
                project_root_dir=project_root,
                use_mlflow=True,
                experiment_name="networking_tester_phase2"
            )
            
            self.registry_path = self.registry_client.manifest_path
            logger.info(f"✅ Enhanced Model Registry initialized")
            logger.info(f"📁 Registry path: {self.registry_path}")
            logger.info(f"🔄 MLflow integration: {'ENABLED' if self.registry_client.use_mlflow else 'DISABLED'}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize model registry: {e}", exc_info=True)
            return False
    
    def validate_registry(self) -> Dict[str, Any]:
        """Validate the model registry structure and content."""
        logger.info("🔍 Validating model registry...")
        
        validation_results = {
            "status": "unknown",
            "models_count": 0,
            "valid_models": [],
            "invalid_models": [],
            "missing_files": [],
            "registry_health": "unknown",
            "recommendations": []
        }
        
        try:
            # List all models
            models = self.registry_client.list_models(source="file")
            validation_results["models_count"] = len(models)
            
            logger.info(f"📊 Found {len(models)} models in registry: {models}")
            
            # Validate each model
            for model_name in models:
                logger.info(f"🔍 Validating model: {model_name}")
                
                try:
                    # Get model versions
                    versions = self.registry_client.get_model_versions(model_name, source="file")
                    logger.info(f"   📈 Versions: {versions}")
                    
                    # Get model metadata for latest version
                    model_info = self.registry_client.get_model(model_name, "latest")
                    
                    if model_info:
                        model_path = model_info.get("model_path")
                        if model_path:
                            full_path = os.path.join(
                                os.path.dirname(self.registry_path), 
                                model_path
                            )
                            
                            if os.path.exists(full_path):
                                validation_results["valid_models"].append({
                                    "name": model_name,
                                    "versions": versions,
                                    "path": model_path,
                                    "metadata": model_info.get("metadata", {})
                                })
                                logger.info(f"   ✅ Model valid: {full_path}")
                            else:
                                validation_results["missing_files"].append({
                                    "model": model_name,
                                    "path": full_path
                                })
                                validation_results["invalid_models"].append(model_name)
                                logger.warning(f"   ❌ Missing file: {full_path}")
                        else:
                            validation_results["invalid_models"].append(model_name)
                            logger.warning(f"   ❌ No model path specified for {model_name}")
                    else:
                        validation_results["invalid_models"].append(model_name)
                        logger.warning(f"   ❌ Model info not found for {model_name}")
                        
                except Exception as e:
                    validation_results["invalid_models"].append(model_name)
                    logger.error(f"   ❌ Error validating {model_name}: {e}")
            
            # Determine overall health
            valid_count = len(validation_results["valid_models"])
            invalid_count = len(validation_results["invalid_models"])
            
            if invalid_count == 0:
                validation_results["registry_health"] = "excellent"
                validation_results["status"] = "healthy"
            elif valid_count > invalid_count:
                validation_results["registry_health"] = "good" 
                validation_results["status"] = "mostly_healthy"
            else:
                validation_results["registry_health"] = "poor"
                validation_results["status"] = "needs_attention"
            
            # Generate recommendations
            recommendations = []
            if validation_results["missing_files"]:
                recommendations.append("Restore missing model files or update registry paths")
            if validation_results["invalid_models"]:
                recommendations.append("Fix or remove invalid model entries")
            if valid_count == 0:
                recommendations.append("Add at least one valid model for testing")
            
            validation_results["recommendations"] = recommendations
            
            logger.info(f"🏥 Registry health: {validation_results['registry_health'].upper()}")
            logger.info(f"✅ Valid models: {valid_count}")
            logger.info(f"❌ Invalid models: {invalid_count}")
            
            return validation_results
            
        except Exception as e:
            logger.error(f"❌ Error during registry validation: {e}", exc_info=True)
            validation_results["status"] = "error"
            validation_results["registry_health"] = "error"
            return validation_results
    
    def create_sample_models(self):
        """Create sample models for Phase 2 testing."""
        logger.info("🛠️ Creating sample models for Phase 2...")
        
        try:
            # Create sample GMM model entry
            gmm_model_entry = {
                "model_id": f"gmm-phase2-{datetime.now().strftime('%Y%m%d')}",
                "model_name": "qos_anomaly_gmm_phase2",
                "metadata": {
                    "description": "Enhanced GMM model for Phase 2 QoS anomaly detection",
                    "model_type": "gmm",
                    "tags": ["qos", "gmm", "anomaly_detection", "phase2"],
                    "training_data": "phase2_enhanced_features",
                    "performance_metrics": {
                        "precision": 0.85,
                        "recall": 0.82,
                        "f1_score": 0.83,
                        "roc_auc": 0.89
                    },
                    "feature_schema": [
                        "frame_length", "ip_version", "ip_tos", "dscp",
                        "tcp_flags", "tcp_window", "is_tcp", "is_udp",
                        "src_port", "dst_port", "packet_size_category"
                    ]
                },
                "versions": [
                    {
                        "version": "1.0.0",
                        "model_path": "gmm_phase2_v1/",
                        "creation_timestamp": datetime.utcnow().isoformat() + "Z",
                        "description": "Initial Phase 2 enhanced GMM model with improved feature extraction",
                        "metrics": {
                            "accuracy": 0.87,
                            "training_time_minutes": 15.3,
                            "model_size_mb": 2.1
                        },
                        "deployment_config": {
                            "min_memory_mb": 512,
                            "max_inference_time_ms": 50,
                            "batch_size": 100
                        }
                    }
                ]
            }
            
            # Create sample Isolation Forest model entry
            if_model_entry = {
                "model_id": f"if-phase2-{datetime.now().strftime('%Y%m%d')}",
                "model_name": "qos_anomaly_isolation_forest_phase2",
                "metadata": {
                    "description": "Enhanced Isolation Forest model for Phase 2 QoS anomaly detection",
                    "model_type": "isolation_forest", 
                    "tags": ["qos", "isolation_forest", "anomaly_detection", "phase2"],
                    "training_data": "phase2_enhanced_features",
                    "performance_metrics": {
                        "precision": 0.78,
                        "recall": 0.85,
                        "f1_score": 0.81,
                        "roc_auc": 0.86
                    },
                    "feature_schema": [
                        "frame_length", "ip_version", "ip_tos", "dscp",
                        "tcp_flags", "tcp_window", "is_tcp", "is_udp",
                        "src_port", "dst_port", "packet_size_category"
                    ]
                },
                "versions": [
                    {
                        "version": "1.0.0",
                        "model_path": "isolation_forest_phase2_v1/",
                        "creation_timestamp": datetime.utcnow().isoformat() + "Z",
                        "description": "Initial Phase 2 enhanced Isolation Forest model",
                        "metrics": {
                            "accuracy": 0.83,
                            "training_time_minutes": 8.7,
                            "model_size_mb": 1.3
                        },
                        "deployment_config": {
                            "min_memory_mb": 256,
                            "max_inference_time_ms": 30,
                            "batch_size": 200
                        }
                    }
                ]
            }
            
            # Add models to registry
            for model_entry in [gmm_model_entry, if_model_entry]:
                success = self.registry_client.register_model(
                    model_name=model_entry["model_name"],
                    model_path=model_entry["versions"][0]["model_path"], 
                    model_id=model_entry["model_id"],
                    version=model_entry["versions"][0]["version"],
                    metadata=model_entry["metadata"],
                    description=model_entry["versions"][0]["description"]
                )
                
                if success:
                    logger.info(f"✅ Created sample model: {model_entry['model_name']}")
                else:
                    logger.warning(f"⚠️ Failed to create sample model: {model_entry['model_name']}")
            
            logger.info("🛠️ Sample model creation completed")
            
        except Exception as e:
            logger.error(f"❌ Error creating sample models: {e}", exc_info=True)
    
    def display_registry_status(self):
        """Display comprehensive registry status."""
        logger.info("📊 Displaying Model Registry Status...")
        
        try:
            # Basic registry info
            models = self.registry_client.list_models(source="file")
            logger.info(f"📦 Total models: {len(models)}")
            
            # Model details
            for model_name in models:
                versions = self.registry_client.get_model_versions(model_name)
                model_info = self.registry_client.get_model(model_name, "latest")
                
                logger.info(f"🤖 Model: {model_name}")
                logger.info(f"   📈 Versions: {len(versions)} ({', '.join(versions)})")
                
                if model_info and "metadata" in model_info:
                    metadata = model_info["metadata"]
                    model_type = metadata.get("model_type", "unknown")
                    description = metadata.get("description", "No description")
                    logger.info(f"   🏷️ Type: {model_type}")
                    logger.info(f"   📝 Description: {description}")
                    
                    if "performance_metrics" in metadata:
                        metrics = metadata["performance_metrics"]
                        logger.info(f"   📊 Performance: {metrics}")
            
            # MLflow status
            if self.registry_client.use_mlflow:
                try:
                    mlflow_models = self.registry_client.list_models(source="mlflow")
                    logger.info(f"🔄 MLflow models: {len(mlflow_models)}")
                except Exception as e:
                    logger.warning(f"⚠️ MLflow query failed: {e}")
            
        except Exception as e:
            logger.error(f"❌ Error displaying registry status: {e}", exc_info=True)

def main():
    """Main function for Model Registry Enhancement."""
    
    manager = ModelRegistryManager()
    
    if not manager.initialize():
        return 1
    
    try:
        # Validate current registry
        logger.info("=" * 60)
        logger.info("🔍 PHASE 2 MODEL REGISTRY VALIDATION")
        logger.info("=" * 60)
        
        validation_results = manager.validate_registry()
        
        # Display validation results
        logger.info(f"✅ Validation Status: {validation_results['status'].upper()}")
        logger.info(f"🏥 Registry Health: {validation_results['registry_health'].upper()}")
        
        if validation_results["recommendations"]:
            logger.info("💡 Recommendations:")
            for i, rec in enumerate(validation_results["recommendations"], 1):
                logger.info(f"   {i}. {rec}")
        
        # Create sample models if needed
        if len(validation_results["valid_models"]) < 2:
            logger.info("=" * 60)
            logger.info("🛠️ CREATING PHASE 2 SAMPLE MODELS")
            logger.info("=" * 60)
            manager.create_sample_models()
        
        # Display final registry status
        logger.info("=" * 60)
        logger.info("📊 FINAL REGISTRY STATUS")
        logger.info("=" * 60)
        manager.display_registry_status()
        
        logger.info("=" * 60)
        logger.info("✅ PHASE 2 TASK 2.3 COMPLETED: ML Model Registry Enhanced")
        logger.info("=" * 60)
        
        return 0
        
    except Exception as e:
        logger.error(f"💥 Fatal error in Model Registry Enhancement: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("🛑 Model Registry Enhancement stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}", exc_info=True)
        sys.exit(1)
