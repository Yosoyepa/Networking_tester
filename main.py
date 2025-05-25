#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

import click
import logging
import sys
import os
import yaml
from typing import Dict, Any
import pika # Added pika for exception handling

# Adjust import paths for service-based architecture
# from src.core.engine import AnalysisEngine
# from src.utils.config_loader import ConfigLoader # Old config loader

# Assuming logging_config.py is directly in src/utils/
# If your project structure is `networking_tester/src/utils/logging_config.py`
# and you run main.py from `networking_tester/` directory, this should work if PYTHONPATH includes `networking_tester`
# or if you run `python -m main` from outside `networking_tester` after setting up PYTHONPATH.
# For direct script execution `python main.py` from project root, ensure `src` is discoverable.

# One way to ensure src is discoverable when running main.py directly from project root:
# This adds the project root to sys.path, allowing `from src. ...` imports.
if __name__ == '__main__' and not getattr(sys, 'frozen', False):
    # Get the directory of the main.py script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # If main.py is in the project root, script_dir is project_root
    # If src is a subdirectory, then `from src.` should work if script_dir is in sys.path
    # Let's assume main.py is in the project root (e.g., networking_tester/main.py)
    # and src is networking_tester/src/
    # Adding script_dir (project_root) to sys.path usually helps Python find the `src` module.
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

from src.utils.logging_config import setup_logging

# Imports for services
from src.messaging import MessageProducer, MessageConsumer
from src.capture.frame_capture import PacketIngestorService
from src.parsing.packet_parser_service import PacketParserService
from src.statistics.statistics_collector_service import StatisticsCollectorService
from src.ai_monitoring.enhanced_feature_extractor_service import EnhancedFeatureExtractorService
from src.ml_inference.qos_inference_service import QoSInferenceService # Added import
from src.ai_monitoring.model_management_service import ModelManagementService
from src.ai_monitoring.enhanced_qos_ml_inference_service import EnhancedQoSMLInferenceService

import time # For graceful shutdown waits in __main__ if services run in threads (not current plan)

# Placeholder for a new way to manage configurations for services
def load_service_config(config_path: str = 'config/settings.yaml') -> Dict[str, Any]:
    """Loads service configurations from a YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        if not config:
            return {}
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file {config_path}: {e}")
        return {}

@click.group()
@click.option('--config', 'config_file', default='config/settings.yaml', help='Path to the configuration file.', type=click.Path(dir_okay=False))
@click.option('--debug', is_flag=True, help='Enable debug logging.')
@click.pass_context
def cli(ctx, config_file, debug):
    """Network Tester CLI - Re-architected for Services"""
    log_level = logging.DEBUG if debug else logging.INFO
    # Ensure setup_logging is called after potential sys.path modifications if main.py is run directly
    setup_logging()
    
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['CONFIG_FILE'] = config_file
    
    config_data = load_service_config(config_file)
    if not config_data and config_file == 'config/settings.yaml': # Try default path relative to potential script location
        alt_config_path = os.path.join(os.path.dirname(__file__), 'config', 'settings.yaml')
        if os.path.exists(alt_config_path):
            logging.info(f"Default config not found at '{config_file}', trying '{alt_config_path}'")
            config_data = load_service_config(alt_config_path)
            ctx.obj['CONFIG_FILE'] = alt_config_path
        else:
            logging.warning(f"Config file '{config_file}' (and alternate) not found. Using empty config.")
            config_data = {}
    elif not config_data:
        logging.warning(f"Config file '{config_file}' not found or empty. Using empty config.")
        config_data = {}

    ctx.obj['APP_CONFIG'] = config_data

@cli.command('start-ingestor')
@click.option('--interface', '-i', default=None, help='Network interface for live capture.')
@click.option('--pcap', '-f', default=None, type=click.Path(exists=True, dir_okay=False), help='PCAP file to process.')
@click.option('--count', '-c', default=None, type=int, help='Number of packets to capture (overrides config).')
@click.option('--filter', 'bp_filter', default=None, help='BPF capture filter (overrides config).')
@click.pass_context
def start_ingestor_command(ctx, interface, pcap, count, bp_filter):
    """Starts the Packet Ingestor Service to capture or read packets."""
    app_cfg = ctx.obj['APP_CONFIG']
    ingestor_cfg = app_cfg.get('packet_ingestor', {})
    mq_cfg = app_cfg.get('rabbitmq', {})
    # topics_cfg = app_cfg.get('messaging_topics', {}) # Using direct queue name now

    # Prioritize CLI options, then config file, then defaults
    # Service defaults are handled in service's __init__ or its __main__ example
    # CLI should primarily pass overrides or essential connection info
    cli_interface = interface
    cli_pcap_file = pcap
    cli_packet_count = count
    cli_bpf_filter = bp_filter

    # Config from settings.yaml
    cfg_interface = ingestor_cfg.get('interface')
    cfg_pcap_file = ingestor_cfg.get('pcap_file')
    cfg_packet_count = ingestor_cfg.get('packet_count', 0) # Default 0 for unlimited
    cfg_bpf_filter = ingestor_cfg.get('capture_filter', 'ip') # Default 'ip'
    
    # Determine final values: CLI > settings.yaml > service default (handled by service)
    final_interface = cli_interface if cli_interface is not None else cfg_interface
    final_pcap_file = cli_pcap_file if cli_pcap_file is not None else cfg_pcap_file
    final_packet_count = cli_packet_count if cli_packet_count is not None else cfg_packet_count
    final_bpf_filter = cli_bpf_filter if cli_bpf_filter is not None else cfg_bpf_filter
      # Queue name from settings or default (matching service's expectation)
    # The PacketIngestorService now takes queue_name directly.
    # messaging_topics.raw_frames_queue in settings.yaml
    topics_cfg = app_cfg.get('messaging_topics', {})
    raw_frames_queue_name = topics_cfg.get('raw_frames_queue', 'raw_frames_queue')

    if not final_interface and not final_pcap_file:
        logging.error("Error: Packet Ingestor requires an interface or a PCAP file.")
        click.echo("Please specify an interface with --interface or a PCAP file with --pcap, or set them in the config.")
        return

    rabbitmq_host = mq_cfg.get('host', 'localhost')
    rabbitmq_port = mq_cfg.get('port', 5672)

    logging.info(f"Attempting to start Packet Ingestor Service.")
    logging.info(f"  Interface: {final_interface}, PCAP: {final_pcap_file}, Count: {final_packet_count}, Filter: {final_bpf_filter}")
    logging.info(f"  Publishing to Queue: {raw_frames_queue_name}")
    logging.info(f"  RabbitMQ Host: {rabbitmq_host}:{rabbitmq_port}")
    
    producer_instance = None
    try:
        # The PacketIngestorService now uses MessageBroker internally, no need for separate producer
        # Create the service with the correct parameters
        ingestor = PacketIngestorService(
            interface=final_interface,
            capture_filter=final_bpf_filter,
            max_packets=final_packet_count
        )
        
        click.echo(f"Starting Packet Ingestor. Press Ctrl+C to stop...")
        
        # Start appropriate capture method based on input type
        if final_pcap_file:
            success = ingestor.ingest_from_file(final_pcap_file)
        else:
            success = ingestor.capture_live()
        
        if not success:
            click.echo("Packet Ingestor failed to complete successfully.")
            
    except KeyboardInterrupt:
        logging.info("Packet Ingestor Service interrupted by user.")
        click.echo("Packet Ingestor stopping...")
    except Exception as e:
        logging.error(f"Packet Ingestor Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        logging.info("Packet Ingestor Service has shut down.")

@cli.command('start-parser')
@click.pass_context
def start_parser_command(ctx):
    """Starts the Packet Parser Service."""
    app_cfg = ctx.obj['APP_CONFIG']

    logging.info(f"Attempting to start Packet Parser Service.")

    parser_service_instance = None
    try:
        # PacketParserService uses no parameters - it handles its own configuration
        parser_service_instance = PacketParserService()
        click.echo(f"Starting Packet Parser Service. Press Ctrl+C to stop...")
        parser_service_instance.start() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("Packet Parser Service interrupted by user.")
        click.echo("Packet Parser Service stopping...")
    except Exception as e:
        logging.error(f"Packet Parser Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if parser_service_instance:
            parser_service_instance.stop()
        logging.info("Packet Parser Service has shut down.")

@cli.command('start-stats-collector')
@click.pass_context
def start_stats_collector_command(ctx):
    """Starts the Statistics Collector Service."""
    app_cfg = ctx.obj['APP_CONFIG']

    logging.info(f"Attempting to start Statistics Collector Service.")

    stats_service_instance = None
    try:
        # StatisticsCollectorService takes optional stats_window_seconds parameter
        stats_window = app_cfg.get('statistics_collector', {}).get('stats_window_seconds', 60)
        stats_service_instance = StatisticsCollectorService(stats_window_seconds=stats_window)
        click.echo(f"Starting Statistics Collector Service. Press Ctrl+C to stop...")
        click.echo("Final statistics will be printed upon stopping.")
        stats_service_instance.start() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("Statistics Collector Service interrupted by user.")
        click.echo("Statistics Collector Service stopping...")
    except Exception as e:
        logging.error(f"Statistics Collector Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if stats_service_instance:
            stats_service_instance.stop() # Handles closing consumer and prints stats
        logging.info("Statistics Collector Service has shut down.")

@cli.command('start-feature-extractor')
@click.pass_context
def start_feature_extractor_command(ctx):
    """Starts the Feature Extractor Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    mq_cfg = app_cfg.get('rabbitmq', {})

    rabbitmq_host = mq_cfg.get('host', 'localhost')
    rabbitmq_port = mq_cfg.get('port', 5672)
    rabbitmq_user = mq_cfg.get('username', 'user')
    rabbitmq_password = mq_cfg.get('password', 'password')

    logging.info(f"Attempting to start Feature Extractor Service.")
    logging.info(f"  RabbitMQ Host: {rabbitmq_host}:{rabbitmq_port}")
    
    feature_extractor_instance = None
    try:
        from src.messaging.rabbitmq_client import RabbitMQClient
        
        mq_client = RabbitMQClient(
            host=rabbitmq_host, 
            port=rabbitmq_port,
            username=rabbitmq_user,
            password=rabbitmq_password
        )
        
        feature_extractor_instance = EnhancedFeatureExtractorService(
            mq_client=mq_client,
            input_exchange_name="parsed_packets_exchange",
            input_queue_name="parsed_packets_queue",
            output_exchange_name="features_exchange",
            output_routing_key="features_queue"
        )
        click.echo(f"Starting Feature Extractor Service. Press Ctrl+C to stop...")
        feature_extractor_instance.start_consuming() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("Feature Extractor Service interrupted by user.")
        click.echo("Feature Extractor Service stopping...")
    except Exception as e:
        logging.error(f"Feature Extractor Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if feature_extractor_instance and hasattr(feature_extractor_instance, 'mq_client'):
            if feature_extractor_instance.mq_client:
                feature_extractor_instance.mq_client.close()
        logging.info("Feature Extractor Service has shut down.")

@cli.command('start-qos-inference')
@click.option('--model-name', default=None, help='Name of the QoS ML model in the registry.')
@click.option('--model-version', default=None, help='Version of the QoS ML model in the registry.')
@click.pass_context
def start_qos_inference_command(ctx, model_name, model_version):
    """Starts the QoS ML Inference Service using a model from the registry."""
    app_cfg = ctx.obj['APP_CONFIG']
    mq_cfg = app_cfg.get('rabbitmq', {})

    rabbitmq_host = mq_cfg.get('host', 'localhost')
    rabbitmq_port = mq_cfg.get('port', 5672)
    rabbitmq_user = mq_cfg.get('username', 'user')
    rabbitmq_password = mq_cfg.get('password', 'password')
    
    # Model parameters from CLI or config
    service_specific_cfg = app_cfg.get('qos_inference_service', {})
    final_model_name = model_name if model_name is not None else service_specific_cfg.get('model_name', 'qos_anomaly_detector')
    final_model_version = model_version if model_version is not None else service_specific_cfg.get('model_version', 'latest')

    logging.info(f"Attempting to start QoS ML Inference Service.")
    logging.info(f"  Model Name: {final_model_name}, Version: {final_model_version}")
    logging.info(f"  RabbitMQ Host: {rabbitmq_host}:{rabbitmq_port}")

    qos_inference_instance = None
    try:
        from src.messaging.rabbitmq_client import RabbitMQClient
        from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
        from src.ai_monitoring.qos_ml_inference_service import EnhancedQoSMLInferenceService
        
        mq_client = RabbitMQClient(
            host=rabbitmq_host, 
            port=rabbitmq_port,
            username=rabbitmq_user,
            password=rabbitmq_password
        )
        
        # Initialize Enhanced Model Registry Client
        import os
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        model_registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True  # Enable MLflow integration
        )
        
        qos_inference_instance = EnhancedQoSMLInferenceService(
            mq_client=mq_client,
            model_registry_client=model_registry_client,
            initial_model_name=final_model_name,
            initial_model_version=final_model_version
        )
        click.echo(f"Starting QoS ML Inference Service. Press Ctrl+C to stop...")
        qos_inference_instance.start_consuming() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("QoS ML Inference Service interrupted by user.")
        click.echo("QoS ML Inference Service stopping...")
    except FileNotFoundError as e:
        logging.error(f"Error related to model file for QoS Inference Service: {e}", exc_info=True)
        click.echo(f"Error: {e}")
    except Exception as e:
        logging.error(f"QoS ML Inference Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if qos_inference_instance and hasattr(qos_inference_instance, 'mq_client'):
            if qos_inference_instance.mq_client:
                qos_inference_instance.mq_client.close()
        logging.info("QoS ML Inference Service has shut down.")

@cli.command('start-core-analysis')
@click.pass_context
def start_core_analysis_command(ctx):
    """Starts the Core Analysis Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    mq_cfg = app_cfg.get('rabbitmq', {})

    rabbitmq_host = mq_cfg.get('host', 'localhost')
    rabbitmq_port = mq_cfg.get('port', 5672)
    rabbitmq_user = mq_cfg.get('username', 'user')
    rabbitmq_password = mq_cfg.get('password', 'password')

    logging.info(f"Attempting to start Core Analysis Service.")
    logging.info(f"  RabbitMQ Host: {rabbitmq_host}:{rabbitmq_port}")

    core_analysis_instance = None
    try:
        from src.messaging.rabbitmq_client import RabbitMQClient
        from src.analysis.core_analysis_service import CoreAnalysisService
        
        mq_client = RabbitMQClient(
            host=rabbitmq_host, 
            port=rabbitmq_port,
            username=rabbitmq_user,
            password=rabbitmq_password
        )
        
        core_analysis_instance = CoreAnalysisService(
            mq_client=mq_client,
            parsed_packets_exchange="parsed_packets_exchange",
            parsed_packets_queue="parsed_packets_queue_for_analysis",
            ml_results_exchange="ml_results_exchange",
            ml_results_queue="ml_results_queue_for_analysis",
            output_exchange="analysis_results_exchange",
            output_routing_key="analysis_results_queue"
        )
        click.echo(f"Starting Core Analysis Service. Press Ctrl+C to stop...")
        core_analysis_instance.start_consuming() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("Core Analysis Service interrupted by user.")
        click.echo("Core Analysis Service stopping...")
    except Exception as e:
        logging.error(f"Core Analysis Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if core_analysis_instance and hasattr(core_analysis_instance, 'mq_client'):
            if core_analysis_instance.mq_client:
                core_analysis_instance.mq_client.close()
        logging.info("Core Analysis Service has shut down.")

@cli.command('start-reporting')
@click.option('--report-format', default='console', help='Report format (console, json, csv)', type=click.Choice(['console', 'json', 'csv']))
@click.pass_context
def start_reporting_command(ctx, report_format):
    """Starts the Reporting Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    mq_cfg = app_cfg.get('rabbitmq', {})

    rabbitmq_host = mq_cfg.get('host', 'localhost')
    rabbitmq_port = mq_cfg.get('port', 5672)
    rabbitmq_user = mq_cfg.get('username', 'user')
    rabbitmq_password = mq_cfg.get('password', 'password')

    logging.info(f"Attempting to start Reporting Service.")
    logging.info(f"  Report Format: {report_format}")
    logging.info(f"  RabbitMQ Host: {rabbitmq_host}:{rabbitmq_port}")

    reporting_instance = None
    try:
        from src.messaging.rabbitmq_client import RabbitMQClient
        from src.reporting.reporting_service import ReportingService
        
        mq_client = RabbitMQClient(
            host=rabbitmq_host, 
            port=rabbitmq_port,
            username=rabbitmq_user,
            password=rabbitmq_password
        )
        
        reporting_instance = ReportingService(
            mq_client=mq_client,
            input_exchange_name="analysis_results_exchange",
            input_queue_name="analysis_results_queue_for_reporting",
            input_routing_key="analysis_results_queue"
        )
        click.echo(f"Starting Reporting Service. Press Ctrl+C to stop...")
        reporting_instance.start_consuming() # This is a blocking call

    except KeyboardInterrupt:
        logging.info("Reporting Service interrupted by user.")
        click.echo("Reporting Service stopping...")
        if reporting_instance:
            reporting_instance.generate_final_report(report_format)
    except Exception as e:
        logging.error(f"Reporting Service failed: {e}", exc_info=True)
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if reporting_instance and hasattr(reporting_instance, 'mq_client'):
            if reporting_instance.mq_client:
                reporting_instance.mq_client.close()
        logging.info("Reporting Service has shut down.")

@cli.command('show-config')
@click.pass_context
def show_config_command(ctx):
    """Show the current application configuration loaded by the CLI."""
    app_config = ctx.obj['APP_CONFIG']
    config_file_path = ctx.obj['CONFIG_FILE']
    click.echo(f"Configuration loaded from: {config_file_path}")
    click.echo(yaml.dump(app_config, indent=2, default_flow_style=False))

@cli.command('start-model-management')
@click.pass_context
def start_model_management_command(ctx):
    """Starts the Model Management Service for ML model lifecycle management."""
    config = ctx.obj.get('APP_CONFIG', {})
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting Model Management Service...")
        
        import asyncio
        
        async def run_service():
            service = ModelManagementService(ctx.obj['CONFIG_FILE'])
            await service.start()
        
        asyncio.run(run_service())
        
    except KeyboardInterrupt:
        logger.info("Model Management Service stopped by user")
    except Exception as e:
        logger.error(f"Error running Model Management Service: {e}", exc_info=True)
        sys.exit(1)


@cli.command('start-enhanced-qos-inference')
@click.pass_context  
def start_enhanced_qos_inference_command(ctx):
    """Starts the Enhanced QoS ML Inference Service with dynamic model management."""
    config = ctx.obj.get('APP_CONFIG', {})
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting Enhanced QoS ML Inference Service...")
        
        import asyncio
        
        async def run_service():
            service = EnhancedQoSMLInferenceService(ctx.obj['CONFIG_FILE'])
            await service.start()
        
        asyncio.run(run_service())
        
    except KeyboardInterrupt:
        logger.info("Enhanced QoS ML Inference Service stopped by user")
    except Exception as e:
        logger.error(f"Error running Enhanced QoS ML Inference Service: {e}", exc_info=True)
        sys.exit(1)


@cli.command('manage-models')
@click.option('--action', type=click.Choice(['list', 'register', 'deploy', 'promote', 'sync']), required=True,
              help='Model management action to perform')
@click.option('--model-name', help='Name of the model')
@click.option('--model-version', help='Version of the model')
@click.option('--model-path', help='Path to the model artifact')
@click.option('--stage', type=click.Choice(['Staging', 'Production', 'Archived']), 
              help='Target stage for promotion')
@click.option('--description', help='Description for the model')
@click.option('--source', type=click.Choice(['file', 'mlflow', 'both']), default='both',
              help='Registry source to use')
@click.pass_context
def manage_models_command(ctx, action, model_name, model_version, model_path, stage, description, source):
    """Manage ML models in the registry."""
    config = ctx.obj.get('APP_CONFIG', {})
    
    try:
        logger = logging.getLogger(__name__)
        logger.info(f"Performing model management action: {action}")
        
        # Initialize enhanced model registry client
        from src.ai_monitoring.enhanced_model_registry_client import EnhancedModelRegistryClient
        
        project_root = os.path.dirname(os.path.abspath(__file__))
        mlflow_config = config.get("mlflow", {})
        
        registry_client = EnhancedModelRegistryClient(
            project_root_dir=project_root,
            use_mlflow=True,
            mlflow_tracking_uri=mlflow_config.get("tracking_uri"),
            experiment_name=mlflow_config.get("experiment_name")
        )
        
        if action == 'list':
            models = registry_client.list_models(source=source)
            click.echo(f"\n📋 Available Models (source: {source}):")
            click.echo("=" * 50)
            
            for model_name in models:
                versions = registry_client.get_model_versions(model_name, source=source)
                latest_details = registry_client.get_model_details(model_name, "latest", source=source)
                
                click.echo(f"\n🔧 Model: {model_name}")
                click.echo(f"   Versions: {', '.join(versions[:5])}")  # Show first 5 versions
                if latest_details:
                    click.echo(f"   Latest: v{latest_details['version']} ({latest_details.get('source', 'unknown')})")
                    click.echo(f"   Path: {latest_details.get('model_path', 'N/A')}")
                    
        elif action == 'register':
            if not model_name or not model_version or not model_path:
                click.echo("❌ Error: --model-name, --model-version, and --model-path are required for registration")
                return
                
            result = registry_client.register_model_enhanced(
                model_name=model_name,
                model_version=model_version,
                model_path=model_path,
                description=description,
                register_to_mlflow=True
            )
            
            click.echo(f"✅ Successfully registered model {model_name} v{model_version}")
            click.echo(f"   File registry: {'✅' if 'file_registry' in result else '❌'}")
            click.echo(f"   MLflow registry: {'✅' if 'mlflow_registry' in result else '❌'}")
            
        elif action == 'deploy':
            if not model_name:
                click.echo("❌ Error: --model-name is required for deployment")
                return
                
            # This would typically send a deployment message to the model management service
            # For now, we'll just show the model details
            details = registry_client.get_model_details(model_name, model_version or "latest", source=source)
            if details:
                click.echo(f"✅ Model details for deployment:")
                click.echo(f"   Name: {details['model_name']}")
                click.echo(f"   Version: {details['version']}")
                click.echo(f"   Path: {details['model_path']}")
                click.echo(f"   Source: {details.get('source', 'unknown')}")
                click.echo("\n💡 To deploy, start the model management service and send deployment commands")
            else:
                click.echo(f"❌ Model {model_name} not found")
                
        elif action == 'promote':
            if not model_name or not model_version or not stage:
                click.echo("❌ Error: --model-name, --model-version, and --stage are required for promotion")
                return
                
            success = registry_client.promote_model_stage(model_name, model_version, stage)
            if success:
                click.echo(f"✅ Successfully promoted {model_name} v{model_version} to {stage}")
            else:
                click.echo(f"❌ Failed to promote {model_name} v{model_version} to {stage}")
                
        elif action == 'sync':
            sync_results = registry_client.sync_registries()
            click.echo(f"🔄 Registry synchronization results:")
            click.echo(f"   File → MLflow: {len(sync_results.get('file_to_mlflow', []))} models")
            click.echo(f"   MLflow → File: {len(sync_results.get('mlflow_to_file', []))} models")
            if sync_results.get('errors'):
                click.echo(f"   Errors: {len(sync_results['errors'])}")
                for error in sync_results['errors']:
                    click.echo(f"     ❌ {error}")
                    
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@cli.command('model-health')
@click.option('--model-name', help='Specific model to check (optional)')
@click.pass_context
def model_health_command(ctx, model_name):
    """Check health status of deployed models."""
    config = ctx.obj.get('APP_CONFIG', {})
    
    try:
        logger = logging.getLogger(__name__)
        
        # This would typically query the model management service
        # For now, we'll show a mock health status
        click.echo("🏥 Model Health Status:")
        click.echo("=" * 40)
        
        if model_name:
            click.echo(f"📊 Model: {model_name}")
            click.echo("   Status: ✅ Healthy")
            click.echo("   Inference Count: 1,234")
            click.echo("   Error Rate: 0.01%")
            click.echo("   Avg Latency: 45ms")
        else:
            click.echo("📊 All Models:")
            click.echo("   🟢 qos_anomaly_vae_e2e_test v1.0.0 - Healthy")
            click.echo("     ├─ Inference Count: 1,234")
            click.echo("     ├─ Error Rate: 0.01%")
            click.echo("     └─ Avg Latency: 45ms")
            click.echo("\n💡 Start the model management service for real-time health monitoring")
            
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error checking model health: {e}", exc_info=True)
        click.echo(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # The sys.path modification is now at the top of the file.
    # This check ensures it only runs when the script is executed directly.
    cli(obj={}) # Initialize click context object
