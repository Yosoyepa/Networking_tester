#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced CLI for networking_tester with distributed architecture support.
Manages services orchestration and provides unified interface.
"""

import click
import logging
import sys
import os
import time
import threading
import subprocess
import signal
from typing import Dict, Any, List, Optional
import yaml

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from src.capture.frame_capture import PacketIngestorService
from src.parsing.packet_parser_service import PacketParserService
from src.statistics.statistics_collector_service import StatisticsCollectorService
from src.messaging.message_broker import MessageBroker
from src.messaging.schemas import MessageSchemas
from src.utils.simple_logging import setup_logging


class ServiceOrchestrator:
    """Orchestrates the lifecycle of distributed services."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.services = {}
        self.service_threads = {}
        self.is_running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down services...")
        self.stop_all_services()
    
    def start_packet_ingestor(self, interface: Optional[str] = None, 
                             pcap_file: Optional[str] = None,
                             max_packets: int = 0,
                             capture_filter: Optional[str] = None) -> bool:
        """Start the packet ingestor service."""
        try:
            if 'ingestor' in self.services:
                self.logger.warning("Packet ingestor already running")
                return False
            
            service = PacketIngestorService(
                interface=interface,
                capture_filter=capture_filter,
                max_packets=max_packets
            )
            
            def run_ingestor():
                try:
                    if pcap_file:
                        service.ingest_from_file(pcap_file)
                    else:
                        service.capture_live()
                except Exception as e:
                    self.logger.error(f"Error in packet ingestor: {e}")
            
            thread = threading.Thread(target=run_ingestor, daemon=True)
            thread.start()
            
            self.services['ingestor'] = service
            self.service_threads['ingestor'] = thread
            
            self.logger.info("Packet ingestor service started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet ingestor: {e}")
            return False
    
    def start_packet_parser(self) -> bool:
        """Start the packet parser service."""
        try:
            if 'parser' in self.services:
                self.logger.warning("Packet parser already running")
                return False
            
            service = PacketParserService()
            
            def run_parser():
                try:
                    service.start()
                except Exception as e:
                    self.logger.error(f"Error in packet parser: {e}")
            
            thread = threading.Thread(target=run_parser, daemon=True)
            thread.start()
            
            self.services['parser'] = service
            self.service_threads['parser'] = thread
            
            self.logger.info("Packet parser service started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet parser: {e}")
            return False
    
    def start_statistics_collector(self, stats_window: int = 60) -> bool:
        """Start the statistics collector service."""
        try:
            if 'statistics' in self.services:
                self.logger.warning("Statistics collector already running")
                return False
            
            service = StatisticsCollectorService(stats_window_seconds=stats_window)
            
            def run_statistics():
                try:
                    service.start()
                except Exception as e:
                    self.logger.error(f"Error in statistics collector: {e}")
            
            thread = threading.Thread(target=run_statistics, daemon=True)
            thread.start()
            
            self.services['statistics'] = service
            self.service_threads['statistics'] = thread
            
            self.logger.info("Statistics collector service started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start statistics collector: {e}")
            return False
    
    def start_all_services(self, interface: Optional[str] = None,
                          pcap_file: Optional[str] = None,
                          max_packets: int = 0,
                          capture_filter: Optional[str] = None,
                          stats_window: int = 60) -> bool:
        """Start all services in the correct order."""
        try:
            self.is_running = True
            
            # Start services in dependency order
            self.logger.info("Starting distributed services...")
            
            # 1. Start packet parser (consumer)
            if not self.start_packet_parser():
                return False
            
            # 2. Start statistics collector (consumer)
            if not self.start_statistics_collector(stats_window):
                return False
            
            # Wait a moment for consumers to be ready
            time.sleep(2)
            
            # 3. Start packet ingestor (producer)
            if not self.start_packet_ingestor(interface, pcap_file, max_packets, capture_filter):
                return False
            
            self.logger.info("All services started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start all services: {e}")
            self.stop_all_services()
            return False
    
    def stop_service(self, service_name: str):
        """Stop a specific service."""
        if service_name in self.services:
            try:
                self.services[service_name].stop()
                self.logger.info(f"Stopped {service_name} service")
            except Exception as e:
                self.logger.error(f"Error stopping {service_name}: {e}")
            finally:
                del self.services[service_name]
                if service_name in self.service_threads:
                    del self.service_threads[service_name]
    
    def stop_all_services(self):
        """Stop all running services."""
        self.is_running = False
        self.logger.info("Stopping all services...")
        
        for service_name in list(self.services.keys()):
            self.stop_service(service_name)
        
        self.logger.info("All services stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all services."""
        status = {
            'orchestrator_running': self.is_running,
            'services': {}
        }
        
        for name, service in self.services.items():
            try:
                status['services'][name] = service.get_status()
            except Exception as e:
                status['services'][name] = {'error': str(e)}
        
        return status
    
    def wait_for_completion(self, check_interval: int = 5):
        """Wait for all services to complete."""
        try:
            while self.is_running and any(thread.is_alive() for thread in self.service_threads.values()):
                time.sleep(check_interval)
                
                # Print status periodically
                status = self.get_status()
                self.logger.info(f"Services status: {status}")
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt, stopping services...")
            self.stop_all_services()


# Global orchestrator instance
orchestrator = ServiceOrchestrator()


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config if config else {}
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file {config_path}: {e}")
        return {}


@click.group()
@click.option('--config', 'config_file', default='config/settings.yaml', 
              help='Path to the configuration file.', type=click.Path())
@click.option('--debug', is_flag=True, help='Enable debug logging.')
@click.pass_context
def cli(ctx, config_file, debug):
    """networking_tester CLI - Distributed Architecture"""
    log_level = logging.DEBUG if debug else logging.INFO
    setup_logging(log_level=log_level)
    
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['CONFIG_FILE'] = config_file
    
    # Load configuration
    config_data = load_config(config_file)
    ctx.obj['APP_CONFIG'] = config_data


@cli.command('capture')
@click.option('--interface', '-i', help='Network interface for live capture.')
@click.option('--file', '-f', help='PCAP file to process.', type=click.Path(exists=True))
@click.option('--count', '-c', type=int, default=0, help='Number of packets to capture (0 = unlimited).')
@click.option('--filter', help='BPF capture filter.')
@click.option('--stats-window', type=int, default=60, help='Statistics window in seconds.')
@click.option('--services-only', is_flag=True, help='Start only parser and statistics services.')
@click.pass_context
def capture_command(ctx, interface, file, count, filter, stats_window, services_only):
    """Start packet capture and analysis pipeline."""
    try:
        if services_only:
            # Start only parser and statistics services
            click.echo("Starting parser and statistics services only...")
            
            if not orchestrator.start_packet_parser():
                click.echo("Failed to start packet parser", err=True)
                return
                
            if not orchestrator.start_statistics_collector(stats_window):
                click.echo("Failed to start statistics collector", err=True)
                return
                
            click.echo("Services started. Press Ctrl+C to stop.")
            
        else:
            # Start full pipeline
            click.echo("Starting full packet analysis pipeline...")
            
            if not orchestrator.start_all_services(
                interface=interface,
                pcap_file=file,
                max_packets=count,
                capture_filter=filter,
                stats_window=stats_window
            ):
                click.echo("Failed to start services", err=True)
                return
            
            click.echo("All services started. Press Ctrl+C to stop.")
        
        # Wait for completion
        orchestrator.wait_for_completion()
        
    except KeyboardInterrupt:
        click.echo("\nShutdown requested by user")
    finally:
        orchestrator.stop_all_services()


@cli.command('status')
def status_command():
    """Show status of all services."""
    status = orchestrator.get_status()
    
    click.echo("=== Services Status ===")
    click.echo(f"Orchestrator Running: {status['orchestrator_running']}")
    click.echo()
    
    if not status['services']:
        click.echo("No services running")
        return
    
    for service_name, service_status in status['services'].items():
        click.echo(f"{service_name.upper()} Service:")
        if 'error' in service_status:
            click.echo(f"  Error: {service_status['error']}")
        else:
            for key, value in service_status.items():
                click.echo(f"  {key}: {value}")
        click.echo()


@cli.command('stop')
@click.option('--service', help='Stop specific service (ingestor, parser, statistics)')
def stop_command(service):
    """Stop services."""
    if service:
        orchestrator.stop_service(service)
        click.echo(f"Stopped {service} service")
    else:
        orchestrator.stop_all_services()
        click.echo("Stopped all services")


@cli.command('test-connection')
def test_connection_command():
    """Test RabbitMQ connection."""
    try:
        broker = MessageBroker()
        if broker.connect():
            click.echo("✓ Successfully connected to RabbitMQ")
            
            # Test queue setup
            if broker.setup_queues(MessageSchemas.get_queue_names()):
                click.echo("✓ Successfully setup all queues")
            else:
                click.echo("✗ Failed to setup queues")
                
            broker.disconnect()
        else:
            click.echo("✗ Failed to connect to RabbitMQ")
            
    except Exception as e:
        click.echo(f"✗ Connection test failed: {e}")


@cli.command('list-queues')
def list_queues_command():
    """List all message queues."""
    click.echo("=== Message Queues ===")
    for queue_name in MessageSchemas.get_queue_names():
        click.echo(f"  - {queue_name}")


if __name__ == '__main__':
    cli()
