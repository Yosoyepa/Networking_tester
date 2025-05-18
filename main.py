#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

import click
import logging
import sys
import os
import yaml
from typing import Dict, Any

# Adjust import paths for service-based architecture
# from src.core.engine import AnalysisEngine
# from src.utils.config_loader import ConfigLoader # Old config loader

# Assuming logger_config.py is directly in src/utils/
# If your project structure is `networking_tester/src/utils/logger_config.py`
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

from src.utils.logger_config import setup_logging

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
    setup_logging(log_level=log_level) 
    
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
    """(Conceptual) Start the Packet Ingestor Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    ingestor_cfg = app_cfg.get('packet_ingestor', {})
    mq_cfg = app_cfg.get('rabbitmq', {})
    topics_cfg = app_cfg.get('messaging_topics', {})

    # Prioritize CLI options, then config file, then defaults
    interface = interface if interface is not None else ingestor_cfg.get('interface')
    pcap_file = pcap if pcap is not None else ingestor_cfg.get('pcap_file')
    packet_count = count if count is not None else ingestor_cfg.get('packet_count', 0)
    bpf_filter = bp_filter if bp_filter is not None else ingestor_cfg.get('capture_filter', 'ip')
    
    exchange_name = topics_cfg.get('raw_frames_exchange', 'raw_frames_exchange')
    raw_frames_queue = topics_cfg.get('raw_frames_queue', 'raw_frames_queue') 

    if not interface and not pcap_file:
        logging.error("Error: Packet Ingestor requires an interface or a PCAP file.")
        click.echo("Please specify an interface with --interface or a PCAP file with --pcap, or set them in the config.")
        return

    logging.info(f"CLI: Requesting to start Packet Ingestor.")
    logging.info(f"  Interface: {interface}, PCAP: {pcap_file}, Count: {packet_count}, Filter: {bpf_filter}")
    logging.info(f"  Publishing to Exchange: {exchange_name}, Routing Key/Queue: {raw_frames_queue}")
    logging.info(f"  RabbitMQ Host: {mq_cfg.get('host', 'localhost')}:{mq_cfg.get('port', 5672)}")
    
    click.echo("Conceptual command: This would typically send a message to start the Packet Ingestor Service or use a service orchestrator.")
    click.echo("To run locally for development (ensure RabbitMQ is running and configured in settings.yaml):")
    click.echo(f"  python -m src.capture.frame_capture")
    click.echo("  (Ensure the __main__ block in frame_capture.py reads from settings.yaml or is pre-configured)")

@cli.command('start-parser')
@click.pass_context
def start_parser_command(ctx):
    """(Conceptual) Start the Packet Parser Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    # parser_cfg = app_cfg.get('packet_parser', {}) # If parser has specific config
    mq_cfg = app_cfg.get('rabbitmq', {})
    topics_cfg = app_cfg.get('messaging_topics', {})

    input_exchange = topics_cfg.get('raw_frames_exchange', 'raw_frames_exchange')
    input_queue = topics_cfg.get('raw_frames_queue', 'raw_frames_queue')
    output_exchange = topics_cfg.get('parsed_packets_exchange', 'parsed_packets_exchange')
    output_routing_key = topics_cfg.get('parsed_packets_queue', 'parsed_packets_queue')

    logging.info(f"CLI: Requesting to start Packet Parser Service.")
    logging.info(f"  Consuming from Exchange: {input_exchange}, Queue: {input_queue}")
    logging.info(f"  Publishing to Exchange: {output_exchange}, Routing Key/Queue: {output_routing_key}")
    logging.info(f"  RabbitMQ Host: {mq_cfg.get('host', 'localhost')}:{mq_cfg.get('port', 5672)}")
    click.echo("Conceptual command: This would start the Packet Parser Service.")
    click.echo("To run locally for development (ensure RabbitMQ is running and configured in settings.yaml):")
    click.echo(f"  python -m src.analysis.packet_parser_service")
    click.echo("  (Ensure the __main__ block in packet_parser_service.py reads from settings.yaml or is pre-configured)")

@cli.command('start-stats-collector')
@click.pass_context
def start_stats_collector_command(ctx):
    """(Conceptual) Start the Statistics Collector Service."""
    app_cfg = ctx.obj['APP_CONFIG']
    stats_cfg = app_cfg.get('statistics_collector', {})
    mq_cfg = app_cfg.get('rabbitmq', {})
    topics_cfg = app_cfg.get('messaging_topics', {})

    input_exchange = topics_cfg.get('parsed_packets_exchange', 'parsed_packets_exchange')
    input_queue = topics_cfg.get('parsed_packets_queue', 'parsed_packets_queue')
    log_interval = stats_cfg.get('log_interval_seconds', 60)

    logging.info(f"CLI: Requesting to start Statistics Collector Service.")
    logging.info(f"  Consuming from Exchange: {input_exchange}, Queue: {input_queue}")
    logging.info(f"  Log Interval: {log_interval}s")
    logging.info(f"  RabbitMQ Host: {mq_cfg.get('host', 'localhost')}:{mq_cfg.get('port', 5672)}")
    click.echo("Conceptual command: This would start the Statistics Collector Service.")
    click.echo("To run locally for development (ensure RabbitMQ is running and configured in settings.yaml):")
    click.echo(f"  python -m src.analysis.statistics_collector_service")
    click.echo("  (Ensure the __main__ block in statistics_collector_service.py reads from settings.yaml or is pre-configured)")

@cli.command('show-config')
@click.pass_context
def show_config_command(ctx):
    """Show the current application configuration loaded by the CLI."""
    app_config = ctx.obj['APP_CONFIG']
    config_file_path = ctx.obj['CONFIG_FILE']
    click.echo(f"Configuration loaded from: {config_file_path}")
    click.echo(yaml.dump(app_config, indent=2, default_flow_style=False))


if __name__ == '__main__':
    # The sys.path modification is now at the top of the file.
    # This check ensures it only runs when the script is executed directly.
    cli(obj={}) # Initialize click context object
