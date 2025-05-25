#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Handles the command-line menu interface for Networking Tester."""
import logging
import yaml
import argparse
import shlex
import os
import sys
import subprocess
import time
from pathlib import Path
import pika

from src.messaging import MessageProducer
from src.capture.frame_capture import PacketIngestorService
from src.utils.logging_config import setup_logging
from src.ui.queue_monitor import run_diagnostics, QueueMonitor
from src.ui.report_service_client import process_reports
from src.ui.docker_service_manager import manage_docker_services
from src.ui.reporting_service_fixer import fix_reporting_pipeline

logger = logging.getLogger(__name__)

# Added: Configuration loading function
def load_app_config(config_path="config/settings.yaml") -> dict:
    """Loads application configuration from a YAML file."""
    project_root = Path(__file__).resolve().parent.parent.parent
    full_config_path = project_root / config_path
    try:
        with open(full_config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        if not config: # Check if config is None or empty
            logger.warning(f"Configuration file {full_config_path} is empty or could not be parsed correctly. Returning empty dict.")
            return {} # Return an empty dict if loading failed or file is empty
        logger.info(f"Application configuration loaded successfully from {full_config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {full_config_path}. Cannot proceed without configuration. Returning empty dict.")
        return {} # Return an empty dict if file not found
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration from {full_config_path}: {e}. Returning empty dict.")
        return {} # Return an empty dict on YAML error

def print_project_examples(project_name):
    """Prints command-line examples."""
    examples = f"""
{project_name} - Command-Line Examples:

1. Live Capture (Default Interface, Unlimited Packets/Time, Console Report):
   Select 'Start Live Capture' and press Enter for defaults, or type options.
   Example: -c 50 (captures 50 packets)

2. Live Capture on a Specific Interface (e.g., 'Ethernet 2') for 50 Packets:
   Select 'Start Live Capture' then: -i "Ethernet 2" -c 50

3. Live Capture with a Timeout (e.g., 60 seconds) and JSON Report:
   Select 'Start Live Capture' then: -t 60 --report-format json

4. Live Capture with a BPF Filter (e.g., TCP traffic on port 443):
   Select 'Start Live Capture' then: -f "tcp port 443"

5. Live Capture and Save Packets to a File (e.g., 'live_capture.pcap'):
   Select 'Start Live Capture' then: -w live_capture.pcap

6. Analyze an Existing PCAP File and Generate a CSV Report:
   Select 'Analyze PCAP File' then: -r data/captures/my_capture.pcap --report-format csv
   Or just: data/captures/my_capture.pcap (if it's the only argument)

For more details on BPF syntax, refer to tcpdump documentation.
Interface names can vary by system (e.g., 'eth0', 'en0', 'Ethernet', 'Wi-Fi').
Default settings for interface, report format, etc., can be configured in 'config/settings.yaml'.
"""
    print(examples)

def display_splash_screen(project_name, version):
    """Displays a splash screen."""
    splash = f"""
+------------------------------------------------------------+
|                                                            |
|         ██╗  ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗      |
|         ███╗ ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝      |
|         ████╗██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝       |
|         ██╔██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗      |
|         ██║╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗     |
|                                                            |
|         ████████╗███████╗███████╗████████╗███████╗██████╗       |
|         ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗      |
|            ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝      |
|            ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗      |
|            ██║   ███████╗███████║   ██║   ███████╗██║  ██║      |
|            ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      |
|                                                            |
+------------------------------------------------------------+
|         {f'{project_name} v{version}':^44}         |
|         {'by Juan Carlos Andrade':^44}         |
+------------------------------------------------------------+
"""
    print(splash)

def display_main_menu_and_get_choice():
    """Displays the main menu and gets the user's choice."""
    print("\n--- Networking Tester Main Menu ---")
    print("1. Start Live Packet Capture")
    print("2. Analyze PCAP File")
    print("3. Configure Settings (Not Implemented)")
    print("4. View System Status (Diagnostics)")
    print("5. Print Command-Line Examples")
    print("6. Analyze Session with AI (Under Reconstruction)") 
    print("7. Train AI Anomaly Model (Under Reconstruction)") 
    print("8. Generate Reports from Last Processing")
    print("9. Manage Docker Services")  # New option for Docker services
    print("10. Exit")
    while True:
        try:
            choice = input("Enter your choice (1-10): ")
            if choice.isdigit() and 1 <= int(choice) <= 10:
                return int(choice)
            elif choice.lower() in ['exit', 'quit']:
                return 10
            else:
                print("Invalid choice. Please enter a number between 1 and 10.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nExiting...")
            return 10

def _create_arg_parser(project_name, version, for_live_capture=True):
    """Creates an argument parser instance."""
    parser = argparse.ArgumentParser(
        prog="", # Clears 'main.py' from usage in sub-prompt help
        description=f"{project_name} v{version} - Network Traffic Analyzer",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False # Help is triggered manually or via a specific -h
    )
    parser.add_argument(
        '-h', '--help',
        action='help',
        help="Show this help message and exit."
    )
    if for_live_capture:
        parser.add_argument(
            '-i', '--interface',
            type=str,
            help="Network interface for live capture (e.g., 'eth0', \"Wi-Fi\").\n'auto' or omit for default."
        )
        parser.add_argument(
            '-c', '--count',
            type=int,
            default=0,
            help="Max packets to capture. 0 for unlimited. Default: 0."
        )
        parser.add_argument(
            '-t', '--timeout',
            type=int,
            help="Duration in seconds for live capture. No default."
        )
        parser.add_argument(
            '-w', '--write',
            type=str,
            metavar="PCAP_FILE_OUTPUT",
            help="Save captured packets to a PCAP file (e.g., 'output.pcap')."
        )
        parser.add_argument(
            '-f', '--filter',
            type=str,
            help="BPF filter for live capture (e.g., 'tcp port 80')."
        )
    else: # For PCAP analysis
        parser.add_argument(
            '-r', '--read',
            type=str,
            metavar="PCAP_FILE_INPUT",
            required=True, # Make it required for this mode if called with -r
            help="Path to a PCAP file to read and analyze."
        )
        # Allow a positional argument for the PCAP file as well
        parser.add_argument(
            'pcap_file_positional',
            type=str,
            nargs='?', # Optional positional argument
            help="Path to a PCAP file (alternative to -r)."
        )


    parser.add_argument(
        '--report-format',
        type=str,
        choices=['console', 'json', 'csv'],
        help="Output report format. Overrides 'config/settings.yaml'."
    )
    return parser

def handle_live_capture(config, project_name, version):
    """Handles the live capture option by initiating PacketIngestorService."""
    parser = _create_arg_parser(project_name, version, for_live_capture=True)
    arg_string = input(f"\nEnter live capture arguments (e.g., -i \"Ethernet 2\" -c 10 -w my_capture.pcap), or -h for help:\n> ")
    try:
        args_list = shlex.split(arg_string)
        args = parser.parse_args(args_list)

        # Extract RabbitMQ config, providing defaults if not found
        rabbitmq_config = config.get('rabbitmq', {})
        rabbitmq_host = rabbitmq_config.get('host', 'localhost')
        rabbitmq_port = rabbitmq_config.get('port', 5672)
        rabbitmq_user = rabbitmq_config.get('user')
        rabbitmq_password = rabbitmq_config.get('password')

        # Default queue name, can be made configurable if needed
        queue_name = config.get('capture', {}).get('default_raw_frames_queue', "raw_frames_queue")

        # Prepare output pcap path if specified
        output_pcap_path_final = None
        if args.write:
            raw_output_path = args.write
            # If path is relative and has no directory part, prepend default capture data path
            if not os.path.isabs(raw_output_path) and not os.path.dirname(raw_output_path):
                default_pcap_save_dir = Path(__file__).resolve().parent.parent.parent / "data" / "captures"
                output_pcap_path_final = default_pcap_save_dir / raw_output_path
            else:
                output_pcap_path_final = Path(raw_output_path)
            
            # Ensure directory exists
            output_pcap_dir = output_pcap_path_final.parent
            if not output_pcap_dir.exists():
                output_pcap_dir.mkdir(parents=True, exist_ok=True)
            output_pcap_path_final = str(output_pcap_path_final)

        producer = MessageProducer(
            rabbitmq_host=rabbitmq_host, 
            rabbitmq_port=rabbitmq_port, 
            rabbitmq_user=rabbitmq_user, 
            rabbitmq_password=rabbitmq_password
        )
        
        ingestor = PacketIngestorService(
            producer=producer,
            interface=args.interface if args.interface else config.get('capture', {}).get('default_interface'),
            packet_count=args.count,
            capture_filter=args.filter if args.filter else "ip", # Default to "ip" if not provided
            output_pcap_file=output_pcap_path_final,
            queue_name=queue_name
        )
        logger.info("Starting live capture...")
        ingestor.run() # Changed from start_capture to run
        logger.info("Live capture finished. Packets are being processed by backend services.")
        if output_pcap_path_final:
            logger.info(f"Captured packets saved to: {output_pcap_path_final}")

    except argparse.ArgumentError as e:
        logger.error(f"Argument error: {e}")
        # parser.print_help() # Optionally print help on error
    except PermissionError:
        logger.error("Permission denied. Try running with elevated privileges for live capture.")
    except OSError as e:
        logger.error(f"OS error during live capture (e.g., interface not found or not up): {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during live capture setup or execution: {e}", exc_info=True)


def handle_pcap_analysis(config, project_name, version):
    """Handles PCAP analysis by initiating PacketIngestorService."""
    parser = _create_arg_parser(project_name, version, for_live_capture=False)
    arg_string = input(f"\nEnter PCAP file path (e.g., my_capture.pcap [looks in data/captures/], or full path) and options, or -h for help:\n> ")
    try:
        args_list = shlex.split(arg_string)
        args = parser.parse_args(args_list)

        pcap_file_to_analyze = args.pcap_file_positional if args.pcap_file_positional else args.read

        if not pcap_file_to_analyze:
            logger.error("No PCAP file specified for analysis.")
            parser.print_help()
            return

        # Resolve PCAP file path (similar logic to output_pcap_path_final in live capture)
        pcap_file_path_final = Path(pcap_file_to_analyze)
        if not pcap_file_path_final.is_absolute() and not pcap_file_path_final.parent.name:
             # If just a filename is given, assume it's in data/captures
            default_pcap_input_dir = Path(__file__).resolve().parent.parent.parent / "data" / "captures"
            pcap_file_path_final = default_pcap_input_dir / pcap_file_to_analyze
        
        if not pcap_file_path_final.exists():
            logger.error(f"PCAP file not found: {pcap_file_path_final}")
            return

        # Extract RabbitMQ config
        rabbitmq_config = config.get('rabbitmq', {})
        rabbitmq_host = rabbitmq_config.get('host', 'localhost')
        rabbitmq_port = rabbitmq_config.get('port', 5672)
        rabbitmq_user = rabbitmq_config.get('user')
        rabbitmq_password = rabbitmq_config.get('password')
        
        queue_name = config.get('capture', {}).get('default_raw_frames_queue', "raw_frames_queue")

        producer = MessageProducer(
            rabbitmq_host=rabbitmq_host, 
            rabbitmq_port=rabbitmq_port, 
            rabbitmq_user=rabbitmq_user, 
            rabbitmq_password=rabbitmq_password
        )

        ingestor = PacketIngestorService(
            producer=producer,
            pcap_file=str(pcap_file_path_final),
            queue_name=queue_name
        )
        logger.info(f"Starting PCAP file analysis for: {pcap_file_path_final}...")
        ingestor.run() # Changed from process_pcap_file to run
        logger.info("PCAP file analysis finished. Packets are being processed by backend services.")

    except argparse.ArgumentError as e:
        logger.error(f"Argument error: {e}")
        # parser.print_help()
    except FileNotFoundError:
         # This is now handled by the explicit check above, but kept for safety
        logger.error(f"PCAP file not found. Please ensure the path is correct.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during PCAP analysis: {e}", exc_info=True)

def handle_report_generation(config):
    """Handles the generation of reports from previously processed data."""
    try:
        # Intente usar el nuevo módulo si está disponible
        try:
            from src.ui.report_service_client import process_reports
            process_reports(config, force_sample=False)
            return
        except ImportError:
            logger.info("No se pudo importar el nuevo módulo report_service_client. Usando la implementación antigua.")
        
        # Si llegamos aquí, usamos la implementación original
        # Extract RabbitMQ config
        rabbitmq_config = config.get('rabbitmq', {})
        rabbitmq_host = rabbitmq_config.get('host', 'localhost')
        rabbitmq_port = rabbitmq_config.get('port', 5672)
        rabbitmq_user = rabbitmq_config.get('user')
        rabbitmq_password = rabbitmq_config.get('password')
        
        # Ask for report format
        print("\nSelect report format:")
        print("1. JSON")
        print("2. CSV")
        print("3. Console")
        try:
            format_choice = int(input("Enter format choice (1-3): "))
            if format_choice < 1 or format_choice > 3:
                print("Invalid choice. Using default format from config.")
                format_choice = 0
        except ValueError:
            print("Invalid input. Using default format from config.")
            format_choice = 0
        
        report_format = None
        if format_choice == 1:
            report_format = "json"
        elif format_choice == 2:
            report_format = "csv"
        elif format_choice == 3:
            report_format = "console"
        
        # Import ReportGenerator directly here to avoid circular imports
        from src.reporting.report_generator import ReportGenerator
        import pika
        import json
        import time
        
        # Create a ReportGenerator instance
        report_generator = ReportGenerator()
        
        print("\nAttempting to connect to RabbitMQ for data collection...")
        
        # Connect to RabbitMQ to check if there are processed results
        connection_params = {
            'host': rabbitmq_host,
            'port': rabbitmq_port
        }
        if rabbitmq_user and rabbitmq_password:
            connection_params['credentials'] = pika.PlainCredentials(rabbitmq_user, rabbitmq_password)
        
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(**connection_params))
            channel = connection.channel()
            
            # Check for analyzed results in the 'analysis_results_queue'
            # This is a temporary approach to get some data directly from the queue
            analysis_queue_name = config.get('messaging_topics', {}).get('analysis_results_queue', 'analysis_results_queue')
            
            # Declare the queue to make sure it exists (does nothing if it already exists)
            channel.queue_declare(queue=analysis_queue_name, durable=True)
            
            # Try to get a message with a short timeout
            method_frame, header_frame, body = channel.basic_get(
                queue=analysis_queue_name,
                auto_ack=False  # Don't acknowledge yet
            )
            
            if method_frame:
                # There are messages in the queue
                print(f"Found data in the message queue. Using for report generation.")
                
                # Parse the message
                try:
                    message_data = json.loads(body)
                    
                    # Generate the report
                    report_data = []
                    
                    # Add the packet data to the report
                    if isinstance(message_data, dict):
                        report_data.append(message_data)
                    elif isinstance(message_data, list):
                        report_data.extend(message_data)
                    
                    # Include more messages if available (up to 10)
                    for _ in range(9):  # Try to get up to 9 more messages
                        method_frame, header_frame, body = channel.basic_get(
                            queue=analysis_queue_name,
                            auto_ack=False
                        )
                        if method_frame:
                            try:
                                message_data = json.loads(body)
                                if isinstance(message_data, dict):
                                    report_data.append(message_data)
                                elif isinstance(message_data, list):
                                    report_data.extend(message_data)
                            except json.JSONDecodeError:
                                logger.warning("Received a message that is not valid JSON, skipping.")
                        else:
                            break  # No more messages
                    
                    # Generate the report
                    if report_data:
                        result = report_generator.generate_report(report_data, report_format)
                        print("\nReport generated successfully with actual data from services.")
                        print("If the format was not 'console', check the reports directory.")
                        
                        # Now acknowledge all the messages we read
                        channel.basic_ack(delivery_tag=method_frame.delivery_tag, multiple=True)
                    else:
                        print("No valid data found in messages. Using sample data.")
                        raise ValueError("No valid data in messages")
                        
                except json.JSONDecodeError:
                    logger.warning("Received a message that is not valid JSON.")
                    channel.basic_nack(delivery_tag=method_frame.delivery_tag)
                    raise ValueError("Invalid message format")
                
            else:
                # No messages in the queue, try to read from reports directory
                import os
                from pathlib import Path
                
                project_root = Path(__file__).resolve().parent.parent.parent
                reports_dir = project_root / "reports"
                
                if os.path.exists(reports_dir) and len(os.listdir(reports_dir)) > 0:
                    print(f"\nNo data in message queue, but found existing reports in {reports_dir}.")
                    print("Please check these existing reports.")
                else:
                    print("\nNo data in message queue and no existing reports found. Using sample data for demonstration.")
                    
                    # Sample data for demonstration
                    sample_data = [
                        {"timestamp": "2025-05-18T10:15:30Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 64},
                        {"timestamp": "2025-05-18T10:15:31Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 76},
                        {"timestamp": "2025-05-18T10:15:32Z", "src_ip": "8.8.8.8", "dst_ip": "192.168.1.100", "protocol": "TCP", "length": 60}
                    ]
                    
                    # Generate report
                    result = report_generator.generate_report(sample_data, report_format)
                    print("\nReport generated successfully with sample data.")
                    print("If the format was not 'console', check the reports directory.")
            
        except pika.exceptions.AMQPConnectionError as e:
            print(f"Failed to connect to RabbitMQ at {rabbitmq_host}:{rabbitmq_port}.")
            print("Error: " + str(e))
            print("Falling back to sample data for report generation...")
            
            # Sample data as fallback
            sample_data = [
                {"timestamp": "2025-05-18T10:15:30Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 64},
                {"timestamp": "2025-05-18T10:15:31Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 76},
                {"timestamp": "2025-05-18T10:15:32Z", "src_ip": "8.8.8.8", "dst_ip": "192.168.1.100", "protocol": "TCP", "length": 60}
            ]
            
            # Generate report with fallback data
            result = report_generator.generate_report(sample_data, report_format)
            print("\nReport generated with sample data due to connection error.")
            print("If the format was not 'console', check the reports directory.")
        
        finally:
            # Close the connection if it exists and is open
            if 'connection' in locals() and connection.is_open:
                connection.close()
                print("RabbitMQ connection closed.")
        
    except Exception as e:
        logger.error(f"An unexpected error occurred during report generation: {e}", exc_info=True)
        print(f"An unexpected error occurred: {e}. Check logs for details.")

def handle_system_status(config):
    """Handles displaying system status and diagnostics."""
    try:
        # Import our improved system status handler
        from src.ui.handle_system_status import handle_system_status as improved_handler
        return improved_handler(config)
    except ImportError as e:
        logger.warning(f"Could not import improved system status handler: {e}. Using fallback implementation.")
        # Continue with the fallback implementation below
    """Handles displaying system status and diagnostics."""
    try:
        # Intenta usar el nuevo módulo si está disponible
        try:
            from src.ui.queue_monitor import run_diagnostics
            diagnosis = run_diagnostics(config)
            
            print("\n=== Additional Diagnostics Options ===")
            print("1. Check sample messages from a queue")
            print("2. Check Docker service status")
            print("3. Return to main menu")
            
            option = input("\nEnter your choice (1-3): ").strip()
            
            if option == "1":
                # Sample queue messages
                print("\nEnter the name of the queue to inspect (e.g., raw_frames_queue, analysis_results_queue):")
                check_messages = input("Queue name or 'n' to skip: ").strip()
                
                if check_messages.lower() not in ['n', 'no', '']:
                    queue_name = check_messages
                    from src.ui.queue_monitor import QueueMonitor
                    
                    # Extract RabbitMQ config
                    rabbitmq_config = config.get('rabbitmq', {})
                    rabbitmq_host = rabbitmq_config.get('host', 'localhost')
                    rabbitmq_port = rabbitmq_config.get('port', 5672)
                    rabbitmq_user = rabbitmq_config.get('user')
                    rabbitmq_password = rabbitmq_config.get('password')
                    
                    monitor = QueueMonitor(
                        host=rabbitmq_host,
                        port=rabbitmq_port,
                        username=rabbitmq_user,
                        password=rabbitmq_password
                    )
                    
                    messages = monitor.get_sample_messages(queue_name, count=2, peek_only=True)
                    
                    if messages:
                        import json
                        print(f"\nSample messages from queue '{queue_name}':")
                        for i, msg in enumerate(messages, 1):
                            print(f"\nMessage {i}:")
                            print(json.dumps(msg, indent=2)[:500] + "..." if len(json.dumps(msg, indent=2)) > 500 else json.dumps(msg, indent=2))
                    else:
                        print(f"\nNo messages found in queue '{queue_name}'.")
            
            elif option == "2":
                # Check Docker services
                try:
                    from src.ui.docker_service_manager import DockerServiceManager
                    manager = DockerServiceManager()
                    
                    if not manager.is_docker_available():
                        print("\nError: Docker is not available on this system.")
                        return
                        
                    if not manager.is_docker_running():
                        print("\nError: Docker is not running. Please start Docker Desktop first.")
                        return
                        
                    success, status_output, _ = manager.get_service_status()
                    if success:
                        print("\n--- Docker Services Status ---")
                        print(status_output)
                    else:
                        print(f"\nError getting Docker service status: {status_output}")
                except ImportError:
                    print("\nDocker service management module not available.")
                except Exception as e:
                    print(f"\nError checking Docker services: {e}")
                    
        except ImportError as e:
            logger.error(f"Failed to import diagnostic module: {e}")
            print("Diagnostic tools not available. Please ensure all requirements are installed.")
            
            # Fallback to simple RabbitMQ connection test
            print("\nFalling back to simple RabbitMQ connection test...")
            import pika
            
            rabbitmq_config = config.get('rabbitmq', {})
            rabbitmq_host = rabbitmq_config.get('host', 'localhost')
            rabbitmq_port = rabbitmq_config.get('port', 5672)
            rabbitmq_user = rabbitmq_config.get('user')
            rabbitmq_password = rabbitmq_config.get('password')
            
            connection_params = {
                'host': rabbitmq_host,
                'port': rabbitmq_port
            }
            if rabbitmq_user and rabbitmq_password:
                connection_params['credentials'] = pika.PlainCredentials(rabbitmq_user, rabbitmq_password)
            
            try:
                connection = pika.BlockingConnection(pika.ConnectionParameters(**connection_params))
                print(f"Successfully connected to RabbitMQ at {rabbitmq_host}:{rabbitmq_port}")
                connection.close()
                print("Connection closed.")
            except pika.exceptions.AMQPConnectionError as e:
                print(f"Failed to connect to RabbitMQ at {rabbitmq_host}:{rabbitmq_port}")
                print(f"Error: {e}")
                
    except Exception as e:
        logger.error(f"Error during diagnostics: {e}", exc_info=True)
        print(f"An error occurred during diagnostics: {e}")
        
def handle_docker_services(config):
    """Handles starting, stopping, and checking Docker services."""
    try:
        from src.ui.docker_service_manager import manage_docker_services
        manage_docker_services(config)
    except ImportError:
        logger.error("The docker_service_manager module is not available.")
        print("\nDocker service management is not available.")
        print("Make sure you have the docker_service_manager.py module installed.")
    except Exception as e:
        logger.error(f"Error managing Docker services: {e}", exc_info=True)
        print(f"An error occurred while managing Docker services: {e}")

def handle_user_choice(choice, config, project_name, version): # Modified signature
    """Handles the user's menu choice."""
    if choice == 1:
        handle_live_capture(config, project_name, version)
    elif choice == 2:
        handle_pcap_analysis(config, project_name, version)
    elif choice == 3:
        print("Configuration management via menu is not yet implemented in this version.")
        # Future: Could allow editing parts of config or selecting profiles.
    elif choice == 4:
        handle_system_status(config)
    elif choice == 5:
        print_project_examples(project_name)
    elif choice == 6:
        print("AI-driven session analysis is currently under reconstruction and not available.")
        logger.info("User selected AI session analysis - currently unavailable.")
    elif choice == 7:
        print("AI model training via menu is currently under reconstruction and not available.")
        logger.info("User selected AI model training - currently unavailable.")
    elif choice == 8:
        handle_report_generation(config)
    elif choice == 9:
        handle_docker_services(config)  # New handler for Docker services
    elif choice == 10:
        print("Exiting Networking Tester. Goodbye!")
        return False  # Signal to exit loop
    return True  # Signal to continue loop

def run_main_loop(project_name="NetworkingTester", version="0.1.0-refactored"): # Added defaults for standalone run
    """Runs the main command-line interface loop."""
    # Initialize logging first
    # setup_logging() now gets its configuration internally.
    setup_logging()

    try:
        app_config = load_app_config()
    except Exception as e: # Catch errors from load_app_config
        logger.critical(f"Failed to load application configuration: {e}. The application cannot start without it.", exc_info=True)
        print(f"Critical Error: Failed to load application configuration: {e}. Please check 'config/settings.yaml' and logs. Exiting.")
        return # Exit if config fails to load
    
    display_splash_screen(project_name, version)
    
    running = True
    while running:
        try:
            choice = display_main_menu_and_get_choice()
            running = handle_user_choice(choice, app_config, project_name, version) # Pass config
        except KeyboardInterrupt:
            print("\nCaught Ctrl+C. Exiting gracefully...")
            running = False
        except Exception as e:
            logger.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
            print(f"An unexpected error occurred: {e}. Please check logs. Returning to menu.")

if __name__ == '__main__':
    # This allows running menu_handler.py directly for testing the UI
    # In a full application, main.py would likely be the entry point and might call run_main_loop.
    print("Running menu_handler directly...")
    # Define project_name and version if running standalone, or get them from a central place
    PROJECT_NAME = "Networking Tester (UI Direct)"
    VERSION = "0.1.0-dev"
    run_main_loop(PROJECT_NAME, VERSION)


