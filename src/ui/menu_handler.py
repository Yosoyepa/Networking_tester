#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Handles the command-line menu interface for Networking Tester."""

import argparse
import shlex
import logging
import os # Added for path manipulation
from src.utils.config_manager import ConfigManager
from src.core.engine import AnalysisEngine

logger = logging.getLogger(__name__)

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
    """Displays the main menu and gets user choice."""
    print("\\nMain Menu:")
    print("1. Start Live Capture")
    print("2. Analyze PCAP File")
    print("3. Help (Show command options)")
    print("4. Show Examples")
    print("5. Exit")
    choice = input("Select an option (1-5): ")
    return choice

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

def handle_live_capture(engine, project_name, version):
    """Handles the live capture option from the menu."""
    parser = _create_arg_parser(project_name, version, for_live_capture=True)
    arg_string = input(f"\nEnter live capture arguments (e.g., -i \"Ethernet 2\" -c 10 -w my_capture.pcap), or -h for help:\n> ")
    try:
        args_list = shlex.split(arg_string)
        if not args_list or args_list[0].lower() in ['exit', 'quit', 'back', 'menu']:
            print("Returning to main menu.")
            return

        parsed_args = parser.parse_args(args_list)

        if parsed_args.report_format:
            if hasattr(ConfigManager, '_config') and isinstance(ConfigManager._config, dict):
                if 'reporting' not in ConfigManager._config:
                    ConfigManager._config['reporting'] = {}
                ConfigManager._config['reporting']['default_format'] = parsed_args.report_format
                logger.info(f"Report format overridden by CLI to: {parsed_args.report_format}")
            else:
                logger.warning("Could not override report format: ConfigManager._config not found or not a dict.")

        interface_to_use = parsed_args.interface if parsed_args.interface else ConfigManager.get('capture.default_interface', 'auto')
        
        output_pcap_path_final = None
        if parsed_args.write:
            raw_output_path = parsed_args.write
            
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))            
            
            # Check if it's a simple filename (no directory components)
            if not os.path.isabs(raw_output_path) and \
               not os.path.dirname(raw_output_path): # os.path.dirname will be empty for simple filenames
                default_capture_dir_abs = os.path.join(project_root, "data", "captures")
                output_pcap_path_final = os.path.join(default_capture_dir_abs, raw_output_path)
            else:
                # User provided a path (could be relative to CWD or absolute)
                output_pcap_path_final = os.path.abspath(raw_output_path)

            # Ensure the directory for the (now absolute) output path exists
            output_pcap_dir = os.path.dirname(output_pcap_path_final)
            if not os.path.exists(output_pcap_dir):
                os.makedirs(output_pcap_dir)
                logger.info(f"Created directory: {output_pcap_dir}")
            
            logger.info(f"Capture will be saved to: {output_pcap_path_final}")

        logger.info(f"Starting live capture on interface: {interface_to_use}")
        engine.run_live_capture(
            interface=interface_to_use,
            count=parsed_args.count,
            timeout=parsed_args.timeout,
            bpf_filter=parsed_args.filter,
            output_pcap_path=output_pcap_path_final # Use the processed path
        )
    except SystemExit: # Raised by parser.parse_args() on -h or error
        pass
    except KeyboardInterrupt:
        logger.info("\\nLive capture interrupted by user (Ctrl+C). Returning to main menu.")
    except Exception as e:
        logger.error(f"Error during live capture: {e}", exc_info=True)

def handle_pcap_analysis(engine, project_name, version):
    """Handles the PCAP analysis option from the menu."""
    parser = _create_arg_parser(project_name, version, for_live_capture=False)
    arg_string = input(f"\nEnter PCAP file path (e.g., my_capture.pcap [looks in data/captures/], or full path like data/captures/capture.pcap) and options, or -h for help:\n> ")
    try:
        args_list = shlex.split(arg_string)
        if not args_list or args_list[0].lower() in ['exit', 'quit', 'back', 'menu']:
            print("Returning to main menu.")
            return
            
        if len(args_list) == 1 and not args_list[0].startswith('-'):
            args_list = ['-r', args_list[0]]

        parsed_args = parser.parse_args(args_list)
        
        pcap_file_to_analyze = parsed_args.read if parsed_args.read else parsed_args.pcap_file_positional
        
        if not pcap_file_to_analyze:
            logger.error("No PCAP file specified for analysis.")
            parser.print_help()
            return

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))        
        pcap_file_path_final = pcap_file_to_analyze
        # Check if it's a simple filename (no directory components)
        if not os.path.isabs(pcap_file_to_analyze) and \
           not os.path.dirname(pcap_file_to_analyze): # os.path.dirname will be empty for simple filenames
            default_capture_dir_abs = os.path.join(project_root, "data", "captures")
            pcap_file_path_final = os.path.join(default_capture_dir_abs, pcap_file_to_analyze)
            logger.info(f"Attempting to read PCAP from default location: {pcap_file_path_final}")
        else:
            pcap_file_path_final = os.path.abspath(pcap_file_to_analyze)
            logger.info(f"Attempting to read PCAP from specified location: {pcap_file_path_final}")

        if parsed_args.report_format:
            if hasattr(ConfigManager, '_config') and isinstance(ConfigManager._config, dict):
                if 'reporting' not in ConfigManager._config:
                    ConfigManager._config['reporting'] = {}
                ConfigManager._config['reporting']['default_format'] = parsed_args.report_format
                logger.info(f"Report format overridden by CLI to: {parsed_args.report_format}")
            else:
                logger.warning("Could not override report format: ConfigManager._config not found or not a dict.")

        logger.info(f"Analyzing PCAP file: {pcap_file_path_final}")
        engine.run_from_pcap(pcap_file_path=pcap_file_path_final)

    except SystemExit: # Raised by parser.parse_args() on -h or error
        pass
    except KeyboardInterrupt:
        logger.info("\\nPCAP analysis interrupted by user (Ctrl+C). Returning to main menu.")
    except Exception as e:
        logger.error(f"Error during PCAP analysis: {e}", exc_info=True)

def run_main_loop():
    """Runs the main interactive menu loop."""
    project_name = ConfigManager.get('general.project_name', 'Networking Tester')
    version = ConfigManager.get('general.version', 'N/A')

    display_splash_screen(project_name, version)
    
    # Create a single engine instance to be used throughout the session
    engine = AnalysisEngine()
    
    # Create a general parser for the help option from the main menu
    # This parser lists all possible arguments.
    # We can refine this later if needed.
    # For now, using the live capture parser for general help seems reasonable.
    help_parser = _create_arg_parser(project_name, version, for_live_capture=True)
    # Add PCAP specific args for a comprehensive help
    help_parser.add_argument(
            '-r', '--read',
            type=str,
            metavar="PCAP_FILE_INPUT",
            help="Path to a PCAP file to read and analyze (used in 'Analyze PCAP File' mode)."
        )


    try:
        while True:
            choice = display_main_menu_and_get_choice()

            if choice == '1': # Start Live Capture
                handle_live_capture(engine, project_name, version)
            elif choice == '2': # Analyze PCAP File
                handle_pcap_analysis(engine, project_name, version)
            elif choice == '3': # Help
                help_parser.print_help()
            elif choice == '4': # Examples
                print_project_examples(project_name)
            elif choice == '5': # Exit
                logger.info(f"Exiting {project_name}...")
                break
            else:
                print("Invalid option. Please try again.")
            
            print("\\n" + "-"*30) # Separator

    except KeyboardInterrupt:
        logger.info(f"\\n{project_name} interrupted by user (Ctrl+C). Exiting now.")
    finally:
        if engine: # Ensure engine exists before calling shutdown
            engine.shutdown()
        logger.info(f"{project_name} finished.")
