#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

import argparse
import logging
import sys
from networking_tester.utils.logging_config import setup_logging # Uses ConfigManager internally
from networking_tester.core.engine import AnalysisEngine
from networking_tester.utils.config_manager import ConfigManager # To access version or other general config

def main():
    # Setup logging first, as it now reads from config
    setup_logging() 
    logger = logging.getLogger(__name__) # Get logger after setup

    project_name = ConfigManager.get('general.project_name', 'Networking Tester')
    version = ConfigManager.get('general.version', 'N/A')
    logger.info(f"Starting {project_name} v{version}")

    parser = argparse.ArgumentParser(description=f"{project_name} - Network Traffic Capture and Analysis Tool")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to capture from (e.g., eth0, Wi-Fi). 'auto' or omit for default.")
    parser.add_argument('-c', '--count', type=int, default=0, help="Number of packets to capture (0 for unlimited until timeout or Ctrl+C).")
    parser.add_argument('-t', '--timeout', type=int, help="Stop capturing after N seconds.")
    parser.add_argument('-r', '--read', type=str, metavar="PCAP_FILE", help="Read packets from a PCAP file instead of live capture.")
    parser.add_argument('-w', '--write', type=str, metavar="PCAP_FILE", help="Save captured packets to a PCAP file (Not yet fully integrated with engine flow).") # TODO
    parser.add_argument('-f', '--filter', type=str, help="BPF filter string for capture (e.g., 'tcp port 80').")
    parser.add_argument('--report-format', type=str, choices=['console', 'json', 'csv'], help="Output report format.")
    # Add more arguments as needed

    args = parser.parse_args()

    engine = AnalysisEngine()

    try:
        if args.report_format: # Allow overriding config for report format via CLI
            ConfigManager._config['reporting']['default_format'] = args.report_format # Temporary direct modification for demo
            logger.info(f"Report format overridden by CLI: {args.report_format}")


        if args.read:
            engine.run_from_pcap(args.read)
        else:
            interface_to_use = args.interface if args.interface else ConfigManager.get('capture.default_interface', 'auto')
            engine.run_live_capture(
                interface=interface_to_use,
                count=args.count,
                timeout=args.timeout,
                bpf_filter=args.filter
            )
        
        # TODO: Implement -w --write logic. This would involve collecting raw packets in the engine
        # and then calling frame_capturer.write_pcap().

    except KeyboardInterrupt:
        logger.info("Capture interrupted by user (Ctrl+C).")
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}", exc_info=True)
    finally:
        engine.shutdown()
        logger.info(f"{project_name} finished.")

if __name__ == "__main__":
    main()
