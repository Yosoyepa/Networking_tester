#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Frame capture module for networking_tester.
Provides functionality to capture network frames and packets.
"""

import logging
import os # Add os import for path operations
from scapy.all import sniff, wrpcap, rdpcap, AsyncSniffer

logger = logging.getLogger(__name__)

class FrameCapture:
    """Class for capturing network frames. Focuses purely on capture."""
    
    def __init__(self, packet_processing_callback=None):
        """
        Initialize the frame capture module.
        
        Args:
            packet_processing_callback: A function to call for each captured packet.
                                        This callback will receive the Scapy packet.
        """
        self.packet_processor = packet_processing_callback
        self.async_sniffer = None
        # self.captured_packets_for_pcap_read = [] # This list is now managed by the engine if needed for writing, or returned by read_pcap directly.
        logger.debug("FrameCapture initialized.")

    def _internal_scapy_callback(self, packet):
        """Internal callback for Scapy's sniff, passes packet to the main processor."""
        if self.packet_processor:
            try:
                self.packet_processor(packet) # Engine's callback will handle storage if needed
            except Exception as e:
                logger.error(f"Error in packet_processor callback: {e}", exc_info=True)
        # No direct storage here anymore; engine decides if packets are stored for writing.

    def start_capture(self, interface=None, count=0, timeout=None, filter_str=None):
        """Starts synchronous packet capture."""
        logger.info(f"Starting synchronous capture on interface {interface} (count={count}, timeout={timeout}, filter='{filter_str}')")
        if not self.packet_processor:
            logger.warning("No packet_processor callback set for FrameCapture. Packets will not be processed live or stored for writing.")
        
        try:
            kwargs = {'iface': interface, 'count': count, 'timeout': timeout, 'store': False, 'prn': self._internal_scapy_callback}
            if filter_str: kwargs['filter'] = filter_str
            
            sniff(**kwargs)
            logger.info(f"Synchronous capture finished on {interface}.")
        except Exception as e:
            logger.error(f"Error during synchronous packet capture: {e}", exc_info=True)
        # The method doesn't return packets; they are handled by the callback.

    def read_pcap(self, pcap_file):
        """Reads packets from a PCAP file and processes them via the callback."""
        logger.info(f"Reading packets from {pcap_file}")
        processed_packets_list = [] # To return the list of packets read
        try:
            packets_from_file = rdpcap(pcap_file)
            processed_packets_list = list(packets_from_file)

            if self.packet_processor:
                for packet_to_process in processed_packets_list:
                    self.packet_processor(packet_to_process)
            else:
                logger.warning(f"No packet_processor set. Packets from {pcap_file} read but not processed further by FrameCapture.")

            logger.info(f"Read and processed {len(processed_packets_list)} packets from {pcap_file}")
            return processed_packets_list 
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}", exc_info=True)
            return [] # Return empty list on error

    def write_pcap(self, packets, output_file):
        """Writes a list of Scapy packets to a PCAP file."""
        if not packets:
            logger.warning("No packets to write.")
            return False # Ensure boolean return

        try:
            # Ensure the directory exists
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                logger.info(f"Created directory: {output_dir}")

            logger.info(f"Writing {len(packets)} packets to {output_file}")
            wrpcap(output_file, packets)
            logger.info(f"Successfully wrote packets to {output_file}")

            # Check file size after writing
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                logger.info(f"PCAP file {output_file} size: {file_size} bytes.")
                if file_size == 0:
                    logger.warning(f"PCAP file {output_file} was created but is empty.")
                    return False # File is empty
                return True # File exists and is not empty
            else:
                logger.error(f"PCAP file {output_file} was NOT created after wrpcap call.")
                return False # File not created
        except Exception as e:
            logger.error(f"Error writing PCAP file {output_file}: {e}", exc_info=True)
            return False # Exception occurred

    def start_async_capture(self, interface=None, filter_str=None):
        """Starts asynchronous packet capture."""
        logger.info(f"Starting asynchronous capture on interface {interface} (filter='{filter_str}')")
        if not self.packet_processor:
            logger.warning("No packet_processor callback set for FrameCapture. Packets will not be processed live.")

        try:
            kwargs = {'iface': interface, 'store': False, 'prn': self._internal_scapy_callback}
            if filter_str: kwargs['filter'] = filter_str
            self.async_sniffer = AsyncSniffer(**kwargs)
            self.async_sniffer.start()
            logger.info(f"Asynchronous capture started on {interface}.")
            return True
        except Exception as e:
            logger.error(f"Error starting asynchronous capture: {e}", exc_info=True)
            return False

    def stop_async_capture(self):
        """Stops asynchronous packet capture."""
        if self.async_sniffer and self.async_sniffer.running:
            self.async_sniffer.stop()
            self.async_sniffer.join(timeout=2) # Wait for thread to finish
            logger.info("Asynchronous capture stopped.")
            # Results are processed by callback. AsyncSniffer.results might be populated if store=True was used.
            # Since we use store=False, the results are handled by the packet_processor.
            return True # Indicate successful stop
        logger.warning("No active asynchronous capture to stop or already stopped.")
        return False