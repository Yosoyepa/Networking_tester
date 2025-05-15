#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Frame capture module for networking_tester.
Provides functionality to capture network frames and packets.
"""

import logging
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
        self.captured_packets_for_pcap_read = [] # Only for read_pcap results
        logger.debug("FrameCapture initialized.")

    def _internal_scapy_callback(self, packet):
        """Internal callback for Scapy's sniff, passes packet to the main processor."""
        if self.packet_processor:
            try:
                self.packet_processor(packet)
            except Exception as e:
                logger.error(f"Error in packet_processor callback: {e}", exc_info=True)
        # For read_pcap, we might want to collect them if no processor is set for that specific call
        # However, the engine should always provide a processor.
        # This list is mainly for the return value of read_pcap if used standalone.
        self.captured_packets_for_pcap_read.append(packet)


    def start_capture(self, interface=None, count=0, timeout=None, filter_str=None):
        """Starts synchronous packet capture."""
        logger.info(f"Starting synchronous capture on interface {interface} (count={count}, timeout={timeout}, filter='{filter_str}')")
        if not self.packet_processor:
            logger.warning("No packet_processor callback set for FrameCapture. Packets will not be processed live.")
        
        captured_scapy_packets = []
        try:
            kwargs = {'iface': interface, 'count': count, 'timeout': timeout, 'store': False, 'prn': self._internal_scapy_callback}
            if filter_str: kwargs['filter'] = filter_str
            
            # Sniff stores packets if store=True. If store=False, prn is called.
            # We want to process live, so store=False. If the engine wants to store them too, it can.
            sniff(**kwargs) 
            # The packets are processed by the callback. Sniff with store=False and prn doesn't return packets.
            # If the engine needs the raw list, it should collect them in its callback.
            logger.info(f"Synchronous capture finished on {interface}.")
            # This method might not need to return packets if they are all handled by the callback.
            # For now, let's assume the engine handles accumulation.
        except Exception as e:
            logger.error(f"Error during synchronous packet capture: {e}", exc_info=True)
        return [] # Or perhaps a count of packets sniffed if Scapy provides it easily without storing.

    def read_pcap(self, pcap_file):
        """Reads packets from a PCAP file and processes them."""
        logger.info(f"Reading packets from {pcap_file}")
        self.captured_packets_for_pcap_read = [] # Reset for this read
        try:
            # rdpcap loads all packets into memory. For very large files, consider PcapReader.
            packets = rdpcap(pcap_file)
            if self.packet_processor:
                for packet in packets:
                    self.packet_processor(packet)
            else: # If no processor, just store them for return (legacy or direct use)
                self.captured_packets_for_pcap_read = list(packets)

            logger.info(f"Read and processed {len(packets)} packets from {pcap_file}")
            return self.captured_packets_for_pcap_read # Return packets if no processor, or processed list if engine collects
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}", exc_info=True)
            return []

    def write_pcap(self, packets, output_file):
        """Writes a list of Scapy packets to a PCAP file."""
        logger.info(f"Writing {len(packets)} packets to {output_file}")
        try:
            wrpcap(output_file, packets)
            logger.info(f"Successfully wrote packets to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error writing PCAP file {output_file}: {e}", exc_info=True)
            return False

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