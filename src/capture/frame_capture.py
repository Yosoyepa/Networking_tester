#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for capturing network frames using Scapy and publishing them to a message queue.
"""

import base64
import time
import logging
import pika # Added import for pika exceptions
import uuid # Added for message_id
from scapy.all import sniff, wrpcap, PcapReader
from scapy.error import Scapy_Exception # Import Scapy_Exception
from src.messaging.message_producer import MessageProducer # Updated import

logger = logging.getLogger(__name__)

class PacketIngestorService:
    def __init__(self, producer: MessageProducer, interface: str = None, pcap_file: str = None, capture_filter: str = "ip", packet_count: int = 0, output_pcap_file: str = None, queue_name: str = "raw_frames_queue"): # Updated parameters
        """
        Initializes the PacketIngestorService.

        Args:
            producer: An instance of the MessageProducer.
            interface: Network interface to capture from (e.g., "eth0").
            pcap_file: Path to a PCAP file to read from.
            capture_filter: BPF filter for packet capture (e.g., "tcp port 80").
            packet_count: Number of packets to capture (0 for indefinite).
            output_pcap_file: Optional. Path to save captured packets to a new PCAP file.
            queue_name: The message queue name to publish raw frames to.
        """
        if not interface and not pcap_file:
            raise ValueError("Either a network interface or a PCAP file path must be provided.")
        if interface and pcap_file:
            logger.warning("Both interface and PCAP file provided. Interface capture will be prioritized.")

        self.producer = producer # Updated attribute
        self.interface = interface
        self.pcap_file = pcap_file
        self.capture_filter = capture_filter
        self.packet_count = packet_count
        self.output_pcap_file = output_pcap_file
        self.queue_name = queue_name # New attribute

    def _process_packet(self, packet):
        """
        Processes a single captured packet and publishes it to the message queue.
        Optionally writes to an output PCAP file.
        """
        try:
            timestamp = time.time() # More precise timestamp if packet.time is not granular enough
            if hasattr(packet, 'time'):
                timestamp = float(packet.time)

            frame_bytes = bytes(packet)
            frame_base64 = base64.b64encode(frame_bytes).decode('utf-8')

            fractional_seconds = ("%.6f" % (timestamp % 1))[1:] # .xxxxxx
            iso_timestamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(timestamp)) + fractional_seconds + 'Z'

            raw_frame_message = {
                "schema_version": "1.0",
                "message_id": str(uuid.uuid4()),
                "timestamp": iso_timestamp,
                "source": {
                    "type": "live_capture" if self.interface else "pcap_file",
                    "identifier": self.interface if self.interface else self.pcap_file
                },
                "frame_data": {
                    "raw_bytes_base64": frame_base64,
                    "original_length": len(frame_bytes),
                    "scapy_summary": packet.summary()
                },
                "metadata": {
                    "processing_stage": "ingestion"
                }
            }
            
            self.producer.publish_message(
                message=raw_frame_message,
                queue_name=self.queue_name 
            )
            # logger.debug(f"Published frame from {raw_frame_message['source']['identifier']} to queue {self.queue_name}")

            if self.output_pcap_file:
                wrpcap(self.output_pcap_file, packet, append=True)

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def start_capture(self):
        """
        Starts capturing packets from the specified interface.
        """
        if not self.interface:
            logger.info("No interface specified. Skipping live capture.")
            return

        logger.info(f"Starting live packet capture on interface '{self.interface}' with filter '{self.capture_filter}'.")
        logger.info(f"Publishing to queue '{self.queue_name}'")
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.capture_filter,
                count=self.packet_count,
                store=False  # Do not store packets in memory
            )
            logger.info(f"Finished live packet capture on interface '{self.interface}'.")
        except PermissionError:
            logger.error(f"Permission denied for capturing on interface '{self.interface}'. Try running as root/administrator.")
            raise
        except OSError as e:
            # Specific check for "No such device" or similar errors if Scapy raises them distinctly
            # For now, a general OSError catch.
            logger.error(f"OS error during capture (interface '{self.interface}' might be invalid, down, or not supported by Npcap/WinPcap): {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during live capture: {e}", exc_info=True)
            raise

    def process_pcap_file(self):
        """
        Reads packets from the specified PCAP file and processes them.
        """
        if not self.pcap_file:
            logger.info("No PCAP file specified. Skipping PCAP processing.")
            return

        logger.info(f"Starting PCAP file processing for '{self.pcap_file}'.")
        logger.info(f"Publishing to queue '{self.queue_name}'")
        try:
            count = 0
            with PcapReader(self.pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    self._process_packet(packet)
                    count += 1
                    if self.packet_count > 0 and count >= self.packet_count:
                        logger.info(f"Reached specified packet count ({self.packet_count}). Stopping PCAP processing.")
                        break
            logger.info(f"Finished processing PCAP file '{self.pcap_file}'. Processed {count} packets.")
        except FileNotFoundError:
            logger.error(f"PCAP file not found: '{self.pcap_file}'")
            raise
        except Scapy_Exception as se: # Catch Scapy-specific errors if PcapReader fails
            logger.error(f"Scapy error reading PCAP file '{self.pcap_file}': {se}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"An error occurred during PCAP file processing: {e}", exc_info=True)
            raise

    def run(self):
        """
        Runs the packet ingestion process based on configuration.
        Prioritizes live capture if an interface is specified.
        """
        try:
            # MessageProducer handles connection and queue declaration internally
            logger.info(f"Packet Ingestor configured to publish to queue: '{self.queue_name}'")

            if self.interface:
                self.start_capture()
            elif self.pcap_file:
                self.process_pcap_file()
            else:
                logger.warning("Packet Ingestor started but no source (interface or pcap_file) is configured.")
        except Exception as e:
            logger.error(f"PacketIngestorService failed to run: {e}", exc_info=True)
        finally:
            logger.info("PacketIngestorService run method finished.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    RABBITMQ_HOST = 'localhost'
    RABBITMQ_PORT = 5672
    
    # --- CHOOSE ONE CAPTURE METHOD ---
    # 1. Live Capture (adjust interface name for your system)
    #    On Windows, find interface names with `get_windows_if_list()` from `scapy.arch.windows`
    #    Common names: "Ethernet", "Wi-Fi"
    CAPTURE_INTERFACE = None # Set to an interface name string to enable live capture
    
    # 2. PCAP File Reading
    # Create this file or use your own. For example, create an empty file if you don't have one.
    PCAP_FILE_TO_READ = "data/captures/sample.pcapng" 
    # --- END CHOOSE --- 

    if not CAPTURE_INTERFACE and not PCAP_FILE_TO_READ:
        logger.error("No capture method selected. Please set CAPTURE_INTERFACE or PCAP_FILE_TO_READ.")
        exit(1)
    
    # Ensure data/captures directory exists if PCAP_FILE_TO_READ is set
    if PCAP_FILE_TO_READ:
        import os
        pcap_dir = os.path.dirname(PCAP_FILE_TO_READ)
        if pcap_dir and not os.path.exists(pcap_dir):
            try:
                os.makedirs(pcap_dir)
                logger.info(f"Created directory: {pcap_dir}")
            except OSError as e:
                logger.error(f"Could not create directory {pcap_dir}: {e}")
                # exit(1) # Decide if this is fatal
        # Optionally, create a dummy pcap if it doesn't exist to prevent FileNotFoundError from PcapReader
        # if not os.path.exists(PCAP_FILE_TO_READ):
        #     logger.warning(f"PCAP file {PCAP_FILE_TO_READ} not found. Creating an empty dummy file for the example to run.")
        #     with open(PCAP_FILE_TO_READ, 'wb') as f:
        #         # Minimal valid PCAP header (global header)
        #         # magic_number (d4 c3 b2 a1), version_major (02 00), version_minor (04 00),
        #         # thiszone (00 00 00 00), sigfigs (00 00 00 00), snaplen (ff ff 00 00), network (01 00 00 00)
        #         pcap_header = b'\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\x01\\x00\\x00\\x00'
        #         f.write(pcap_header)


    if CAPTURE_INTERFACE and PCAP_FILE_TO_READ:
        logger.warning("Both CAPTURE_INTERFACE and PCAP_FILE_TO_READ are set. Prioritizing live capture.")
        PCAP_FILE_TO_READ = None # Prioritize live capture

    PACKET_COUNT_LIMIT = 10  # 0 for unlimited, set to 10 for quick test
    OUTPUT_PCAP_SAVE_PATH = None # "logs/ingestor_captured_packets.pcap" # Optional
    
    RAW_FRAMES_QUEUE_NAME = "raw_frames_queue"

    logger.info("Initializing Packet Ingestor Service Example...")
    message_producer_instance = None
    try:
        message_producer_instance = MessageProducer(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        message_producer_instance.connect() # Ensure connection is established

        ingestor = PacketIngestorService(
            producer=message_producer_instance,
            interface=CAPTURE_INTERFACE,
            pcap_file=PCAP_FILE_TO_READ,
            packet_count=PACKET_COUNT_LIMIT,
            output_pcap_file=OUTPUT_PCAP_SAVE_PATH,
            queue_name=RAW_FRAMES_QUEUE_NAME
        )

        logger.info(f"Starting packet ingestion. Interface: '{CAPTURE_INTERFACE}', PCAP: '{PCAP_FILE_TO_READ}'. Publishing to queue '{RAW_FRAMES_QUEUE_NAME}'.")
        ingestor.run()

    except ConnectionRefusedError:
        logger.error(f"Connection to RabbitMQ at {RABBITMQ_HOST}:{RABBITMQ_PORT} refused. Is RabbitMQ running and accessible?")
    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Check RabbitMQ server, credentials, and network.")
    except FileNotFoundError as fnf_err:
        logger.error(f"PCAP File Error: {fnf_err}")
    except PermissionError as perm_err:
        logger.error(f"Permission Error: {perm_err}. If capturing, try with elevated privileges.")
    except OSError as os_err:
        logger.error(f"OS Error: {os_err}. Interface might be down or invalid.")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block: {e}", exc_info=True)
    finally:
        if message_producer_instance:
            logger.info("Closing MessageProducer connection.")
            message_producer_instance.close()
        logger.info("Packet Ingestor Service Example finished.")