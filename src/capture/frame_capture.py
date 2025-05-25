#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Packet Ingestor Service with RabbitMQ integration.
Captures packets and publishes them to the message queue for processing.
"""

import logging
import time
import base64
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
import threading
import signal
import sys
import os

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.append(project_root)

from scapy.all import sniff, rdpcap, Packet
from src.messaging.message_broker import MessageBroker
from src.messaging.schemas import RawPacketMessage, PacketMetadata, MessageSchemas


class PacketIngestorService:
    """
    Enhanced packet ingestor service that captures packets and publishes them to RabbitMQ.
    Supports both live capture and file-based ingestion.
    """
    
    def __init__(self, interface: Optional[str] = None, 
                 capture_filter: Optional[str] = None,
                 max_packets: int = 0):
        """
        Initialize the packet ingestor service.
        
        Args:
            interface: Network interface to capture from (None for all interfaces)
            capture_filter: BPF filter for packet capture
            max_packets: Maximum number of packets to capture (0 = unlimited)
        """
        self.interface = interface
        self.capture_filter = capture_filter
        self.max_packets = max_packets
        self.session_id = str(uuid.uuid4())
        self.is_running = False
        self.packet_count = 0
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize message broker
        self.message_broker = MessageBroker()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self) -> bool:
        """
        Start the packet ingestor service.
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            # Connect to RabbitMQ
            if not self.message_broker.connect():
                self.logger.error("Failed to connect to RabbitMQ")
                return False
            
            # Setup required queues
            if not self.message_broker.setup_queues([MessageSchemas.RAW_PACKETS_QUEUE]):
                self.logger.error("Failed to setup queues")
                return False
            
            self.is_running = True
            self.logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
            self.logger.info(f"Capture session ID: {self.session_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet ingestor: {e}")
            return False
    
    def stop(self):
        """Stop the packet ingestor service."""
        self.is_running = False
        self.logger.info(f"Stopped packet ingestor. Total packets captured: {self.packet_count}")
        
        # Disconnect from RabbitMQ
        self.message_broker.disconnect()
    
    def _process_packet(self, packet: Packet):
        """
        Process a captured packet and publish it to RabbitMQ.
        
        Args:
            packet: Scapy packet object
        """
        try:
            if not self.is_running:
                return
            
            # Extract basic metadata
            metadata = self._extract_metadata(packet)
            
            # Encode packet data
            packet_bytes = bytes(packet)
            packet_data_b64 = base64.b64encode(packet_bytes).decode('utf-8')
            
            # Create message
            message = RawPacketMessage(
                message_id=str(uuid.uuid4()),
                packet_data=packet_data_b64,
                metadata=metadata,
                capture_session_id=self.session_id
            )
            
            # Publish to RabbitMQ
            if self.message_broker.publish_message(
                MessageSchemas.RAW_PACKETS_QUEUE,
                message.to_json()
            ):
                self.packet_count += 1
                self.logger.debug(f"Published packet {self.packet_count} to queue")
                
                # Check if we've reached the maximum packet count
                if self.max_packets > 0 and self.packet_count >= self.max_packets:
                    self.logger.info(f"Reached maximum packet count: {self.max_packets}")
                    self.stop()
            else:
                self.logger.error("Failed to publish packet to queue")
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_metadata(self, packet: Packet) -> PacketMetadata:
        """
        Extract metadata from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketMetadata: Extracted metadata
        """
        timestamp = datetime.now().isoformat()
        packet_size = len(packet)
        
        # Extract MAC addresses if available
        src_mac = None
        dst_mac = None
        protocol = None
        
        if hasattr(packet, 'src'):
            src_mac = packet.src
        if hasattr(packet, 'dst'):
            dst_mac = packet.dst
        if hasattr(packet, 'name'):
            protocol = packet.name
        
        # Create packet hash for deduplication
        packet_hash = MessageSchemas.create_packet_hash(bytes(packet))
        
        return PacketMetadata(
            timestamp=timestamp,
            interface=self.interface or "unknown",
            packet_size=packet_size,
            src_mac=src_mac,
            dst_mac=dst_mac,
            protocol=protocol,
            packet_hash=packet_hash
        )
    
    def capture_live(self) -> bool:
        """
        Start live packet capture.
        
        Returns:
            bool: True if capture completed successfully, False otherwise
        """
        try:
            if not self.start():
                return False
            
            self.logger.info("Starting live packet capture...")
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_running,
                count=self.max_packets if self.max_packets > 0 else 0
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error during live capture: {e}")
            return False
        finally:
            self.stop()
    
    def ingest_from_file(self, file_path: str) -> bool:
        """
        Ingest packets from a PCAP file.
        
        Args:
            file_path: Path to the PCAP file
            
        Returns:
            bool: True if ingestion completed successfully, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
            
            if not self.start():
                return False
            
            self.logger.info(f"Ingesting packets from file: {file_path}")
            
            # Read packets from file
            packets = rdpcap(file_path)
            
            for packet in packets:
                if not self.is_running:
                    break
                    
                self._process_packet(packet)
                
                # Check packet limit
                if self.max_packets > 0 and self.packet_count >= self.max_packets:
                    break
            
            self.logger.info(f"Completed file ingestion. Processed {self.packet_count} packets")
            return True
            
        except Exception as e:
            self.logger.error(f"Error ingesting from file: {e}")
            return False
        finally:
            self.stop()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the ingestor service.
        
        Returns:
            dict: Status information
        """
        return {
            "session_id": self.session_id,
            "is_running": self.is_running,
            "packet_count": self.packet_count,
            "interface": self.interface,
            "max_packets": self.max_packets
        }


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Packet Ingestor Service')
    parser.add_argument('--interface', '-i', help='Network interface to capture from')
    parser.add_argument('--filter', '-f', help='BPF capture filter')
    parser.add_argument('--max-packets', '-c', type=int, default=0, 
                       help='Maximum packets to capture (0 = unlimited)')
    parser.add_argument('--file', help='PCAP file to ingest')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start service
    service = PacketIngestorService(
        interface=args.interface,
        capture_filter=args.filter,
        max_packets=args.max_packets
    )
    
    try:
        if args.file:
            success = service.ingest_from_file(args.file)
        else:
            success = service.capture_live()
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        service.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()