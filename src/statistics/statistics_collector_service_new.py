#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Statistics Collector Service with RabbitMQ integration.
Consumes parsed packets from queue, aggregates statistics, and publishes results.
"""

import logging
import json
import uuid
import threading
import time
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.append(project_root)

from src.messaging.message_broker import MessageBroker
from src.messaging.schemas import (
    ParsedPacketMessage, StatisticsMessage, MessageSchemas
)


class StatisticsCollectorService:
    """
    Statistics collector service that consumes parsed packets and publishes aggregated statistics.
    """
    
    def __init__(self, stats_window_seconds: int = 60):
        """
        Initialize the statistics collector service.
        
        Args:
            stats_window_seconds: Time window for statistics aggregation
        """
        self.logger = logging.getLogger(__name__)
        self.message_broker = MessageBroker()
        self.is_running = False
        self.stats_window_seconds = stats_window_seconds
        
        # Statistics storage
        self.reset_stats()
        
        # Threading
        self.stats_thread = None
        self.last_stats_publish = datetime.now()
        
        self.processed_count = 0
    
    def reset_stats(self):
        """Reset all statistics counters."""
        self.total_packets_processed = 0
        self.protocol_counts = Counter()  # e.g., TCP, UDP, ICMP
        self.ip_source_counts = Counter()
        self.ip_destination_counts = Counter()
        self.port_source_counts = Counter()
        self.port_destination_counts = Counter()
        self.ethernet_type_counts = Counter()  # For L2 ethertypes
        self.dot11_type_subtype_counts = Counter()  # For WiFi frame types
        self.parsing_error_count = 0
        self.qos_stats = Counter()  # QoS related statistics
        self.packet_size_stats = {"min": float('inf'), "max": 0, "total": 0, "count": 0}
        self.first_packet_timestamp: Optional[datetime] = None
        self.last_packet_timestamp: Optional[datetime] = None
        
        self.logger.info("Statistics reset.")
    
    def start(self) -> bool:
        """
        Start the statistics collector service.
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            # Connect to RabbitMQ
            if not self.message_broker.connect():
                self.logger.error("Failed to connect to RabbitMQ")
                return False
            
            # Setup queues
            queues_to_setup = [
                MessageSchemas.PARSED_PACKETS_QUEUE,
                MessageSchemas.STATISTICS_QUEUE
            ]
            
            if not self.message_broker.setup_queues(queues_to_setup):
                self.logger.error("Failed to setup queues")
                return False
            
            self.is_running = True
            self.logger.info("Statistics Collector Service started successfully")
            
            # Start statistics publishing thread
            self.stats_thread = threading.Thread(target=self._periodic_stats_publisher)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            # Start consuming messages
            return self.message_broker.consume_messages(
                MessageSchemas.PARSED_PACKETS_QUEUE,
                self._process_parsed_packet_message
            )
            
        except Exception as e:
            self.logger.error(f"Failed to start statistics collector service: {e}")
            return False
    
    def stop(self):
        """Stop the statistics collector service."""
        self.is_running = False
        self.logger.info(f"Stopped statistics collector. Processed {self.processed_count} packets")
        
        # Publish final statistics
        self._publish_current_statistics()
        
        # Disconnect from RabbitMQ
        self.message_broker.disconnect()
    
    def _process_parsed_packet_message(self, ch, method, properties, body):
        """
        Process a parsed packet message from RabbitMQ.
        
        Args:
            ch: Channel
            method: Method
            properties: Properties
            body: Message body
        """
        try:
            if not self.is_running:
                return
            
            # Parse the message
            parsed_message = ParsedPacketMessage.from_json(body.decode('utf-8'))
            self.logger.debug(f"Processing parsed packet message: {parsed_message.message_id}")
            
            # Update statistics
            self._update_stats_from_parsed_packet(parsed_message)
            
            self.processed_count += 1
            
        except Exception as e:
            self.logger.error(f"Error processing parsed packet message: {e}")
            # Re-raise to trigger nack and requeue
            raise
    
    def _update_stats_from_parsed_packet(self, parsed_message: ParsedPacketMessage):
        """
        Update statistics from a parsed packet message.
        
        Args:
            parsed_message: Parsed packet message
        """
        self.total_packets_processed += 1
        
        parsed_data = parsed_message.parsed_data
        protocol_info = parsed_message.protocol_info
        qos_info = parsed_message.qos_info
        
        # Update timestamps
        current_time = datetime.now(timezone.utc)
        if self.first_packet_timestamp is None:
            self.first_packet_timestamp = current_time
        self.last_packet_timestamp = current_time
        
        # Update packet size statistics
        packet_size = parsed_data.get('packet_size', 0)
        if packet_size > 0:
            self.packet_size_stats['min'] = min(self.packet_size_stats['min'], packet_size)
            self.packet_size_stats['max'] = max(self.packet_size_stats['max'], packet_size)
            self.packet_size_stats['total'] += packet_size
            self.packet_size_stats['count'] += 1
        
        # Protocol statistics
        protocol_type = protocol_info.get('type', 'Unknown')
        self.protocol_counts[protocol_type] += 1
        
        # Layer-specific statistics
        layers_detail = parsed_data.get('layers_detail', {})
        
        # Ethernet/L2 statistics
        if 'Ether' in layers_detail:
            ether_info = layers_detail['Ether']
            ether_type = ether_info.get('type', 'Unknown')
            self.ethernet_type_counts[ether_type] += 1
            
            # MAC addresses
            src_mac = ether_info.get('src')
            dst_mac = ether_info.get('dst')
            if src_mac:
                self.ip_source_counts[f"MAC:{src_mac}"] += 1
            if dst_mac:
                self.ip_destination_counts[f"MAC:{dst_mac}"] += 1
        
        # WiFi/802.11 statistics
        if 'Dot11' in layers_detail:
            dot11_info = layers_detail['Dot11']
            frame_type = dot11_info.get('type', 'Unknown')
            self.dot11_type_subtype_counts[frame_type] += 1
        
        # IP statistics
        if 'IP' in layers_detail:
            ip_info = layers_detail['IP']
            src_ip = ip_info.get('src')
            dst_ip = ip_info.get('dst')
            protocol = ip_info.get('proto')
            
            if src_ip:
                self.ip_source_counts[src_ip] += 1
            if dst_ip:
                self.ip_destination_counts[dst_ip] += 1
            if protocol:
                self.protocol_counts[f"IP_Proto_{protocol}"] += 1
        
        # TCP statistics
        if 'TCP' in layers_detail:
            tcp_info = layers_detail['TCP']
            src_port = tcp_info.get('sport')
            dst_port = tcp_info.get('dport')
            
            if src_port:
                self.port_source_counts[str(src_port)] += 1
            if dst_port:
                self.port_destination_counts[str(dst_port)] += 1
        
        # UDP statistics
        if 'UDP' in layers_detail:
            udp_info = layers_detail['UDP']
            src_port = udp_info.get('sport')
            dst_port = udp_info.get('dport')
            
            if src_port:
                self.port_source_counts[str(src_port)] += 1
            if dst_port:
                self.port_destination_counts[str(dst_port)] += 1
        
        # QoS statistics
        if qos_info:
            for key, value in qos_info.items():
                self.qos_stats[f"QoS_{key}_{value}"] += 1
        
        # Error tracking
        if parsed_data.get('error'):
            self.parsing_error_count += 1
    
    def _periodic_stats_publisher(self):
        """Periodically publish statistics."""
        while self.is_running:
            try:
                time.sleep(self.stats_window_seconds)
                if self.is_running:
                    self._publish_current_statistics()
            except Exception as e:
                self.logger.error(f"Error in periodic stats publisher: {e}")
    
    def _publish_current_statistics(self):
        """Publish current statistics to the statistics queue."""
        try:
            # Calculate derived statistics
            avg_packet_size = 0
            if self.packet_size_stats['count'] > 0:
                avg_packet_size = self.packet_size_stats['total'] / self.packet_size_stats['count']
            
            duration_seconds = 0
            if self.first_packet_timestamp and self.last_packet_timestamp:
                duration = self.last_packet_timestamp - self.first_packet_timestamp
                duration_seconds = duration.total_seconds()
            
            packets_per_second = 0
            if duration_seconds > 0:
                packets_per_second = self.total_packets_processed / duration_seconds
            
            # Create statistics message
            statistics = {
                'summary': {
                    'total_packets': self.total_packets_processed,
                    'parsing_errors': self.parsing_error_count,
                    'duration_seconds': duration_seconds,
                    'packets_per_second': packets_per_second,
                    'first_packet_time': self.first_packet_timestamp.isoformat() if self.first_packet_timestamp else None,
                    'last_packet_time': self.last_packet_timestamp.isoformat() if self.last_packet_timestamp else None
                },
                'packet_sizes': {
                    'min': self.packet_size_stats['min'] if self.packet_size_stats['min'] != float('inf') else 0,
                    'max': self.packet_size_stats['max'],
                    'average': avg_packet_size,
                    'total_bytes': self.packet_size_stats['total']
                },
                'protocols': dict(self.protocol_counts.most_common(20)),
                'top_source_ips': dict(self.ip_source_counts.most_common(10)),
                'top_destination_ips': dict(self.ip_destination_counts.most_common(10)),
                'top_source_ports': dict(self.port_source_counts.most_common(10)),
                'top_destination_ports': dict(self.port_destination_counts.most_common(10)),
                'ethernet_types': dict(self.ethernet_type_counts.most_common(10)),
                'wifi_frame_types': dict(self.dot11_type_subtype_counts.most_common(10)),
                'qos_statistics': dict(self.qos_stats.most_common(10))
            }
            
            stats_message = StatisticsMessage(
                message_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                statistics=statistics,
                time_window=f"{self.stats_window_seconds}s"
            )
            
            # Publish statistics
            if self.message_broker.publish_message(
                MessageSchemas.STATISTICS_QUEUE,
                stats_message.to_json()
            ):
                self.logger.info(f"Published statistics: {self.total_packets_processed} packets processed")
            else:
                self.logger.error("Failed to publish statistics")
                
        except Exception as e:
            self.logger.error(f"Error publishing statistics: {e}")
    
    def get_current_statistics(self) -> Dict[str, Any]:
        """Get current statistics without publishing."""
        return {
            'total_packets': self.total_packets_processed,
            'parsing_errors': self.parsing_error_count,
            'protocols': dict(self.protocol_counts.most_common(10)),
            'top_source_ips': dict(self.ip_source_counts.most_common(5)),
            'top_destination_ips': dict(self.ip_destination_counts.most_common(5)),
            'processed_count': self.processed_count,
            'is_running': self.is_running
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status."""
        return {
            'is_running': self.is_running,
            'processed_count': self.processed_count,
            'total_packets': self.total_packets_processed,
            'stats_window_seconds': self.stats_window_seconds
        }


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Statistics Collector Service')
    parser.add_argument('--window', '-w', type=int, default=60,
                       help='Statistics aggregation window in seconds')
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
    service = StatisticsCollectorService(stats_window_seconds=args.window)
    
    try:
        service.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        service.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
