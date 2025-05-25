#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Packet Parser Service with RabbitMQ integration.
Consumes raw packets from queue, parses them, and publishes parsed data.
"""

import logging
import json
import base64
import uuid
import sys
import os
from typing import Dict, Any, Optional

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.append(project_root)

from scapy.all import Packet
from src.messaging.message_broker import MessageBroker
from src.messaging.schemas import (
    RawPacketMessage, ParsedPacketMessage, MessageSchemas
)
from src.analysis.ieee802_3_analyzer import IEEE802_3_Analyzer
from src.analysis.ieee802_11_analyzer import IEEE802_11_Analyzer
from src.utils.config_manager import ConfigManager


class PacketParserService:
    """
    Packet parser service that consumes raw packets and publishes parsed data.
    """
    
    def __init__(self):
        """Initialize the packet parser service."""
        self.logger = logging.getLogger(__name__)
        self.message_broker = MessageBroker()
        self.is_running = False
        
        # Initialize config manager
        config_manager = ConfigManager()
        config_manager.load_config()
        
        # Initialize analyzers
        self.ieee802_3_analyzer = IEEE802_3_Analyzer(config_manager)
        self.ieee802_11_analyzer = IEEE802_11_Analyzer(config_manager)
        
        self.processed_count = 0
    
    def start(self) -> bool:
        """
        Start the packet parser service.
        
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
                MessageSchemas.RAW_PACKETS_QUEUE,
                MessageSchemas.PARSED_PACKETS_QUEUE
            ]
            
            if not self.message_broker.setup_queues(queues_to_setup):
                self.logger.error("Failed to setup queues")
                return False
            
            self.is_running = True
            self.logger.info("Packet Parser Service started successfully")
            
            # Start consuming messages
            return self.message_broker.consume_messages(
                MessageSchemas.RAW_PACKETS_QUEUE,
                self._process_raw_packet_message
            )
            
        except Exception as e:
            self.logger.error(f"Failed to start packet parser service: {e}")
            return False
    
    def stop(self):
        """Stop the packet parser service."""
        self.is_running = False
        self.logger.info(f"Stopped packet parser. Processed {self.processed_count} packets")
        self.message_broker.disconnect()
    
    def _process_raw_packet_message(self, ch, method, properties, body):
        """
        Process a raw packet message from RabbitMQ.
        
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
            raw_message = RawPacketMessage.from_json(body.decode('utf-8'))
            self.logger.debug(f"Processing packet message: {raw_message.message_id}")
            
            # Decode packet data
            packet_data = base64.b64decode(raw_message.packet_data)
            packet = Packet(packet_data)
            
            # Parse the packet
            parsed_data = self._parse_packet(packet)
            
            # Create parsed message
            parsed_message = ParsedPacketMessage(
                message_id=str(uuid.uuid4()),
                original_message_id=raw_message.message_id,
                parsed_data=parsed_data.get('parsed_data', {}),
                protocol_info=parsed_data.get('protocol_info', {}),
                qos_info=parsed_data.get('qos_info')
            )
            
            # Publish parsed message
            if self.message_broker.publish_message(
                MessageSchemas.PARSED_PACKETS_QUEUE,
                parsed_message.to_json()
            ):
                self.processed_count += 1
                self.logger.debug(f"Published parsed packet {self.processed_count}")
            else:
                self.logger.error("Failed to publish parsed packet")
                
        except Exception as e:
            self.logger.error(f"Error processing raw packet message: {e}")
            # Re-raise to trigger nack and requeue
            raise
    
    def _parse_packet(self, packet: Packet) -> Dict[str, Any]:
        """
        Parse a packet using appropriate analyzer.
        
        Args:
            packet: Scapy packet object
              Returns:
            dict: Parsed packet data
        """
        result = {
            'parsed_data': {},
            'protocol_info': {},
            'qos_info': None
        }
        
        try:
            # Determine packet type and use appropriate analyzer
            if self._is_ethernet_packet(packet):
                analysis_result = self.ieee802_3_analyzer.analyze_packet(packet)
                result['parsed_data'] = analysis_result
                result['protocol_info'] = {
                    'type': 'IEEE 802.3',
                    'layer2_protocol': analysis_result.get('type', 'ethernet'),
                    'ethertype': analysis_result.get('ethertype', 'Unknown')
                }
                
                # Extract QoS information if available
                qos_info = analysis_result.get('qos')
                if qos_info:
                    result['qos_info'] = qos_info
                    
            elif self._is_wifi_packet(packet):
                analysis_result = self.ieee802_11_analyzer.analyze_packet(packet)
                # WiFi analyzer returns data in wifi_details key
                wifi_details = analysis_result.get('wifi_details', {})
                result['parsed_data'] = wifi_details
                result['protocol_info'] = {
                    'type': 'IEEE 802.11',
                    'frame_type': wifi_details.get('tipo_subtipo', 'Unknown'),
                    'security_status': wifi_details.get('security_info', {}).get('status', 'Unknown')
                }
                
                # Extract QoS information if available
                qos_info = wifi_details.get('qos_control')
                if qos_info:
                    result['qos_info'] = qos_info
                    
            else:
                # Generic packet parsing
                result['parsed_data'] = self._generic_packet_parse(packet)
                result['protocol_info'] = {
                    'type': 'Generic',
                    'protocol': packet.name if hasattr(packet, 'name') else 'Unknown'
                }
              # Add common packet information
            if isinstance(result['parsed_data'], dict):
                result['parsed_data']['packet_size'] = len(packet)
                result['parsed_data']['layers'] = [layer.name for layer in packet.layers()]
            else:
                # If parsed_data is not a dict, create a new dict with the data
                result['parsed_data'] = {
                    'parsed_info': result['parsed_data'],
                    'packet_size': len(packet),
                    'layers': [layer.name for layer in packet.layers()]
                }
            
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            result['parsed_data'] = {'error': str(e)}
            result['protocol_info'] = {'type': 'Error'}
        
        return result
    
    def _is_ethernet_packet(self, packet: Packet) -> bool:
        """Check if packet is an Ethernet frame."""
        return hasattr(packet, 'src') and hasattr(packet, 'dst') and len(packet.src) == 17
    
    def _is_wifi_packet(self, packet: Packet) -> bool:
        """Check if packet is a WiFi frame."""
        # This is a simplified check - in practice, you'd want more sophisticated detection
        return 'Dot11' in str(type(packet)) or 'RadioTap' in str(type(packet))
    
    def _generic_packet_parse(self, packet: Packet) -> Dict[str, Any]:
        """Generic packet parsing for unknown packet types."""
        parsed = {}
        
        try:
            # Extract basic information
            if hasattr(packet, 'src'):
                parsed['src'] = str(packet.src)
            if hasattr(packet, 'dst'):
                parsed['dst'] = str(packet.dst)
            if hasattr(packet, 'proto'):
                parsed['protocol'] = packet.proto
            if hasattr(packet, 'len'):
                parsed['length'] = packet.len
                
            # Layer-specific information
            layer_info = {}
            for layer in packet.layers():
                layer_name = layer.name
                layer_fields = {}
                
                layer_obj = packet.getlayer(layer)
                if layer_obj:
                    for field_name, field_value in layer_obj.fields.items():
                        layer_fields[field_name] = str(field_value)
                
                if layer_fields:
                    layer_info[layer_name] = layer_fields
            
            parsed['layers_detail'] = layer_info
            
        except Exception as e:
            self.logger.warning(f"Error in generic packet parsing: {e}")
            parsed['parsing_error'] = str(e)
        
        return parsed
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status."""
        return {
            'is_running': self.is_running,
            'processed_count': self.processed_count
        }


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Packet Parser Service')
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
    service = PacketParserService()
    
    try:
        service.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        service.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
