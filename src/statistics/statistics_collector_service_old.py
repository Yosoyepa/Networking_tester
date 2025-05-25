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

logger = logging.getLogger(__name__)

class StatisticsCollectorService:
    def __init__(self, parsed_packets_queue: str, 
                 rabbitmq_host: str, rabbitmq_port: int, 
                 rabbitmq_user: Optional[str], rabbitmq_password: Optional[str]): # MODIFIED arguments
        # self.consumer = consumer # REMOVED
        self.consumer: Optional[MessageConsumer] = None # ADDED: Initialize consumer to None
        self.rabbitmq_host = rabbitmq_host # ADDED
        self.rabbitmq_port = rabbitmq_port # ADDED
        self.rabbitmq_user = rabbitmq_user # ADDED
        self.rabbitmq_password = rabbitmq_password # ADDED
        self.parsed_packets_queue = parsed_packets_queue
        self._running = False
        self.reset_stats()

    def reset_stats(self):
        self.total_packets_processed = 0
        self.protocol_counts = Counter()  # e.g., TCP, UDP, ICMP
        self.ip_source_counts = Counter()
        self.ip_destination_counts = Counter()
        self.port_source_counts = Counter()
        self.port_destination_counts = Counter()
        self.ethernet_type_counts = Counter() # For L2 ethertypes
        self.dot11_type_subtype_counts = Counter() # For WiFi frame types
        self.parsing_error_count = 0
        self.first_packet_timestamp: Optional[datetime] = None
        self.last_packet_timestamp: Optional[datetime] = None
        logger.info("Statistics reset.")

    def _update_stats_from_parsed_packet(self, parsed_packet: Dict[str, Any]):
        self.total_packets_processed += 1

        # Timestamps
        raw_frame_ts_str = parsed_packet.get('raw_frame_timestamp')
        if raw_frame_ts_str:
            try:
                # Ensure timestamp is offset-aware UTC
                current_ts = datetime.fromisoformat(raw_frame_ts_str.replace('Z', '+00:00'))
                if self.first_packet_timestamp is None:
                    self.first_packet_timestamp = current_ts
                self.last_packet_timestamp = current_ts
            except ValueError:
                logger.warning(f"Could not parse raw_frame_timestamp: {raw_frame_ts_str}")

        if parsed_packet.get('parsing_errors') and len(parsed_packet['parsing_errors']) > 0:
            self.parsing_error_count += 1

        layers = parsed_packet.get('layers', {})
        if not layers: # Could be due to a parsing error where layers is empty
            return

        # L2 Stats
        if 'ethernet' in layers:
            eth_layer = layers['ethernet']
            self.ethernet_type_counts[eth_layer.get('ethertype', 'N/A')] += 1
        elif 'dot11' in layers:
            dot11_layer = layers['dot11']
            self.dot11_type_subtype_counts[dot11_layer.get('type_subtype', 'N/A')] += 1

        # L3 Stats (IP)
        ip_layer = layers.get('ip') or layers.get('ipv6')
        if ip_layer:
            self.ip_source_counts[ip_layer.get('source_ip', 'N/A')] += 1
            self.ip_destination_counts[ip_layer.get('destination_ip', 'N/A')] += 1
            
            protocol_num = ip_layer.get('protocol') # For IPv4
            if protocol_num is None and 'ipv6' in layers: # For IPv6
                protocol_num = layers['ipv6'].get('next_header')

            # Convert protocol number to name if possible, otherwise use number
            proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'} # Extend as needed
            protocol_name = proto_map.get(protocol_num, str(protocol_num) if protocol_num is not None else 'OTHER_L3')
            self.protocol_counts[protocol_name] += 1

            # L4 Stats (TCP, UDP, ICMP)
            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                self.port_source_counts[str(tcp_layer.get('source_port', 'N/A'))] += 1
                self.port_destination_counts[str(tcp_layer.get('destination_port', 'N/A'))] += 1
            elif 'udp' in layers:
                udp_layer = layers['udp']
                self.port_source_counts[str(udp_layer.get('source_port', 'N/A'))] += 1
                self.port_destination_counts[str(udp_layer.get('destination_port', 'N/A'))] += 1
            # ICMP doesn't have ports in the same way, already counted by protocol_counts
        elif 'arp' in layers:
            self.protocol_counts['ARP'] += 1
            arp_layer = layers['arp']
            self.ip_source_counts[arp_layer.get('psrc', 'N/A')] += 1 # ARP source protocol address
            self.ip_destination_counts[arp_layer.get('pdst', 'N/A')] += 1 # ARP dest protocol address
        else:
            self.protocol_counts['UNKNOWN_L3'] += 1

    def start(self):
        if self._running:
            logger.info("StatisticsCollectorService is already running.")
            return
        logger.info(f"Starting StatisticsCollectorService in thread: {threading.current_thread().name}")
        self._running = True # Set running flag early

        try:
            logger.info(f"Attempting to create and connect MessageConsumer for service within thread: {threading.current_thread().name}")
            self.consumer = MessageConsumer(
                rabbitmq_host=self.rabbitmq_host,
                rabbitmq_port=self.rabbitmq_port,
                rabbitmq_user=self.rabbitmq_user,
                rabbitmq_password=self.rabbitmq_password
            )

            if not self.consumer.channel or not self.consumer.connection or self.consumer.connection.is_closed:
                raise ConnectionError("Failed to connect consumer to RabbitMQ for StatisticsCollectorService (consumer.channel or connection is invalid).")
            logger.info(f"MessageConsumer successfully connected for service in thread: {threading.current_thread().name}")
            
            self.consumer.declare_queue(self.parsed_packets_queue)
            logger.info(f"Queue '{self.parsed_packets_queue}' declared for service consumption.")

            logger.info(f"StatisticsCollectorService starting to consume from '{self.parsed_packets_queue}' using adapter.")
            # This call is blocking and will keep the thread alive until consumption stops or an error occurs.
            self.consumer.start_consuming(self.parsed_packets_queue, self._process_parsed_packet_message_callback_adapter)
            
            # Code here will likely not be reached if start_consuming is blocking indefinitely
            # unless start_consuming itself finishes gracefully (e.g. via stop_consuming from another thread)
            logger.info(f"StatisticsCollectorService consumption loop finished in thread: {threading.current_thread().name}")

        except ConnectionError as ce: # Specific connection error
            logger.error(f"ConnectionError in StatisticsCollectorService.start: {ce}", exc_info=True)
            self._running = False 
            # No consumer to close if connection failed at instantiation
            if self.consumer: # If consumer was created but connection check failed
                self.consumer.close()
                self.consumer = None
        except Exception as e:
            logger.error(f"Failed to start or run StatisticsCollectorService: {e}", exc_info=True)
            self._running = False
            if self.consumer: 
                self.consumer.close()
                self.consumer = None
        finally:
            # This finally block executes when start_consuming returns (e.g., after stop_consuming is called or an unhandled exception in consumer loop)
            logger.info(f"StatisticsCollectorService.start() method is ending in thread: {threading.current_thread().name}. _running is {self._running}")
            # self._running should ideally be false here if stop() was called.
            # If an error occurred, it's already set to false.

    # NEW callback adapter
    def _process_parsed_packet_message_callback_adapter(self, message_body: Dict[str, Any]) -> bool:
        try:
            # Corrected f-string syntax
            logger.debug(f"Adapter received message: {message_body.get('parsed_packet_id')}") 
            self._update_stats_from_parsed_packet(message_body)
            
            if self.total_packets_processed % 100 == 0:
                 # Corrected f-string syntax
                 logger.info(f"Processed {self.total_packets_processed} packets. Current stats snapshot: {self.get_statistics(top_n=1)}")
            return True # Indicate success for ACK
        except Exception as e:
            logger.error(f"Unexpected error processing parsed packet via adapter: {e}", exc_info=True)
            return False # Indicate failure for NACK (and requeue, depending on MessageConsumer's logic)

    def stop(self):
        logger.info(f"Attempting to stop StatisticsCollectorService from thread: {threading.current_thread().name}")
        if not self._running and not self.consumer:
            logger.info("StatisticsCollectorService was not running or consumer not initialized.")
            return

        self._running = False # Signal to stop any loops if they check this flag
        
        consumer_to_stop = self.consumer
        self.consumer = None # Clear immediately to prevent race conditions if start is called again quickly

        if consumer_to_stop:
            logger.info(f"Calling stop_consuming() on consumer in thread: {threading.current_thread().name}")
            consumer_to_stop.stop_consuming() # This should interrupt the blocking start_consuming() call in the service thread
            logger.info(f"Calling close() on consumer in thread: {threading.current_thread().name}")
            consumer_to_stop.close() # Ensure resources are released
            logger.info("Consumer stopped and closed.")
        else:
            logger.info("No active consumer to stop.")
            
        logger.info("StatisticsCollectorService stopped. Final Stats:")
        logger.info(json.dumps(self.get_statistics(), indent=4))

    # def _process_parsed_packet_message(self, channel, method, properties, body): # OLD - Can be removed or kept for reference
    #     try:
    #         parsed_packet_msg = json.loads(body.decode('utf-8'))
    #         logger.debug(f"Received parsed packet: {parsed_packet_msg.get('parsed_packet_id')}")
    #         
    #         self._update_stats_from_parsed_packet(parsed_packet_msg)
    #         
    #         # Log stats periodically or on some condition, e.g., every N packets
    #         if self.total_packets_processed % 100 == 0:
    #              logger.info(f"Processed {self.total_packets_processed} packets. Current stats snapshot: {self.get_statistics(top_n=1)}")

    #         channel.basic_ack(delivery_tag=method.delivery_tag)
    #     except json.JSONDecodeError as e:
    #         logger.error(f"JSON decode error for incoming parsed packet message: {e}. Body: {body[:200]}...", exc_info=True)
    #         channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
    #     except Exception as e:
    #         logger.error(f"Unexpected error processing parsed packet: {e}", exc_info=True)
    #         channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue for potentially transient errors

    def get_statistics(self, top_n=5) -> Dict[str, Any]:
        # Compile a snapshot of the current statistics
        return {
            "total_packets_processed": self.total_packets_processed,
            "protocol_counts": self.protocol_counts.most_common(top_n),
            "ip_source_counts": self.ip_source_counts.most_common(top_n),
            "ip_destination_counts": self.ip_destination_counts.most_common(top_n),
            "port_source_counts": self.port_source_counts.most_common(top_n),
            "port_destination_counts": self.port_destination_counts.most_common(top_n),
            "ethernet_type_counts": self.ethernet_type_counts.most_common(top_n),
            "dot11_type_subtype_counts": self.dot11_type_subtype_counts.most_common(top_n),
            "parsing_error_count": self.parsing_error_count,
            "first_packet_timestamp": self.first_packet_timestamp.isoformat() if self.first_packet_timestamp else None,
            "last_packet_timestamp": self.last_packet_timestamp.isoformat() if self.last_packet_timestamp else None
        }

# ADDED StatServiceThread class definition
class StatServiceThread(threading.Thread):
    def __init__(self, service_instance: StatisticsCollectorService):
        super().__init__(name="StatCollectorThread") # Give a name to the thread
        self.service = service_instance
        self._stop_event = threading.Event() # For graceful shutdown if needed, though service.stop() handles it

    def run(self):
        logger.info(f"StatServiceThread '{self.name}' starting service...")
        try:
            self.service.start() # This will block until the service is stopped
        except Exception as e:
            logger.error(f"Exception in StatServiceThread '{self.name}': {e}", exc_info=True)
        finally:
            logger.info(f"StatServiceThread '{self.name}' finished service execution.")

    # Optional: method to signal stop if service.start() wasn't blocking or needed external signal
    # def stop(self):
    #     logger.info(f"StatServiceThread '{self.name}' stop called.")
    #     self._stop_event.set()
    #     # If service.start() is blocking, service.stop() should be the primary mechanism

# Example Usage (for testing purposes)
if __name__ == '__main__':
    # Setup basic logging
    # Ensure the format includes threadName for clarity
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s')

    # Configuration
    RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
    RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
    # MODIFIED: Default to 'user' and 'password' if environment variables are not set,
    # aligning with docker-compose.yml defaults for local testing.
    RABBITMQ_USER = os.getenv("RABBITMQ_USER", "user") 
    RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "password")
    
    # Use a unique queue name for testing to avoid conflicts if RabbitMQ has old queues
    # Suffix for StatisticsCollectorService's queue
    TEST_QUEUE_SCS = f"parsed_packets_test_q_scs_{uuid.uuid4().hex[:8]}"


    service: Optional[StatisticsCollectorService] = None
    service_thread: Optional[StatServiceThread] = None
    producer: Optional[MessageProducer] = None

    try:
        logger.info(f"Main test: Using RabbitMQ host {RABBITMQ_HOST}:{RABBITMQ_PORT}")
        logger.info(f"Main test: Statistics service will consume from queue: {TEST_QUEUE_SCS}")

        # Instantiate the service with RabbitMQ parameters
        service = StatisticsCollectorService(
            parsed_packets_queue=TEST_QUEUE_SCS,
            rabbitmq_host=RABBITMQ_HOST,
            rabbitmq_port=RABBITMQ_PORT,
            rabbitmq_user=RABBITMQ_USER,
            rabbitmq_password=RABBITMQ_PASS
        )
        
        # Start the service in its own thread
        service_thread = StatServiceThread(service)
        service_thread.start()
        logger.info("Main test: StatServiceThread started.")

        # Give the service a moment to initialize its consumer and start listening
        logger.info("Main test: Waiting 2 seconds for service consumer to initialize...")
        time.sleep(2) 

        # Setup a producer to send some test messages to the queue the service listens on
        logger.info(f"Main test: Setting up MessageProducer to send to {TEST_QUEUE_SCS}...")
        producer = MessageProducer(
            rabbitmq_host=RABBITMQ_HOST,
            rabbitmq_port=RABBITMQ_PORT,
            rabbitmq_user=RABBITMQ_USER,
            rabbitmq_password=RABBITMQ_PASS
        )

        logger.info(f"Main test: Publishing test messages to {TEST_QUEUE_SCS}...")
        # Message 1
        msg_body1 = {"parsed_packet_id": "test_pkt_1", "raw_frame_timestamp": datetime.now(timezone.utc).isoformat(), "layers": {"ethernet": {"ethertype": "IPv4"}, "ip": {"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8", "protocol": 6}, "tcp": {"source_port": 12345, "destination_port": 80}}}
        producer.publish_message(TEST_QUEUE_SCS, msg_body1)
        logger.info(f"Main test: Message 1 sent: {msg_body1.get('parsed_packet_id')}")
        
        time.sleep(0.1) # Brief pause

        # Message 2
        msg_body2 = {"parsed_packet_id": "test_pkt_2", "raw_frame_timestamp": datetime.now(timezone.utc).isoformat(), "layers": {"ethernet": {"ethertype": "IPv6"}, "ipv6": {"source_ip": "2001:db8::1", "destination_ip": "2001:db8::2", "next_header": 17}, "udp": {"source_port": 54321, "destination_port": 53}}} # Corrected: ipv6 layer key and next_header
        producer.publish_message(TEST_QUEUE_SCS, msg_body2)
        logger.info(f"Main test: Message 2 sent: {msg_body2.get('parsed_packet_id')}")

        logger.info("Main test: Test messages sent. Main thread sleeping for 5 seconds to allow service to process...")
        time.sleep(5) 

    except KeyboardInterrupt:
        logger.info("Main test: KeyboardInterrupt received. Stopping service...")
    except Exception as e:
        logger.error(f"Main test: Error in main test execution: {e}", exc_info=True)
        traceback.print_exc() # Print full traceback for unexpected errors
    finally:
        logger.info("Main test: Initiating shutdown sequence...")
        if service:
            logger.info("Main test: Calling service.stop()...")
            service.stop() # This should signal the service thread to stop its consumer loop
            logger.info("Main test: service.stop() returned.")

        if service_thread and service_thread.is_alive():
            logger.info(f"Main test: Joining StatServiceThread '{service_thread.name}'...")
            service_thread.join(timeout=10) # Wait for the service thread to finish
            if service_thread.is_alive():
                logger.warning(f"Main test: StatServiceThread '{service_thread.name}' did not terminate in time.")
            else:
                logger.info(f"Main test: StatServiceThread '{service_thread.name}' joined.")
        elif service_thread:
            logger.info(f"Main test: StatServiceThread '{service_thread.name}' was already finished.")
        
        if producer:
            logger.info("Main test: Closing producer...")
            producer.close()
            logger.info("Main test: Producer closed.")
            
        logger.info("Main test: Test script finished.")

