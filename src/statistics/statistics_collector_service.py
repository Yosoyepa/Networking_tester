import json
import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from src.messaging import MessageConsumer # Assuming MessageConsumer is in src.messaging

logger = logging.getLogger(__name__)

class StatisticsCollectorService:
    def __init__(self, consumer: MessageConsumer, parsed_packets_queue: str):
        self.consumer = consumer
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

    def _process_parsed_packet_message(self, channel, method, properties, body):
        try:
            parsed_packet_msg = json.loads(body.decode('utf-8'))
            logger.debug(f"Received parsed packet: {parsed_packet_msg.get('parsed_packet_id')}")
            
            self._update_stats_from_parsed_packet(parsed_packet_msg)
            
            # Log stats periodically or on some condition, e.g., every N packets
            if self.total_packets_processed % 100 == 0:
                 logger.info(f"Processed {self.total_packets_processed} packets. Current stats snapshot: {self.get_statistics(top_n=1)}")

            channel.basic_ack(delivery_tag=method.delivery_tag)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for incoming parsed packet message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.error(f"Unexpected error processing parsed packet: {e}", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue for potentially transient errors

    def get_statistics(self, top_n=5) -> Dict[str, Any]:
        duration_seconds = 0
        if self.first_packet_timestamp and self.last_packet_timestamp:
            duration = self.last_packet_timestamp - self.first_packet_timestamp
            duration_seconds = duration.total_seconds()

        packets_per_second = 0
        if duration_seconds > 0 and self.total_packets_processed > 0:
            packets_per_second = round(self.total_packets_processed / duration_seconds, 2)
        
        return {
            "total_packets_processed": self.total_packets_processed,
            "first_packet_timestamp": self.first_packet_timestamp.isoformat() if self.first_packet_timestamp else None,
            "last_packet_timestamp": self.last_packet_timestamp.isoformat() if self.last_packet_timestamp else None,
            "processing_duration_seconds": duration_seconds,
            "packets_per_second_approx": packets_per_second,
            "protocol_distribution": dict(self.protocol_counts.most_common(top_n)),
            "l2_ethernet_type_distribution": dict(self.ethernet_type_counts.most_common(top_n)),
            "l2_dot11_type_subtype_distribution": dict(self.dot11_type_subtype_counts.most_common(top_n)),
            "top_source_ips": dict(self.ip_source_counts.most_common(top_n)),
            "top_destination_ips": dict(self.ip_destination_counts.most_common(top_n)),
            "top_source_ports": dict(self.port_source_counts.most_common(top_n)),
            "top_destination_ports": dict(self.port_destination_counts.most_common(top_n)),
            "parsing_error_count": self.parsing_error_count,
        }

    def start(self):
        if self._running:
            logger.info("StatisticsCollectorService is already running.")
            return
        logger.info("Starting StatisticsCollectorService...")
        try:
            self.consumer.connect()
            # Assuming consumer handles queue declaration for parsed_packets_queue
            self.consumer.start_consuming(self.parsed_packets_queue, self._process_parsed_packet_message)
            self._running = True
            logger.info(f"StatisticsCollectorService started. Consuming from '{self.parsed_packets_queue}'.")
            # This will block if consumer.start_consuming is blocking.
        except Exception as e:
            logger.error(f"Failed to start StatisticsCollectorService: {e}", exc_info=True)
            self._running = False

    def stop(self):
        logger.info("Stopping StatisticsCollectorService...")
        self._running = False
        if self.consumer:
            self.consumer.close()
        logger.info("StatisticsCollectorService stopped. Final Stats:")
        logger.info(json.dumps(self.get_statistics(), indent=4))

# Example Usage (for testing purposes)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    RABBITMQ_HOST = 'localhost'
    PARSED_PACKETS_QUEUE = 'parsed_packets_queue' # Queue this service consumes from

    # For testing, we need a way to send a dummy parsed packet to the queue.
    # We'll use MessageProducer for this.
    from src.messaging import MessageProducer 
    import uuid

    # Example Parsed Packet Message (matches the schema defined in docs/message_schemas.md)
    example_parsed_packet = {
        "schema_version": "1.0",
        "parsed_packet_id": str(uuid.uuid4()),
        "original_raw_frame_id": str(uuid.uuid4()),
        "raw_frame_timestamp": datetime.now(timezone.utc).isoformat(),
        "parsing_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_info": {
            "type": "pcap_file",
            "identifier": "test.pcap"
        },
        "layers": {
            "ethernet": {
                "destination_mac": "00:AA:BB:CC:DD:EE",
                "source_mac": "00:11:22:33:44:55",
                "ethertype": "0x0800"
            },
            "ip": {
                "version": 4,
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.5",
                "protocol": 6, # TCP
                "ttl": 64,
                "length": 52
            },
            "tcp": {
                "source_port": 54321,
                "destination_port": 80,
                "sequence_number": 1000,
                "acknowledgment_number": 0,
                "flags": { "syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False, "ece": False, "cwr": False },
                "window_size": 65535
            }
        },
        "parsing_errors": []
    }

    stats_consumer = None
    stats_service = None
    test_msg_producer = None

    try:
        # Producer to send a test message to PARSED_PACKETS_QUEUE
        test_msg_producer = MessageProducer(host=RABBITMQ_HOST)
        test_msg_producer.connect()
        logger.info(f"Sending test parsed packet to '{PARSED_PACKETS_QUEUE}'...")
        test_msg_producer.publish_message(example_parsed_packet, PARSED_PACKETS_QUEUE)
        logger.info(f"Test message sent. ID: {example_parsed_packet['parsed_packet_id']}")
        # Sending a second message to test aggregation
        time.sleep(0.1) # ensure different timestamp if that matters for stats
        example_parsed_packet["parsed_packet_id"] = str(uuid.uuid4())
        example_parsed_packet["raw_frame_timestamp"] = datetime.now(timezone.utc).isoformat()
        example_parsed_packet["layers"]["ip"]["source_ip"] = "192.168.1.11"
        test_msg_producer.publish_message(example_parsed_packet, PARSED_PACKETS_QUEUE)
        logger.info(f"Second test message sent. ID: {example_parsed_packet['parsed_packet_id']}")
        test_msg_producer.close()

        # Setup consumer for the service
        stats_consumer = MessageConsumer(host=RABBITMQ_HOST, prefetch_count=5)
        
        stats_service = StatisticsCollectorService(stats_consumer, PARSED_PACKETS_QUEUE)
        stats_service.start() # This will block if consumer.start_consuming is blocking

        logger.info("StatisticsCollectorService running. Press Ctrl+C to stop after a few seconds if messages are processed.")
        # Keep main thread alive. Service should process messages and log.
        # For a real scenario, start() would be in a thread or the process would be managed.
        # Let it run for a bit to process messages
        count = 0
        while stats_service._running and count < 10: # Run for 10 seconds or until stopped
            time.sleep(1)
            count +=1
            if stats_service.total_packets_processed >= 2: # Stop if both messages processed
                logger.info("Both test messages processed.")
                break
        
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Error in main: {e}", exc_info=True)
    finally:
        if stats_service:
            stats_service.stop() # This will also close its consumer
        elif stats_consumer: # If service failed to init but consumer was created
            stats_consumer.close()
        
        # test_msg_producer is already closed after sending messages.
        logger.info("Main script finished.")

