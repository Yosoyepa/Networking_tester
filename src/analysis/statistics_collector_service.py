"""
Statistics Collector Service

Consumes ParsedPacket messages from a queue, computes various statistics,
and periodically logs or publishes these statistics.
"""
import logging
import time
from collections import defaultdict, Counter
from typing import Dict, Any, List

from src.messaging.rabbitmq_client import RabbitMQClient # Assuming RabbitMQ
from src.messaging.schemas import ParsedPacket, PARSED_PACKETS_TOPIC # Assuming this is the input topic/queue name
# Define a new topic for publishing statistics if needed, e.g., STATISTICS_RESULTS_TOPIC

logger = logging.getLogger(__name__)

class StatisticsCollectorService:
    def __init__(self, mq_client: RabbitMQClient, 
                 input_exchange_name: str, input_queue_name: str,
                 # output_exchange_name: str = None, output_routing_key: str = None, # If publishing stats
                 log_interval_seconds: int = 60):
        """
        Initializes the StatisticsCollectorService.

        Args:
            mq_client: An instance of the message queue client.
            input_exchange_name: Exchange to bind the input queue to.
            input_queue_name: Queue to consume ParsedPacket messages from.
            log_interval_seconds: Interval in seconds to log collected statistics.
        """
        self.mq_client = mq_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        # self.output_exchange_name = output_exchange_name
        # self.output_routing_key = output_routing_key
        self.log_interval_seconds = log_interval_seconds

        # Internal state for statistics
        self.packet_count = 0
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.src_port_counts = Counter() # For TCP/UDP
        self.dst_port_counts = Counter() # For TCP/UDP
        self.ethernet_type_counts = Counter()
        self.dot11_type_subtype_counts = Counter()
        self.total_bytes = 0
        self.errors_parsing = 0 # If ParsedPacket contains error flags

        self.last_log_time = time.time()

        self._setup_messaging()

    def _setup_messaging(self):
        logger.info(f"Setting up messaging for StatisticsCollectorService.")
        # Input: Consuming from parsed_packets_queue bound to parsed_packets_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name)
        
        # If publishing statistics to a queue:
        # if self.output_exchange_name and self.output_routing_key:
        #     self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        #     self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name}.")

    def _update_statistics(self, parsed_packet: ParsedPacket):
        """
        Updates statistics based on a single ParsedPacket message.
        """
        self.packet_count += 1
        
        layers = parsed_packet.get('layers', {})
        metadata = parsed_packet.get('metadata', {})

        # Estimate packet size (e.g. from raw_frame_id or add to ParsedPacket schema)
        # For now, let's assume a field 'original_length' might be in metadata from parser
        # or we can approximate. This is a placeholder.
        # A better way would be to have the parser include the original frame length in ParsedPacket.
        # For now, we'll count packets and protocols.
        # if 'original_length' in metadata:
        #    self.total_bytes += metadata['original_length']

        if 'ethernet' in layers:
            eth_layer = layers['ethernet']
            self.ethernet_type_counts[eth_layer.get('type')] += 1

        if 'dot11' in layers:
            dot11_layer = layers['dot11']
            type_subtype = f"{dot11_layer.get('type','N/A')}-{dot11_layer.get('subtype','N/A')}"
            self.dot11_type_subtype_counts[type_subtype] += 1

        if 'ip' in layers:
            ip_layer = layers['ip']
            self.src_ip_counts[ip_layer.get('src_ip')] += 1
            self.dst_ip_counts[ip_layer.get('dst_ip')] += 1
            self.protocol_counts[ip_layer.get('proto')] += 1 # IP protocol number

            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                self.protocol_counts['TCP'] += 1 # More specific count
                self.src_port_counts[f"TCP-{tcp_layer.get('sport')}"] += 1
                self.dst_port_counts[f"TCP-{tcp_layer.get('dport')}"] += 1
            elif 'udp' in layers:
                udp_layer = layers['udp']
                self.protocol_counts['UDP'] += 1 # More specific count
                self.src_port_counts[f"UDP-{udp_layer.get('sport')}"] += 1
                self.dst_port_counts[f"UDP-{udp_layer.get('dport')}"] += 1
            elif 'icmp' in layers:
                self.protocol_counts['ICMP'] += 1 # More specific count
        
        # Check for parsing errors if indicated in metadata
        if metadata.get('parsing_error'):
            self.errors_parsing +=1

    def _log_or_publish_statistics(self, force_log=False):
        """
        Logs the current statistics or publishes them.
        """
        current_time = time.time()
        if not force_log and (current_time - self.last_log_time < self.log_interval_seconds):
            return

        if self.packet_count == 0 and not force_log: # Don't log if no packets processed unless forced
            self.last_log_time = current_time
            return

        stats_summary = {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
            "interval_seconds": self.log_interval_seconds if not force_log else (current_time - self.last_log_time),
            "total_packets_processed": self.packet_count,
            "protocol_distribution (L4/App)": dict(self.protocol_counts.most_common(10)),
            "ip_protocol_numbers (L3)": {k:v for k,v in self.protocol_counts.items() if isinstance(k, int)},
            "top_10_src_ips": dict(self.src_ip_counts.most_common(10)),
            "top_10_dst_ips": dict(self.dst_ip_counts.most_common(10)),
            "top_5_src_ports": dict(self.src_port_counts.most_common(5)),
            "top_5_dst_ports": dict(self.dst_port_counts.most_common(5)),
            "ethernet_type_distribution": dict(self.ethernet_type_counts.most_common(5)),
            "dot11_type_subtype_distribution": dict(self.dot11_type_subtype_counts.most_common(5)),
            # "total_bytes_processed": self.total_bytes, # Uncomment if length is available
            "parsing_errors_detected": self.errors_parsing
        }

        logger.info(f"Statistics Update ({time.strftime('%Y-%m-%d %H:%M:%S')}):")
        for key, value in stats_summary.items():
            if isinstance(value, dict):
                logger.info(f"  {key}:")
                for sub_key, sub_value in value.items():
                    logger.info(f"    {sub_key}: {sub_value}")
            else:
                logger.info(f"  {key}: {value}")
        
        # If publishing statistics:
        # if self.output_exchange_name and self.output_routing_key:
        #     self.mq_client.publish(self.output_exchange_name, self.output_routing_key, stats_summary)
        #     logger.info(f"Published statistics to {self.output_exchange_name}/{self.output_routing_key}")

        # Reset counters for the next interval if needed, or keep them cumulative
        # For this example, let's keep them cumulative for simplicity of viewing totals.
        # If interval-based stats are needed, reset here:
        # self.packet_count = 0
        # self.protocol_counts.clear()
        # ... etc.
        self.last_log_time = current_time

    def _message_handler(self, parsed_packet_message: ParsedPacket):
        """
        Callback function to process a single ParsedPacket message from the queue.
        """
        try:
            # logger.debug(f"Received parsed packet message: {parsed_packet_message.get('packet_id')}")
            self._update_statistics(parsed_packet_message)
            self._log_or_publish_statistics() # Check if it's time to log/publish

        except KeyError as ke:
            logger.error(f"Missing key in parsed_packet_message: {ke}. Message: {parsed_packet_message}")
        except Exception as e:
            logger.error(f"Error in StatisticsCollectorService message_handler: {e}", exc_info=True)

    def start_consuming(self):
        """
        Starts consuming messages from the input queue and processing them.
        """
        logger.info(f"StatisticsCollectorService starting to consume from queue: '{self.input_queue_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=False # Manual ack for robust processing
            )
        except Exception as e:
            logger.error(f"StatisticsCollectorService failed to start consuming: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
            raise
        finally:
            # Log any remaining statistics before exiting
            logger.info("StatisticsCollectorService consumption loop finished or was interrupted. Logging final stats.")
            self._log_or_publish_statistics(force_log=True)
            logger.info("StatisticsCollectorService shut down.")


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # --- Configuration ---
    RABBITMQ_HOST = 'localhost'
    RABBITMQ_PORT = 5672
    LOG_INTERVAL = 15 # Log statistics every 15 seconds for testing

    PARSED_PACKETS_EXCHANGE_NAME = "parsed_packets_exchange"
    PARSED_PACKETS_QUEUE_NAME = "parsed_packets_queue" # Consumes from this queue

    # Optional: If publishing stats to a different queue
    # STATS_EXCHANGE_NAME = "statistics_exchange"
    # STATS_QUEUE_ROUTING_KEY = "statistics_results_queue"

    logger.info("Initializing Statistics Collector Service Example...")
    mq_client_instance = None
    try:
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        # The service itself handles declaring its input queue.
        # If it were to publish, it would also handle its output exchange/queue declarations.

        stats_service = StatisticsCollectorService(
            mq_client=mq_client_instance,
            input_exchange_name=PARSED_PACKETS_EXCHANGE_NAME,
            input_queue_name=PARSED_PACKETS_QUEUE_NAME,
            log_interval_seconds=LOG_INTERVAL
            # output_exchange_name=STATS_EXCHANGE_NAME, # Uncomment if publishing
            # output_routing_key=STATS_QUEUE_ROUTING_KEY  # Uncomment if publishing
        )
        
        logger.info(f"Starting statistics collection. Consuming from '{PARSED_PACKETS_QUEUE_NAME}'. Log interval: {LOG_INTERVAL}s. Press Ctrl+C to stop.")
        stats_service.start_consuming()

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Statistics Collector Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block of Statistics Collector: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("Statistics Collector Service Example finished.")

