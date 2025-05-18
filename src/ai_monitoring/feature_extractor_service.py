"""
Feature Extractor Service

Consumes ParsedPacket messages, extracts features relevant for ML models,
and publishes FeatureVector messages.
"""
import logging
import time
import uuid
from typing import Dict, Any, List, Optional

# Removed pandas import as we process packet by packet
# from scapy.all import IP, TCP, UDP, ICMP, Dot11, Raw # Not needed directly, using parsed_packet

from src.messaging.rabbitmq_client import RabbitMQClient # Assuming RabbitMQ
from src.messaging.schemas import ParsedPacket, FeatureVector, PARSED_PACKETS_TOPIC, FEATURES_TOPIC
from src.utils.logger_config import setup_logging # For standalone execution

logger = logging.getLogger(__name__)

class FeatureExtractorService:
    def __init__(self, mq_client: RabbitMQClient,
                 input_exchange_name: str, input_queue_name: str,
                 output_exchange_name: str, output_routing_key: str):
        """
        Initializes the FeatureExtractorService.

        Args:
            mq_client: An instance of the message queue client.
            input_exchange_name: Exchange for the input queue.
            input_queue_name: Queue to consume ParsedPacket messages from.
            output_exchange_name: Exchange to publish FeatureVector messages to.
            output_routing_key: Routing key for publishing FeatureVector messages.
        """
        self.mq_client = mq_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.output_exchange_name = output_exchange_name
        self.output_routing_key = output_routing_key

        self._setup_messaging()

    def _setup_messaging(self):
        logger.info(f"Setting up messaging for FeatureExtractorService.")
        # Input: Consuming from parsed_packets_queue bound to parsed_packets_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        # Ensure the input queue is bound with the correct routing key, which is typically the queue name itself for direct exchanges
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name) # routing key = queue name
        
        # Output: Publishing to features_exchange
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        # The queue for features will be declared by its consumer(s) (e.g., MLInferenceService)
        # or can be declared here if this service is also responsible for it.
        # For robustness, let's ensure the output queue (if named the same as routing key) is declared by the producer too.
        # This helps if the consumer starts later.
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name} (bound to {self.input_exchange_name}), publishing to {self.output_exchange_name} with key {self.output_routing_key}")

    def _extract_features(self, parsed_packet: ParsedPacket) -> Optional[FeatureVector]:
        """
        Extracts features from a ParsedPacket, adapting logic from the old PacketFeatureExtractor.
        """
        packet_id_val = parsed_packet.get("packet_id") # Store for logging and use
        try:
            timestamp_str = parsed_packet.get('timestamp') # This is already ISO8601 string
            layers = parsed_packet.get('layers', {})
            
            if not packet_id_val or not timestamp_str:
                logger.error(f"ParsedPacket missing packet_id or timestamp: {parsed_packet}")
                return None

            features: Dict[str, float | int | str] = {}
            flow_parts: List[str] = [] # Initialize flow_parts

            # General features
            # Using parentheses for multi-line assignment to avoid issues with backslashes
            features['frame_length'] = (
                parsed_packet.get('metadata', {}).get('original_length', 0)
                if 'ethernet' in layers or 'wifi' in layers else
                parsed_packet.get('metadata', {}).get('raw_frame_length', 0)
            )
            if features['frame_length'] == 0 and 'raw_frame_data_len' in parsed_packet.get('metadata', {}): 
                 features['frame_length'] = parsed_packet['metadata']['raw_frame_data_len']


            # IP Layer
            if 'ip' in layers:
                ip_layer = layers['ip']
                features['ip_version'] = int(ip_layer.get('version', 0))
                features['ip_ihl'] = int(ip_layer.get('ihl', 0))
                features['ip_tos'] = int(ip_layer.get('tos', 0))
                features['dscp'] = int(ip_layer.get('tos', 0)) >> 2
                features['ip_len'] = int(ip_layer.get('len', 0))
                features['ip_id'] = int(ip_layer.get('id', 0))
                features['ip_flags'] = int(ip_layer.get('flags_value', 0)) 
                features['ip_frag'] = int(ip_layer.get('frag', 0))
                features['ip_ttl'] = int(ip_layer.get('ttl', 0))
                features['ip_protocol'] = int(ip_layer.get('proto', 0))
                features['ip_src'] = str(ip_layer.get('src_ip', '0.0.0.0'))
                features['ip_dst'] = str(ip_layer.get('dst_ip', '0.0.0.0'))
                features['is_ip'] = 1
                
                # Initialize flow_parts here if IP layer exists
                flow_parts = [str(ip_layer.get('src_ip')), str(ip_layer.get('dst_ip')), str(ip_layer.get('proto'))]
            else:
                features['is_ip'] = 0
                for col in ['ip_version', 'ip_ihl', 'ip_tos', 'dscp', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_protocol']:
                    features[col] = 0
                features['ip_src'] = '0.0.0.0'
                features['ip_dst'] = '0.0.0.0'
                # flow_parts remains empty as initialized

            # Transport Layer (TCP/UDP/ICMP)
            features['is_tcp'] = 1 if 'tcp' in layers else 0
            features['is_udp'] = 1 if 'udp' in layers else 0
            features['is_icmp'] = 1 if 'icmp' in layers else 0

            transport_defaults = {
                'src_port': 0, 'dst_port': 0,
                'tcp_seq': 0.0, 'tcp_ack': 0.0, 'tcp_dataofs': 0.0, 'tcp_reserved': 0.0,
                'tcp_flags': 0.0, 'tcp_window': 0.0, 'tcp_chksum': 0.0, 'tcp_urgptr': 0.0,
                'udp_len': 0.0, 'udp_chksum': 0.0,
                'icmp_type': 0.0, 'icmp_code': 0.0, 'icmp_chksum': 0.0
            }
            for k, v in transport_defaults.items():
                features[k] = v

            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                features['src_port'] = int(tcp_layer.get('sport', 0))
                features['dst_port'] = int(tcp_layer.get('dport', 0))
                features['tcp_seq'] = float(tcp_layer.get('seq', 0))
                features['tcp_ack'] = float(tcp_layer.get('ack_val', 0)) 
                features['tcp_dataofs'] = float(tcp_layer.get('dataofs', 0))
                features['tcp_reserved'] = float(tcp_layer.get('reserved', 0))
                features['tcp_flags'] = float(tcp_layer.get('flags_value', 0)) 
                features['tcp_window'] = float(tcp_layer.get('window', 0))
                features['tcp_chksum'] = float(tcp_layer.get('chksum', 0))
                features['tcp_urgptr'] = float(tcp_layer.get('urgptr', 0))
                if flow_parts: # Check if flow_parts was initialized (it is, if IP layer was present)
                    flow_parts.extend([str(tcp_layer.get('sport')), str(tcp_layer.get('dport'))])
            elif 'udp' in layers:
                udp_layer = layers['udp']
                features['src_port'] = int(udp_layer.get('sport', 0))
                features['dst_port'] = int(udp_layer.get('dport', 0))
                features['udp_len'] = float(udp_layer.get('len', 0))
                features['udp_chksum'] = float(udp_layer.get('chksum', 0))
                if flow_parts: 
                     flow_parts.extend([str(udp_layer.get('sport')), str(udp_layer.get('dport'))])
            elif 'icmp' in layers:
                icmp_layer = layers['icmp']
                features['icmp_type'] = float(icmp_layer.get('type', 0))
                features['icmp_code'] = float(icmp_layer.get('code', 0))
                features['icmp_chksum'] = float(icmp_layer.get('chksum', 0))

            flow_identifier = "-".join(filter(None, flow_parts)) if flow_parts else None


            # Wi-Fi (802.11) Layer
            has_wifi = False
            if 'wifi' in layers: 
                has_wifi = True
                wifi_layer = layers['wifi']
                features['wifi_fc_type'] = int(wifi_layer.get('fc_type', 0))
                features['wifi_fc_subtype'] = int(wifi_layer.get('fc_subtype', 0))
                fc_flags = wifi_layer.get('fc_flags', {})
                features['wifi_fc_to_ds'] = 1 if fc_flags.get('to_ds') else 0
                features['wifi_fc_from_ds'] = 1 if fc_flags.get('from_ds') else 0
                features['wifi_fc_more_frag'] = 1 if fc_flags.get('more_frag') else 0
                features['wifi_fc_retry'] = 1 if fc_flags.get('retry') else 0
                features['wifi_fc_pwr_mgt'] = 1 if fc_flags.get('pwr_mgt') else 0
                features['wifi_fc_more_data'] = 1 if fc_flags.get('more_data') else 0
                features['wifi_fc_protected'] = 1 if fc_flags.get('wep') else 0 
                features['wifi_fc_order'] = 1 if fc_flags.get('order') else 0
                features['wifi_duration_id'] = int(wifi_layer.get('duration_id', 0))
                features['wifi_addr1'] = str(wifi_layer.get('addr1', "00:00:00:00:00:00"))
                features['wifi_addr2'] = str(wifi_layer.get('addr2', "00:00:00:00:00:00"))
                features['wifi_addr3'] = str(wifi_layer.get('addr3', "00:00:00:00:00:00"))
                features['wifi_addr4'] = str(wifi_layer.get('addr4', "00:00:00:00:00:00"))
                features['wifi_sc_frag'] = int(wifi_layer.get('sc_frag', 0)) 
                features['wifi_sc_seq'] = int(wifi_layer.get('sc_seq', 0))   
                features['wifi_tid'] = int(wifi_layer.get('qos_tid', 0)) if 'qos_tid' in wifi_layer else 0 
            
            features['is_wifi'] = 1 if has_wifi else 0
            if not has_wifi:
                for col in ['wifi_fc_type', 'wifi_fc_subtype', 'wifi_fc_to_ds', 'wifi_fc_from_ds',
                            'wifi_fc_more_frag', 'wifi_fc_retry', 'wifi_fc_pwr_mgt', 'wifi_fc_more_data',
                            'wifi_fc_protected', 'wifi_fc_order', 'wifi_duration_id', 
                            'wifi_sc_frag', 'wifi_sc_seq', 'wifi_tid']:
                    features[col] = 0
                for col in ['wifi_addr1', 'wifi_addr2', 'wifi_addr3', 'wifi_addr4']:
                    features[col] = "00:00:00:00:00:00"

            # Payload features
            features['payload_length'] = parsed_packet.get('metadata', {}).get('payload_len', 0)
            if 'raw_data' in layers and layers['raw_data'] and 'data' in layers['raw_data']: 
                 features['payload_length'] = len(layers['raw_data']['data']) // 2 

            final_features = {}
            for k, v in features.items():
                if isinstance(v, (int, float, str)):
                    final_features[k] = v
                else:
                    final_features[k] = str(v) 

            feature_vector: FeatureVector = {
                "packet_id": packet_id_val, 
                "timestamp": timestamp_str, 
                "flow_id": flow_identifier,
                "features": final_features,
                "metadata": {
                    "feature_extractor_version": "0.2.1", # Incremented version
                    "extraction_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime())
                }
            }
            return feature_vector

        except Exception as e:
            # Corrected f-string for logging
            logger.error(f"Error extracting features for packet_id '{packet_id_val}': {e}", exc_info=True)
            return None

    def _message_handler(self, parsed_packet_message: ParsedPacket):
        """
        Callback function to process a single ParsedPacket message.
        """
        try:
            # logger.debug(f"Received parsed packet message: {parsed_packet_message.get('packet_id')}")
            
            feature_vector = self._extract_features(parsed_packet_message)
            
            if feature_vector:
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=feature_vector
                )
                # logger.info(f"Successfully extracted features and published for packet_id: {feature_vector['packet_id']}")
            else:
                logger.warning(f"Failed to extract features for packet_id: {parsed_packet_message.get('packet_id')}. Message will not be published.")

        except KeyError as ke:
            logger.error(f"Missing key in parsed_packet_message: {ke}. Message: {parsed_packet_message}")
        except Exception as e:
            logger.error(f"Error in FeatureExtractorService message_handler: {e}", exc_info=True)

    def start_consuming(self):
        """
        Starts consuming messages from the input queue and processing them.
        """
        logger.info(f"FeatureExtractorService starting to consume from queue: '{self.input_queue_name}' bound to exchange '{self.input_exchange_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=True # Changed to True for simplicity in this example, consider manual ack for production
            )
        except Exception as e:
            logger.error(f"FeatureExtractorService failed to start consuming: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
            # raise # Commenting out raise to prevent crash in case of MQ issue during long run
        finally:
            logger.info("FeatureExtractorService consumption loop finished or was interrupted.")


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    # Use setup_logging from utils
    setup_logging()

    # --- Configuration ---
    RABBITMQ_HOST = 'localhost'
    RABBITMQ_PORT = 5672

    PARSED_PACKETS_EXCHANGE_NAME = "parsed_packets_exchange"
    PARSED_PACKETS_QUEUE_NAME = "parsed_packets_queue" # Consumes from this queue
    
    FEATURES_EXCHANGE_NAME = "features_exchange"
    FEATURES_QUEUE_ROUTING_KEY = "features_queue" # Publishes with this routing key

    logger.info("Initializing Feature Extractor Service Example...")
    mq_client_instance = None
    try:
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        # Declare output exchange and queue (consumers of features will also declare the queue)
        mq_client_instance.declare_exchange(FEATURES_EXCHANGE_NAME, exchange_type='direct')
        mq_client_instance.declare_queue(FEATURES_QUEUE_ROUTING_KEY, FEATURES_EXCHANGE_NAME, FEATURES_QUEUE_ROUTING_KEY)
        logger.info(f"Declared exchange '{FEATURES_EXCHANGE_NAME}' and queue '{FEATURES_QUEUE_ROUTING_KEY}' for output.")

        feature_service = FeatureExtractorService(
            mq_client=mq_client_instance,
            input_exchange_name=PARSED_PACKETS_EXCHANGE_NAME,
            input_queue_name=PARSED_PACKETS_QUEUE_NAME,
            output_exchange_name=FEATURES_EXCHANGE_NAME,
            output_routing_key=FEATURES_QUEUE_ROUTING_KEY
        )
        
        logger.info(f"Starting feature extraction. Consuming from '{PARSED_PACKETS_QUEUE_NAME}'. Press Ctrl+C to stop.")
        feature_service.start_consuming()

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Feature Extractor Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block of Feature Extractor: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("Feature Extractor Service Example finished.")
