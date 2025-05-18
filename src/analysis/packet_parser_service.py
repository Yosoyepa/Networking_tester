"""
Packet Parser Service

Consumes raw frames from a message queue, parses them using Scapy, 
and publishes structured parsed packet data to another message queue.
"""
import base64
import logging
import uuid
import time
import pika
from scapy.all import Ether, IP, TCP, UDP, ICMP, Dot11, LLC, SNAP
from scapy.error import Scapy_Exception

from src.messaging.rabbitmq_client import RabbitMQClient # Assuming RabbitMQ
from src.messaging.schemas import RawFrame, ParsedPacket, PARSED_PACKETS_TOPIC, RAW_FRAMES_TOPIC

logger = logging.getLogger(__name__)

class PacketParserService:
    def __init__(self, mq_client: RabbitMQClient, 
                 input_exchange_name: str, input_queue_name: str, 
                 output_exchange_name: str, output_routing_key: str):
        """
        Initializes the PacketParserService.

        Args:
            mq_client: An instance of the message queue client.
            input_exchange_name: Exchange to bind the input queue to.
            input_queue_name: Queue to consume raw frames from.
            output_exchange_name: Exchange to publish parsed packets to.
            output_routing_key: Routing key for publishing parsed packets.
        """
        self.mq_client = mq_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.output_exchange_name = output_exchange_name
        self.output_routing_key = output_routing_key

        # Declare exchanges and queue for consuming and publishing
        self._setup_messaging()

    def _setup_messaging(self):
        logger.info(f"Setting up messaging for PacketParserService.")
        # Input: Consuming from raw_frames_queue bound to raw_frames_exchange
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_queue_name) # Assuming queue name is routing key
        
        # Output: Publishing to an exchange (e.g., parsed_packets_exchange)
        self.mq_client.declare_exchange(self.output_exchange_name, exchange_type='direct')
        # The queue for parsed packets will be declared by its consumer(s), 
        # but we need to ensure the exchange exists.
        # If this service also creates the queue it publishes to (e.g. for direct routing):
        # self.mq_client.declare_queue(self.output_routing_key, self.output_exchange_name, self.output_routing_key)
        logger.info(f"Messaging setup complete. Consuming from {self.input_queue_name}, publishing to {self.output_exchange_name} with key {self.output_routing_key}") 

    def _parse_packet_layers(self, frame_bytes: bytes, raw_frame_id: str, original_timestamp: str) -> ParsedPacket | None:
        """
        Parses a raw frame using Scapy and extracts layer information.
        """
        try:
            # Attempt to decode as Ethernet first, common for wired and some PCAPs
            try:
                packet = Ether(frame_bytes)
            except Scapy_Exception:
                # If Ether() fails, it might be a raw 802.11 frame or other L2 type
                # For this example, we'll try Dot11 directly if Ether fails.
                # A more robust solution might inspect frame_bytes for clues or try multiple decodes.
                packet = Dot11(frame_bytes) # This might also fail if it's not 802.11
            
            layers_data = {}
            current_layer = packet
            
            # Ethernet Layer
            if current_layer.haslayer(Ether):
                ether_layer = current_layer[Ether]
                layers_data['ethernet'] = {
                    'src_mac': ether_layer.src,
                    'dst_mac': ether_layer.dst,
                    'type': hex(ether_layer.type)
                }
                current_layer = ether_layer.payload

            # IEEE 802.11 Layer
            # Note: Scapy's Dot11 layer can be complex. This is a simplified extraction.
            if packet.haslayer(Dot11):
                dot11_layer = packet[Dot11]
                dot11_info = {
                    'type': dot11_layer.type,       # Management, Control, Data
                    'subtype': dot11_layer.subtype,
                    'addr1': dot11_layer.addr1,     # Receiver Address
                    'addr2': dot11_layer.addr2,     # Transmitter Address
                    'addr3': dot11_layer.addr3,     # BSSID or Source/Destination Address
                    'SC': dot11_layer.SC,         # Sequence Control
                }
                if dot11_layer.addr4: # Check if Addr4 is present (e.g., in WDS frames)
                    dot11_info['addr4'] = dot11_layer.addr4
                if dot11_layer.haslayer(LLC) and dot11_layer.haslayer(SNAP):
                     dot11_info['llc_snap_oui'] = dot11_layer[SNAP].OUI
                     dot11_info['llc_snap_code'] = dot11_layer[SNAP].code
                
                # Check for RadioTap header if present (often prepended in monitor mode captures)
                # Scapy might parse RadioTap as a separate layer before Dot11 if it's the outermost
                # If Ether(frame_bytes) was used and it was a 802.11 frame with RadioTap, Ether() might fail or misinterpret.
                # If Dot11(frame_bytes) was used, RadioTap should be handled by Scapy if it's part of the Dot11 layer itself.
                # For this example, we assume RadioTap is handled if Dot11 is the primary layer.
                # A more robust parser might explicitly check for RadioTap: `if packet.haslayer(RadioTap): ...`

                layers_data['dot11'] = dot11_info
                # The payload of Dot11 might be LLC/SNAP then IP, or directly IP if LLC/SNAP is handled implicitly
                current_layer = dot11_layer.payload # This is often LLC/SNAP or data
                if current_layer.haslayer(LLC):
                    current_layer = current_layer[LLC].payload
                    if current_layer.haslayer(SNAP):
                        current_layer = current_layer[SNAP].payload
            
            # IP Layer (IPv4 or IPv6)
            if current_layer.haslayer(IP):
                ip_layer = current_layer[IP]
                layers_data['ip'] = {
                    'version': ip_layer.version,
                    'ihl': ip_layer.ihl,
                    'tos': ip_layer.tos,
                    'len': ip_layer.len,
                    'id': ip_layer.id,
                    'flags': str(ip_layer.flags), # Convert flags to string
                    'frag': ip_layer.frag,
                    'ttl': ip_layer.ttl,
                    'proto': ip_layer.proto,
                    'chksum': hex(ip_layer.chksum),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst
                }
                current_layer = ip_layer.payload
            # Add IPv6 support here if needed: elif current_layer.haslayer(IPv6): ...

            # Transport Layer (TCP, UDP, ICMP)
            if current_layer.haslayer(TCP):
                tcp_layer = current_layer[TCP]
                layers_data['tcp'] = {
                    'sport': tcp_layer.sport,
                    'dport': tcp_layer.dport,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack,
                    'dataofs': tcp_layer.dataofs,
                    'reserved': tcp_layer.reserved,
                    'flags': str(tcp_layer.flags), # Convert flags to string
                    'window': tcp_layer.window,
                    'chksum': hex(tcp_layer.chksum),
                    'urgptr': tcp_layer.urgptr,
                    'options': [(opt[0], opt[1]) for opt in tcp_layer.options] # List of tuples for options
                }
            elif current_layer.haslayer(UDP):
                udp_layer = current_layer[UDP]
                layers_data['udp'] = {
                    'sport': udp_layer.sport,
                    'dport': udp_layer.dport,
                    'len': udp_layer.len,
                    'chksum': hex(udp_layer.chksum)
                }
            elif current_layer.haslayer(ICMP):
                icmp_layer = current_layer[ICMP]
                layers_data['icmp'] = {
                    'type': icmp_layer.type,
                    'code': icmp_layer.code,
                    'chksum': hex(icmp_layer.chksum),
                    # ICMP payloads vary, e.g., id and seq for echo
                    'id': getattr(icmp_layer, 'id', None), 
                    'seq': getattr(icmp_layer, 'seq', None)
                }
            
            if not layers_data: # If no known layers were parsed
                logger.warning(f"Could not parse known L2/L3/L4 layers for raw_frame_id: {raw_frame_id}. Packet summary: {packet.summary()}")
                return None

            parsed_packet: ParsedPacket = {
                "packet_id": str(uuid.uuid4()),
                "timestamp": original_timestamp, # Use timestamp from raw frame
                "raw_frame_id": raw_frame_id, 
                "layers": layers_data,
                "metadata": {
                    "parser_service_version": "0.1.0", # Example metadata
                    "parsing_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()) # Add parsing time
                }
            }
            return parsed_packet

        except Scapy_Exception as e:
            logger.error(f"Scapy parsing error for raw_frame_id '{raw_frame_id}': {e}. Frame (first 100 bytes): {frame_bytes[:100].hex()}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing packet for raw_frame_id '{raw_frame_id}': {e}", exc_info=True)
            return None

    def _message_handler(self, raw_frame_message: RawFrame):
        """
        Callback function to process a single raw frame message from the queue.
        """
        try:
            logger.debug(f"Received raw frame message: {raw_frame_message.get('metadata',{}).get('scapy_summary', 'N/A')}")
            
            frame_bytes_b64 = raw_frame_message.get("frame_bytes")
            raw_frame_id = f"{raw_frame_message.get('interface','unknown')}_{raw_frame_message.get('timestamp')}" # Create a simple ID
            original_timestamp = raw_frame_message.get("timestamp")

            if not frame_bytes_b64 or not original_timestamp:
                logger.error(f"Malformed RawFrame message, missing frame_bytes or timestamp: {raw_frame_message}")
                return

            frame_bytes = base64.b64decode(frame_bytes_b64)
            
            parsed_packet_data = self._parse_packet_layers(frame_bytes, raw_frame_id, original_timestamp)
            
            if parsed_packet_data:
                self.mq_client.publish(
                    exchange_name=self.output_exchange_name,
                    routing_key=self.output_routing_key,
                    message=parsed_packet_data
                )
                # logger.info(f"Successfully parsed and published packet_id: {parsed_packet_data['packet_id']}")
            else:
                logger.warning(f"Failed to parse packet from raw_frame_id: {raw_frame_id}. Message will not be published.")

        except json.JSONDecodeError as json_err: # If the message itself is not valid JSON (should be handled by RabbitMQClient)
            logger.error(f"JSON decoding error in message_handler: {json_err}. Message body was: {raw_frame_message}")
        except KeyError as ke:
            logger.error(f"Missing key in raw_frame_message: {ke}. Message: {raw_frame_message}")
        except Exception as e:
            logger.error(f"Error in PacketParserService message_handler: {e}", exc_info=True)
            # Potentially implement a dead-letter queue mechanism here or rely on RabbitMQ's

    def start_consuming(self):
        """
        Starts consuming messages from the input queue and processing them.
        This method will block until consumption is stopped (e.g., by KeyboardInterrupt).
        """
        logger.info(f"PacketParserService starting to consume from queue: '{self.input_queue_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=False # Manual acknowledgement for better error handling
            )
        except Exception as e:
            logger.error(f"PacketParserService failed to start consuming: {e}", exc_info=True)
            # Ensure client is closed if an error occurs during setup or consumption start
            if self.mq_client:
                self.mq_client.close()
            raise # Re-raise the exception to signal failure to the orchestrator
        finally:
            logger.info("PacketParserService consumption loop finished or was interrupted.")


if __name__ == '__main__':
    import json # For the json.JSONDecodeError catch block
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # --- Configuration ---
    RABBITMQ_HOST = 'localhost'
    RABBITMQ_PORT = 5672
    # RABBITMQ_USER = 'user'
    # RABBITMQ_PASS = 'password'

    # Exchange and Queue names (should align with PacketIngestorService output and FeatureExtractorService input)
    RAW_FRAMES_EXCHANGE_NAME = "raw_frames_exchange"
    RAW_FRAMES_QUEUE_NAME = "raw_frames_queue" # Parser consumes from this queue
    
    PARSED_PACKETS_EXCHANGE_NAME = "parsed_packets_exchange"
    PARSED_PACKETS_QUEUE_ROUTING_KEY = "parsed_packets_queue" # Parser publishes with this routing key
                                                              # (consumers of parsed packets will listen to this queue)

    logger.info("Initializing Packet Parser Service Example...")
    mq_client_instance = None
    try:
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        # The service itself handles declaring its input queue and output exchange.
        # If the output queue (PARSED_PACKETS_QUEUE_ROUTING_KEY) needs to be explicitly created by the parser,
        # it should also be declared here or in _setup_messaging.
        # For a direct exchange, the consumer of parsed_packets typically declares the queue and binds it.
        # Let's ensure the output exchange exists, and if we want a specific queue for parsed packets created by parser:
        mq_client_instance.declare_exchange(PARSED_PACKETS_EXCHANGE_NAME, exchange_type='direct')
        mq_client_instance.declare_queue(PARSED_PACKETS_QUEUE_ROUTING_KEY, PARSED_PACKETS_EXCHANGE_NAME, PARSED_PACKETS_QUEUE_ROUTING_KEY)
        logger.info(f"Declared exchange '{PARSED_PACKETS_EXCHANGE_NAME}' and queue '{PARSED_PACKETS_QUEUE_ROUTING_KEY}' for output.")

        parser_service = PacketParserService(
            mq_client=mq_client_instance,
            input_exchange_name=RAW_FRAMES_EXCHANGE_NAME,
            input_queue_name=RAW_FRAMES_QUEUE_NAME,
            output_exchange_name=PARSED_PACKETS_EXCHANGE_NAME,
            output_routing_key=PARSED_PACKETS_QUEUE_ROUTING_KEY
        )
        
        logger.info("Starting packet parsing consumption. Press Ctrl+C to stop.")
        parser_service.start_consuming()

    except pika.exceptions.AMQPConnectionError as amqp_err: # Import pika for this
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running and accessible at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Packet Parser Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block of Packet Parser Service: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("Packet Parser Service Example finished.")
