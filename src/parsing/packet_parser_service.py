import json
import logging
import time
import uuid
from typing import Dict, Any, List, Optional

from scapy.all import Ether, IP, TCP, UDP, ICMP, Dot11, LLC, SNAP, Raw, ARP, IPv6
from src.messaging import MessageConsumer, MessageProducer

logger = logging.getLogger(__name__)

class PacketParserService:
    def __init__(self, consumer: MessageConsumer, producer: MessageProducer, 
                 raw_frames_queue: str, parsed_packets_queue: str):
        self.consumer = consumer
        self.producer = producer
        self.raw_frames_queue = raw_frames_queue
        self.parsed_packets_queue = parsed_packets_queue
        self._running = False

    def _parse_packet_layers(self, frame_bytes: bytes, original_interface: str, capture_timestamp: str, message_id: str) -> Optional[Dict[str, Any]]:
        """Parses a raw frame into a structured dictionary based on its layers."""
        try:
            # Attempt to decode as Ethernet first
            packet = Ether(frame_bytes)
            parsed_layers: Dict[str, Any] = {}

            # Ethernet Layer
            if packet.haslayer(Ether):
                parsed_layers['ethernet'] = {
                    'destination_mac': packet[Ether].dst,
                    'source_mac': packet[Ether].src,
                    'ethertype': hex(packet[Ether].type)
                }
            elif packet.haslayer(Dot11):
                dot11_layer = packet[Dot11]
                parsed_layers['dot11'] = {
                    'type_subtype': f'{dot11_layer.type}/{dot11_layer.subtype}',
                    'flags': str(dot11_layer.FCfield),
                    'duration_id': dot11_layer.ID,
                    'address1': dot11_layer.addr1, # RA
                    'address2': dot11_layer.addr2, # TA
                    'address3': dot11_layer.addr3, # DA or BSSID
                    'address4': getattr(dot11_layer, 'addr4', None), # SA (optional)
                    'sequence_control': dot11_layer.SC,
                    # TODO: Add more Dot11 fields like QoS, HT if present and needed
                }
                # For WiFi, payload might be after LLC/SNAP
                if packet.haslayer(LLC) and packet.haslayer(SNAP):
                    parsed_layers['llc_snap'] = {
                        'llc_dsap': packet[LLC].dsap,
                        'llc_ssap': packet[LLC].ssap,
                        'llc_ctrl': packet[LLC].ctrl,
                        'snap_oui': packet[SNAP].OUI,
                        'snap_pid': packet[SNAP].code
                    }
            else:
                logger.warning(f"Frame {message_id} is not Ethernet or Dot11. Type: {packet.type}")
                # Potentially handle other L2 types like SLL (Linux cooked capture)
                # For now, we'll try to find IP layer directly if L2 is unknown/unhandled

            # IP Layer (IPv4 or IPv6)
            ip_layer = None
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                parsed_layers['ip'] = {
                    'version': ip_layer.version,
                    'source_ip': ip_layer.src,
                    'destination_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'ttl': ip_layer.ttl,
                    'length': ip_layer.len,
                    'header_length': ip_layer.ihl * 4, # IHL is in 4-byte words
                    'flags': str(ip_layer.flags),
                    'fragment_offset': ip_layer.frag,
                    'id': ip_layer.id,
                    'checksum': hex(ip_layer.chksum)
                }
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                ip_layer = ipv6_layer # for subsequent protocol checks
                parsed_layers['ipv6'] = {
                    'version': ipv6_layer.version,
                    'source_ip': ipv6_layer.src,
                    'destination_ip': ipv6_layer.dst,
                    'traffic_class': ipv6_layer.tc,
                    'flow_label': ipv6_layer.fl,
                    'payload_length': ipv6_layer.plen,
                    'next_header': ipv6_layer.nh, # Protocol
                    'hop_limit': ipv6_layer.hlim
                }
            
            # ARP Layer (often directly over Ethernet, not IP)
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                parsed_layers['arp'] = {
                    'hwtype': arp_layer.hwtype,
                    'ptype': arp_layer.ptype,
                    'hwlen': arp_layer.hwlen,
                    'plen': arp_layer.plen,
                    'op': arp_layer.op, # 1 for request, 2 for reply
                    'hwsrc': arp_layer.hwsrc,
                    'psrc': arp_layer.psrc,
                    'hwdst': arp_layer.hwdst,
                    'pdst': arp_layer.pdst
                }

            # Transport Layer (TCP, UDP, ICMP)
            # Note: Scapy's haslayer checks on ip_layer if it exists, otherwise on packet
            target_for_transport = ip_layer if ip_layer else packet

            if target_for_transport.haslayer(TCP):
                tcp_layer = target_for_transport[TCP]
                parsed_layers['tcp'] = {
                    'source_port': tcp_layer.sport,
                    'destination_port': tcp_layer.dport,
                    'sequence_number': tcp_layer.seq,
                    'acknowledgment_number': tcp_layer.ack,
                    'data_offset': tcp_layer.dataofs * 4 if tcp_layer.dataofs else 0, # Data offset in 4-byte words
                    'flags': {
                        'fin': bool(tcp_layer.flags.F), 'syn': bool(tcp_layer.flags.S),
                        'rst': bool(tcp_layer.flags.R), 'psh': bool(tcp_layer.flags.P),
                        'ack': bool(tcp_layer.flags.A), 'urg': bool(tcp_layer.flags.U),
                        'ece': bool(tcp_layer.flags.E), 'cwr': bool(tcp_layer.flags.C)
                    },
                    'window_size': tcp_layer.window,
                    'checksum': hex(tcp_layer.chksum),
                    'urgent_pointer': tcp_layer.urgptr,
                    'options': [(opt[0], opt[1]) for opt in tcp_layer.options] # List of (type, value) tuples
                }
            elif target_for_transport.haslayer(UDP):
                udp_layer = target_for_transport[UDP]
                parsed_layers['udp'] = {
                    'source_port': udp_layer.sport,
                    'destination_port': udp_layer.dport,
                    'length': udp_layer.len,
                    'checksum': hex(udp_layer.chksum)
                }
            elif target_for_transport.haslayer(ICMP):
                icmp_layer = target_for_transport[ICMP]
                parsed_layers['icmp'] = {
                    'type': icmp_layer.type,
                    'code': icmp_layer.code,
                    'checksum': hex(icmp_layer.chksum)
                    # ICMP messages have varying fields based on type/code (e.g., id, seq for echo)
                    # Add more specific fields if needed, e.g., for echo:
                    # 'id': icmp_layer.id if hasattr(icmp_layer, 'id') else None,
                    # 'sequence': icmp_layer.seq if hasattr(icmp_layer, 'seq') else None
                }

            # Payload / Raw Data
            if target_for_transport.haslayer(Raw):
                payload_bytes = bytes(target_for_transport[Raw].load)
                parsed_layers['payload'] = {
                    'payload_bytes_base64': base64.b64encode(payload_bytes).decode('utf-8'),
                    'payload_length_original': len(payload_bytes)
                }
            
            if not parsed_layers: # If no known layers were parsed
                logger.warning(f"Could not parse known L2/L3 layers for frame {message_id}. Raw dump: {packet.show(dump=True)}")
                return None

            return parsed_layers
        except Exception as e:
            logger.error(f"Error parsing packet {message_id}: {e}", exc_info=True)
            return None # Indicate parsing failure

    def _process_raw_frame(self, channel, method, properties, body):
        """Callback function to process a single raw frame message."""
        try:
            raw_frame_msg = json.loads(body.decode('utf-8'))
            logger.debug(f"Received raw frame: {raw_frame_msg.get('message_id')}")

            message_id = raw_frame_msg.get('message_id', str(uuid.uuid4()))
            schema_version = raw_frame_msg.get('schema_version')
            capture_timestamp = raw_frame_msg['timestamp']
            source_info = raw_frame_msg['source']
            frame_data = raw_frame_msg['frame_data']

            original_interface = source_info.get('identifier', 'unknown')
            frame_bytes_b64 = frame_data['raw_bytes_base64']
            
            try:
                frame_bytes = base64.b64decode(frame_bytes_b64)
            except base64.binascii.Error as b64_err:
                logger.error(f"Base64 decode error for message {message_id}: {b64_err}")
                channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Dead-letter the message
                return

            parsed_layers = self._parse_packet_layers(frame_bytes, original_interface, capture_timestamp, message_id)
            parsing_errors = []
            if parsed_layers is None:
                parsing_errors.append("Failed to parse packet layers or packet was malformed.")
                # Potentially publish a minimal error message or just log and NACK

            parsed_packet_msg = {
                "schema_version": "1.0", # Or a new version for parsed packets
                "parsed_packet_id": str(uuid.uuid4()),
                "original_raw_frame_id": message_id,
                "raw_frame_timestamp": capture_timestamp,
                "parsing_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(time.time())) + ("%.6f" % (time.time() % 1))[2:] + 'Z',
                "source_info": source_info, # Keep original source info
                "layers": parsed_layers if parsed_layers else {},
                "parsing_errors": parsing_errors
            }

            self.producer.publish_message(parsed_packet_msg, self.parsed_packets_queue)
            logger.debug(f"Published parsed packet for raw frame {message_id} to {self.parsed_packets_queue}")
            channel.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for incoming message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Dead-letter
        except KeyError as e:
            logger.error(f"Missing key in raw frame message: {e}. Body: {body[:200]}...", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Dead-letter
        except Exception as e:
            logger.error(f"Unexpected error processing raw frame: {e}", exc_info=True)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue for transient errors

    def start(self):
        """Connects to RabbitMQ and starts consuming raw frames."""
        if self._running:
            logger.info("PacketParserService is already running.")
            return

        logger.info("Starting PacketParserService...")
        try:
            self.consumer.connect()
            self.producer.connect() # Ensure producer is also connected
            
            # Consumer declares the raw_frames_queue, Producer declares the parsed_packets_queue
            # This is handled within their respective connect/publish methods if designed so,
            # or we can explicitly declare here if needed.
            # For now, assuming MessageConsumer/Producer handle their queue declarations.

            self.consumer.start_consuming(self.raw_frames_queue, self._process_raw_frame)
            self._running = True
            logger.info(f"PacketParserService started. Consuming from '{self.raw_frames_queue}' and publishing to '{self.parsed_packets_queue}'.")
            # Keep the service running (e.g., in a loop or by blocking on consumer)
            # The current MessageConsumer.start_consuming is likely blocking, so this might be okay.
            # If not, a while self._running: time.sleep(1) loop might be needed here.
        except Exception as e:
            logger.error(f"Failed to start PacketParserService: {e}", exc_info=True)
            self._running = False # Ensure state is correct if start fails
            # Potentially re-raise or handle to allow for retries by an orchestrator

    def stop(self):
        """Stops the PacketParserService and closes connections."""
        logger.info("Stopping PacketParserService...")
        self._running = False # Signal any loops to stop
        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.close()
        logger.info("PacketParserService stopped.")

# Example Usage (for testing purposes)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    RABBITMQ_HOST = 'localhost'
    RAW_FRAMES_QUEUE = 'raw_frames_queue'
    PARSED_PACKETS_QUEUE = 'parsed_packets_queue'

    # Dummy Raw Frame message for testing (matches the new schema)
    import base64
    dummy_eth_packet = Ether()/IP(dst="1.2.3.4")/TCP(dport=80)/"GET / HTTP/1.0\r\n\r\n"
    dummy_frame_bytes = bytes(dummy_eth_packet)
    dummy_frame_base64 = base64.b64encode(dummy_frame_bytes).decode('utf-8')
    
    raw_frame_example = {
        "schema_version": "1.0",
        "message_id": str(uuid.uuid4()),
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime(time.time())) + ("%.6f" % (time.time() % 1))[2:] + 'Z',
        "source": {
            "type": "live_capture",
            "identifier": "eth_test"
        },
        "frame_data": {
            "raw_bytes_base64": dummy_frame_base64,
            "original_length": len(dummy_frame_bytes),
            "scapy_summary": "ETH/IP/TCP"
        },
        "metadata": {
            "processing_stage": "ingestion"
        }
    }

    consumer = None
    producer = None
    parser_service = None

    try:
        # Producer to send a test message
        test_producer = MessageProducer(host=RABBITMQ_HOST)
        test_producer.connect()
        test_producer.publish_message(raw_frame_example, RAW_FRAMES_QUEUE)
        logger.info(f"Sent test raw frame to '{RAW_FRAMES_QUEUE}'. Message ID: {raw_frame_example['message_id']}")
        test_producer.close()

        # Setup consumer and producer for the service
        consumer = MessageConsumer(host=RABBITMQ_HOST, prefetch_count=10) # Added prefetch_count
        producer = MessageProducer(host=RABBITMQ_HOST)
        
        # The service itself will connect them
        parser_service = PacketParserService(consumer, producer, RAW_FRAMES_QUEUE, PARSED_PACKETS_QUEUE)
        parser_service.start() # This will block if consumer.start_consuming is blocking

        # To allow graceful shutdown, you'd typically run start() in a thread
        # and then have a main loop that waits for a KeyboardInterrupt or other signal.
        # For this simple example, we'll just let it run and expect manual stop (Ctrl+C)
        # or for it to process the one message and then the consumer might idle.
        # If start_consuming is blocking and there are no more messages, it might just hang.
        # A more robust __main__ would handle threading and graceful shutdown.
        logger.info("PacketParserService running. Press Ctrl+C to stop.")
        while parser_service._running:
             time.sleep(1) # Keep main thread alive while service runs

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Error in main: {e}", exc_info=True)
    finally:
        if parser_service:
            parser_service.stop()
        # Ensure connections are closed even if service stop wasn't called or failed
        elif consumer:
            consumer.close()
        if producer and producer.connection and producer.connection.is_open: # Check if producer was used by service
             producer.close()
        logger.info("Main script finished.")
