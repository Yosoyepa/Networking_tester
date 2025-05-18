"""
Core Analysis and Aggregation Service

Consumes ParsedPacket and MLResult messages, performs correlation,
applies rule-based detection, and generates aggregated analysis results.
"""
import logging
import time
import os
from typing import Dict, Any, Optional, List, Union, TypedDict # Added TypedDict
from collections import defaultdict # Added for flow tracking
import uuid # Added for generating unique IDs
import datetime # Added for correct timestamp handling

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import ParsedPacket, MLResult, AnalysisResult, PARSED_PACKETS_TOPIC, ML_RESULTS_TOPIC, ANALYSIS_RESULTS_TOPIC
from src.utils.logger_config import setup_logging

logger = logging.getLogger(__name__)

# Configuration for exchanges and queues
# Consumes from parsed_packets_exchange and ml_results_exchange
# Publishes to analysis_results_exchange

PARSED_PACKETS_EXCHANGE_NAME = "parsed_packets_exchange"
PARSED_PACKETS_QUEUE_NAME_FOR_ANALYSIS = "parsed_packets_for_analysis_queue"

ML_RESULTS_EXCHANGE_NAME = "ml_results_exchange"
ML_RESULTS_QUEUE_NAME_FOR_ANALYSIS = "ml_results_for_analysis_queue"

ANALYSIS_RESULTS_EXCHANGE_NAME = "analysis_results_exchange"
ANALYSIS_RESULTS_QUEUE_ROUTING_KEY = "analysis_results_queue" # Publishes with this routing key (queue name)

# Flow Analysis Configuration
FLOW_INACTIVITY_TIMEOUT_SECONDS = 60  # Time in seconds to consider a flow inactive
MAX_PACKETS_PER_FLOW_FOR_SUMMARY = 100 # Max packets to track before emitting a summary (for this example)

class FlowState(TypedDict):
    flow_id: str
    first_packet_timestamp: float # Store as float for easy comparison
    last_packet_timestamp: float
    packet_count: int
    byte_count: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[int] # IP Protocol number
    packet_ids: List[str]
    # Add other metrics as needed, e.g., TCP flags, etc.

class CoreAnalysisService:
    def __init__(self, mq_client: RabbitMQClient,
                 parsed_packets_exchange: str, parsed_packets_queue: str,
                 ml_results_exchange: str, ml_results_queue: str,
                 output_exchange: str, output_routing_key: str):
        """
        Initializes the CoreAnalysisService.

        Args:
            mq_client: An instance of the message queue client.
            parsed_packets_exchange: Exchange for ParsedPacket messages.
            parsed_packets_queue: Queue to consume ParsedPacket messages from.
            ml_results_exchange: Exchange for MLResult messages.
            ml_results_queue: Queue to consume MLResult messages from.
            output_exchange: Exchange to publish AnalysisResult messages to.
            output_routing_key: Routing key for publishing AnalysisResult messages.
        """
        self.mq_client = mq_client
        self.parsed_packets_exchange = parsed_packets_exchange
        self.parsed_packets_queue = parsed_packets_queue
        self.ml_results_exchange = ml_results_exchange
        self.ml_results_queue = ml_results_queue
        self.output_exchange = output_exchange
        self.output_routing_key = output_routing_key

        # In-memory storage for recent packets/results for correlation (simple example)
        # For a production system, a dedicated cache (Redis) or database would be used.
        self.recent_packets: Dict[str, ParsedPacket] = {}
        self.recent_ml_results: Dict[str, MLResult] = {}
        self.recent_analysis_results: Dict[str, AnalysisResult] = {} # Added initialization
        self.MAX_RECENT_ITEMS = 1000 # Max items to keep in memory

        # Flow analysis state
        # NOTE: For distributed state, this would be replaced by a connection to Redis or similar.
        # The keys would be flow_ids, and values would be FlowState objects (serialized).
        self.active_flows: Dict[str, FlowState] = defaultdict(lambda: {})
        # For managing timeouts (in-memory version)
        # In a distributed system, a more robust mechanism like Redis sorted sets (by last_packet_timestamp)
        # or a dedicated cleanup task would be needed.
        self.flow_last_seen: Dict[str, float] = {}

        self._setup_messaging()

    def _setup_messaging(self):
        logger.info("Setting up messaging for CoreAnalysisService.")

        # Input: Consuming ParsedPacket messages
        self.mq_client.declare_exchange(self.parsed_packets_exchange, exchange_type='direct')
        self.mq_client.declare_queue(self.parsed_packets_queue, self.parsed_packets_exchange, self.parsed_packets_queue)

        # Input: Consuming MLResult messages
        self.mq_client.declare_exchange(self.ml_results_exchange, exchange_type='direct')
        self.mq_client.declare_queue(self.ml_results_queue, self.ml_results_exchange, self.ml_results_queue)
        
        # Output: Publishing AnalysisResult messages
        self.mq_client.declare_exchange(self.output_exchange, exchange_type='direct')
        self.mq_client.declare_queue(self.output_routing_key, self.output_exchange, self.output_routing_key)
        
        logger.info(f"Messaging setup complete. Consuming from {self.parsed_packets_queue} and {self.ml_results_queue}, "
                    f"publishing to {self.output_exchange} with key {self.output_routing_key}")

    def _add_to_recent_items(self, item_dict: Dict, item: Union[ParsedPacket, MLResult], item_id: str):
        if len(item_dict) >= self.MAX_RECENT_ITEMS:
            # Simple FIFO eviction
            oldest_key = next(iter(item_dict))
            item_dict.pop(oldest_key, None)
        item_dict[item_id] = item

    def _get_flow_id(self, layers: Dict[str, Any]) -> Optional[str]:
        """Generates a flow ID based on 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)."""
        ip_layer = layers.get("ip")
        tcp_layer = layers.get("tcp")
        udp_layer = layers.get("udp")

        if not ip_layer:
            return None # Not an IP packet, cannot form standard 5-tuple flow ID

        src_ip = ip_layer.get("src")
        dst_ip = ip_layer.get("dst")
        protocol = ip_layer.get("proto") # IP protocol number

        src_port = None
        dst_port = None

        if tcp_layer:
            src_port = tcp_layer.get("srcport")
            dst_port = tcp_layer.get("dstport")
        elif udp_layer:
            src_port = udp_layer.get("srcport")
            dst_port = udp_layer.get("dstport")
        # Add ICMP or other protocol specific identifiers if needed for flow definition

        if src_ip and dst_ip and protocol is not None:
            # Normalize by sorting IP/ports to ensure flow ID is same for both directions if desired
            # For this example, we'll keep it directional.
            # flow_parts = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            # return f"{flow_parts[0][0]}:{flow_parts[0][1]}-{flow_parts[1][0]}:{flow_parts[1][1]}-{protocol}"
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return None

    def _update_flow_state(self, parsed_packet_msg: ParsedPacket):
        packet_id = parsed_packet_msg.get("packet_id")
        layers = parsed_packet_msg.get("layers", {})
        timestamp_str = parsed_packet_msg.get("timestamp")
        
        if not timestamp_str:
            logger.warning(f"Packet {packet_id} missing timestamp, cannot update flow state accurately.")
            return
        
        try:
            # Assuming timestamp is ISO8601, convert to UNIX timestamp for easy comparison
            current_packet_time = time.mktime(time.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ'))
        except ValueError:
            try: # Try without fractional seconds if previous failed
                current_packet_time = time.mktime(time.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S'))
            except ValueError:
                logger.warning(f"Could not parse timestamp '{timestamp_str}' for packet {packet_id}. Using current time for flow.")
                current_packet_time = time.time()

        flow_id = self._get_flow_id(layers)
        if not flow_id:
            return # Not a packet that can be part of a flow we are tracking

        # NOTE: In a distributed system with Redis:
        # 1. Acquire a lock for the flow_id (e.g., Redlock) to prevent race conditions.
        # 2. Retrieve current FlowState from Redis (e.g., HGETALL flow_id).
        # 3. Update fields.
        # 4. Write updated FlowState back to Redis (e.g., HMSET flow_id ...).
        # 5. Update last_seen timestamp in a Redis sorted set for timeout management.
        # 6. Release lock.

        flow = self.active_flows.get(flow_id)
        if not flow: # New flow
            ip_layer = layers.get("ip", {})
            tcp_layer = layers.get("tcp", {})
            udp_layer = layers.get("udp", {})
            flow: FlowState = {
                "flow_id": flow_id,
                "first_packet_timestamp": current_packet_time,
                "last_packet_timestamp": current_packet_time,
                "packet_count": 0,
                "byte_count": 0,
                "src_ip": ip_layer.get("src"),
                "dst_ip": ip_layer.get("dst"),
                "src_port": tcp_layer.get("srcport") or udp_layer.get("srcport"),
                "dst_port": tcp_layer.get("dstport") or udp_layer.get("dstport"),
                "protocol": ip_layer.get("proto"),
                "packet_ids": []
            }
            self.active_flows[flow_id] = flow
            logger.info(f"New flow detected: {flow_id}")

        flow["last_packet_timestamp"] = current_packet_time
        flow["packet_count"] += 1
        # Assuming frame_bytes was part of RawFrame and its length could be passed to ParsedPacket metadata
        # For now, let's use a placeholder or assume IP total length if available
        ip_total_length = layers.get("ip", {}).get("len", 0) # IP total length
        flow["byte_count"] += ip_total_length if isinstance(ip_total_length, (int, float)) else 0
        if packet_id:
            flow["packet_ids"].append(packet_id)
        
        self.flow_last_seen[flow_id] = current_packet_time

        # Check if flow should be summarized (e.g., max packets reached)
        if flow["packet_count"] >= MAX_PACKETS_PER_FLOW_FOR_SUMMARY:
            logger.info(f"Flow {flow_id} reached max packet count for summary ({MAX_PACKETS_PER_FLOW_FOR_SUMMARY}). Emitting summary.")
            self._emit_flow_summary(flow_id, "max_packets_reached")
            # No need to remove from active_flows here if we want to continue tracking
            # Or, if it's a one-off summary, then remove:
            # self._remove_flow(flow_id)

    def _emit_flow_summary(self, flow_id: str, reason: str):
        flow = self.active_flows.get(flow_id)
        if not flow:
            return

        duration = flow["last_packet_timestamp"] - flow["first_packet_timestamp"]
        analysis_result: AnalysisResult = {
            "analysis_id": f"flow_summary_{flow_id.replace(':', '_').replace('-', '_')}_{uuid.uuid4().hex[:8]}",
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
            "type": "flow_summary",
            "source_packet_ids": list(flow["packet_ids"]), # Make a copy
            "source_ml_result_ids": [], # Populate if ML results are associated with flows
            "summary": f"Flow {flow_id} ended. Reason: {reason}. Duration: {duration:.2f}s, Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}.",
            "details": {
                "flow_id": flow_id,
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "start_time": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime(flow["first_packet_timestamp"])),
                "end_time": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime(flow["last_packet_timestamp"])),
                "duration_seconds": round(duration, 3),
                "packet_count": flow["packet_count"],
                "byte_count": flow["byte_count"],
                "termination_reason": reason
            },
            "severity": "info"
        }
        self._publish_analysis_result(analysis_result)
        # logger.info(f"Published flow summary for {flow_id}")

    def _remove_flow(self, flow_id: str):
        self.active_flows.pop(flow_id, None)
        self.flow_last_seen.pop(flow_id, None)
        logger.info(f"Removed flow {flow_id} from active tracking.")

    def _check_flow_timeouts(self):
        # NOTE: This is a simple in-memory timeout check. For distributed systems,
        # a more robust mechanism is needed (e.g., Redis TTLs, or a separate worker
        # querying a sorted set of flow_last_seen timestamps).
        current_time = time.time()
        timed_out_flows = []
        for flow_id, last_seen_time in list(self.flow_last_seen.items()): # list() for safe iteration if modifying dict
            if (current_time - last_seen_time) > FLOW_INACTIVITY_TIMEOUT_SECONDS:
                timed_out_flows.append(flow_id)
        
        for flow_id in timed_out_flows:
            logger.info(f"Flow {flow_id} timed out due to inactivity.")
            self._emit_flow_summary(flow_id, "inactivity_timeout")
            self._remove_flow(flow_id)

    def _handle_parsed_packet(self, parsed_packet_msg: ParsedPacket):
        packet_id = parsed_packet_msg.get("packet_id")
        if not packet_id:
            logger.warning("Received ParsedPacket message without packet_id. Skipping.")
            return

        # logger.debug(f"Received ParsedPacket: {packet_id}")
        self._add_to_recent_items(self.recent_packets, parsed_packet_msg, packet_id)

        # --- Example Rule-Based Detection ---
        # Rule: Detect HTTP traffic (port 80)
        layers = parsed_packet_msg.get("layers", {})
        tcp_layer = layers.get("tcp")
        if tcp_layer and (tcp_layer.get("dstport") == 80 or tcp_layer.get("srcport") == 80):
            analysis_result: AnalysisResult = {
                "analysis_id": f"http_detection_{packet_id}_{time.time_ns()}",
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime()),
                "type": "rule_http_traffic",
                "source_packet_ids": [packet_id],
                "source_ml_result_ids": [],
                "summary": f"HTTP traffic detected on port 80 for packet {packet_id}.",
                "details": {
                    "src_ip": layers.get("ip", {}).get("src"),
                    "dst_ip": layers.get("ip", {}).get("dst"),
                    "src_port": tcp_layer.get("srcport"),
                    "dst_port": tcp_layer.get("dstport"),
                    "packet_timestamp": parsed_packet_msg.get("timestamp")
                },
                "severity": "info"
            }
            self._publish_analysis_result(analysis_result)
        
        # --- Placeholder for Flow Analysis ---
        # Flow analysis would typically involve tracking packets belonging to the same flow
        # (e.g., 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
        # and calculating metrics like duration, byte counts, packet counts, etc.
        # This would require more sophisticated state management.

        # Update flow state with the current packet
        self._update_flow_state(parsed_packet_msg)

        # Periodically check for flow timeouts (simple approach for this example)
        # In a real service, this might be a separate thread or timer.
        if time.time() % 10 < 1: # Roughly every 10 seconds, depending on message rate
            self._check_flow_timeouts()

    def _handle_ml_result(self, ml_result_msg: MLResult):
        """
        Handles an incoming MLResult message.
        Generates an AnalysisResult based on the ML prediction.
        """
        packet_id = ml_result_msg.get("packet_id")
        model_id = ml_result_msg.get("model_id")
        model_type = ml_result_msg.get("model_type", "unknown_model_type")
        is_anomaly = ml_result_msg.get("is_anomaly", False)
        anomaly_score = ml_result_msg.get("anomaly_score") # This could be log-likelihood for GMM or recon_error for VAE
        details = ml_result_msg.get("details", {})
        threshold = details.get("threshold") # VAE might include this

        logger.info(f"Received MLResult for packet {packet_id} from model {model_id} (type: {model_type}). Anomaly: {is_anomaly}, Score: {anomaly_score}")
        self._add_to_recent_items(self.recent_ml_results, ml_result_msg, packet_id if packet_id else str(uuid.uuid4()))

        analysis_type = "ml_anomaly_detected" if is_anomaly else "ml_prediction_normal"
        severity = "info" # Default severity
        summary_parts = [f"ML Prediction from model {model_id} (type: {model_type})"]

        if model_type == "gmm":
            score_desc = "Log-Likelihood"
            if is_anomaly:
                # Example severity logic for GMM (lower scores are more anomalous)
                if anomaly_score is not None:
                    if anomaly_score < -10: # Arbitrary threshold for high severity
                        severity = "high"
                    elif anomaly_score < -5: # Arbitrary threshold for medium severity
                        severity = "medium"
                    else:
                        severity = "low"
                summary_parts.append(f"Anomaly detected by GMM.")
            else:
                summary_parts.append(f"Normal prediction by GMM.")
            if anomaly_score is not None:
                 summary_parts.append(f"{score_desc}: {anomaly_score:.4f}")
        
        elif model_type == "vae":
            score_desc = "Reconstruction Error"
            if is_anomaly:
                # Example severity logic for VAE (higher scores are more anomalous)
                if anomaly_score is not None:
                    # Adjusted logic to align with test_core_analysis_vae_integration.py expectations
                    if anomaly_score > 0.75:
                        severity = "high"
                    elif anomaly_score > 0.5: # Covers 0.5 < score <= 0.75
                        severity = "medium"
                    else: # Covers score <= 0.5
                        severity = "low"
                summary_parts.append(f"Anomaly detected by VAE.")
            else:
                summary_parts.append(f"Normal prediction by VAE.")
            if anomaly_score is not None:
                summary_parts.append(f"{score_desc}: {anomaly_score:.4f}")
            if threshold is not None: # Add threshold to summary if available for VAE
                summary_parts.append(f"Threshold: {threshold:.4f}")

        else: # Fallback for other model types
            score_desc = "Score"
            if is_anomaly:
                severity = "medium" # Default for unknown anomaly type
                summary_parts.append(f"Anomaly detected by {model_type}.")
            else:
                summary_parts.append(f"Normal prediction by {model_type}.")
            if anomaly_score is not None:
                 summary_parts.append(f"{score_desc}: {anomaly_score}")

        analysis_result: AnalysisResult = {
            "analysis_id": f"analysis_{uuid.uuid4()}",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "type": analysis_type,
            "source_packet_ids": [packet_id] if packet_id else [],
            "summary": " | ".join(summary_parts),
            "severity": severity,
            "details": {
                "model_id": model_id,
                "model_type": model_type,
                "ml_is_anomaly": is_anomaly,
                "ml_anomaly_score": anomaly_score,
                "ml_result_details": details # Include original ML details
            },
            "tags": [model_type, "ml_prediction"]
        }

        self._publish_analysis_result(analysis_result)

    def _publish_analysis_result(self, result: AnalysisResult):
        try:
            self.mq_client.publish(
                exchange_name=self.output_exchange,
                routing_key=self.output_routing_key,
                message=result
            )
            # logger.info(f"Published AnalysisResult: {result.get('analysis_id')} (Type: {result.get('type')})")
        except Exception as e:
            logger.error(f"Failed to publish AnalysisResult {result.get('analysis_id')}: {e}", exc_info=True)

    def start_consuming(self):
        logger.info(f"CoreAnalysisService starting to consume from queues: "
                    f"'{self.parsed_packets_queue}' and '{self.ml_results_queue}'")
        try:
            # Start consuming from ParsedPackets queue
            self.mq_client.consume(
                queue_name=self.parsed_packets_queue,
                callback_function=self._handle_parsed_packet,
                auto_ack=True, # Consider False for production
                consumer_tag="parsed_packet_consumer" # Unique tag
            )
            
            # Start consuming from MLResults queue
            # Note: RabbitMQClient.consume typically blocks. To consume from multiple queues
            # concurrently with a single client instance in a single thread, you'd need
            # to run consumers in separate threads or use an async client.
            # For this example, we'll assume the client handles this or we'd run multiple
            # instances/threads for a real service.
            # A simple approach for now is to call consume sequentially, but only the first
            # will block if it's a blocking call.
            # A better RabbitMQClient would allow registering multiple consumers.

            # To truly consume from both, the RabbitMQClient's consume method
            # would need to be non-blocking or manage threads.
            # For now, let's simulate by just calling the second one. If the first blocks,
            # this won't be reached in a single-threaded model.
            # This highlights a limitation in the current simple RabbitMQClient for multi-queue consumption.
            
            logger.info(f"Attempting to start consuming ML results. If parsed packet consumer is blocking, this might not start as expected in a single thread.")
            self.mq_client.consume(
                queue_name=self.ml_results_queue,
                callback_function=self._handle_ml_result,
                auto_ack=True, # Consider False for production
                consumer_tag="ml_result_consumer" # Unique tag
            )
            # If both consume calls are blocking, the program will hang on the first one.
            # A robust service would use threading or asyncio for concurrent consumption.
            # For this example, we'll assume the user might run two instances or the RabbitMQClient
            # is more advanced than the placeholder.

        except Exception as e:
            logger.error(f"CoreAnalysisService failed to start consuming: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
        finally:
            logger.info("CoreAnalysisService consumption loop finished or was interrupted.")


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    setup_logging()

    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))

    logger.info("Initializing Core Analysis Service Example...")
    mq_client_instance = None
    try:
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        # Ensure exchanges and queues this service consumes from are declared by their producers.
        # PacketParserService declares: parsed_packets_exchange, parsed_packets_queue
        # QoSMLInferenceService declares: ml_results_exchange, ml_results_queue (as its output routing key)

        # For this service, we define specific queue names it will use to bind to those exchanges.
        # This allows multiple consumers on the same exchange with different queues.

        core_analysis_service = CoreAnalysisService(
            mq_client=mq_client_instance,
            parsed_packets_exchange=PARSED_PACKETS_EXCHANGE_NAME, # Consumes from this exchange
            parsed_packets_queue=PARSED_PACKETS_QUEUE_NAME_FOR_ANALYSIS, # Its own queue for parsed packets
            ml_results_exchange=ML_RESULTS_EXCHANGE_NAME, # Consumes from this exchange
            ml_results_queue=ML_RESULTS_QUEUE_NAME_FOR_ANALYSIS, # Its own queue for ML results
            output_exchange=ANALYSIS_RESULTS_EXCHANGE_NAME, # Publishes to this exchange
            output_routing_key=ANALYSIS_RESULTS_QUEUE_ROUTING_KEY # Publishes with this key (to a queue of the same name)
        )
        
        logger.info(f"Starting Core Analysis Service. Press Ctrl+C to stop.")
        # The start_consuming method needs to handle concurrent consumption from two queues.
        # The current RabbitMQClient.consume is likely blocking.
        # For a real implementation, one might:
        # 1. Run two instances of this service, one for each input queue.
        # 2. Modify RabbitMQClient to support non-blocking consume or manage threads.
        # 3. Use an asyncio-based RabbitMQ client.
        
        # For this example, we'll print a warning about the consumption pattern.
        logger.warning("Note: The current RabbitMQClient's consume method is likely blocking. "
                       "To consume from both parsed_packets and ml_results queues concurrently "
                       "in a single service instance, the client needs to support non-blocking "
                       "operations or manage threads/async tasks. This example may only process "
                       "from the first queue registered if the consume call blocks.")

        # To demonstrate, we'll call start_consuming. If it's truly blocking on the first
        # call to self.mq_client.consume, then messages from the second queue won't be processed
        # by this single instance.
        core_analysis_service.start_consuming() 

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Core Analysis Service interrupted by user. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the main execution block: {e}", exc_info=True)
    finally:
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection.")
            mq_client_instance.close()
        logger.info("Core Analysis Service Example finished.")

