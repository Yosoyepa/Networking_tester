import pika
import json
from typing import Callable, Dict, Any
import logging
import time

logger = logging.getLogger(__name__)

class RabbitMQClient:
    def __init__(self, host='localhost', port=5672, username=None, password=None, max_retries=5, retry_delay=5):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.connection = None
        self.channel = None
        self._connect()

    def _connect(self):
        credentials = None
        if self.username and self.password:
            credentials = pika.PlainCredentials(self.username, self.password)
        
        params = pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            credentials=credentials,
            heartbeat=600,  # Keep connection alive
            blocked_connection_timeout=300 # Timeout for blocked connection
        )
        
        retries = 0
        while retries < self.max_retries:
            try:
                self.connection = pika.BlockingConnection(params)
                self.channel = self.connection.channel()
                logger.info(f"Successfully connected to RabbitMQ at {self.host}:{self.port}")
                return
            except (pika.exceptions.AMQPConnectionError, pika.exceptions.AMQPChannelError) as e:
                retries += 1
                logger.error(f"Failed to connect to RabbitMQ (attempt {retries}/{self.max_retries}): {e}")
                if retries < self.max_retries:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error("Max retries reached. Could not connect to RabbitMQ.")
                    raise

    def _ensure_connected(self):
        if not self.connection or self.connection.is_closed or not self.channel or self.channel.is_closed:
            logger.warning("RabbitMQ connection lost. Attempting to reconnect...")
            self._connect()

    def declare_exchange(self, exchange_name: str, exchange_type='direct'):
        self._ensure_connected()
        try:
            self.channel.exchange_declare(exchange=exchange_name, exchange_type=exchange_type, durable=True)
            logger.info(f"Exchange '{exchange_name}' of type '{exchange_type}' declared successfully.")
        except Exception as e:
            logger.error(f"Failed to declare exchange '{exchange_name}': {e}")
            raise

    def declare_queue(self, queue_name: str, exchange_name: str = None, routing_key: str = None):
        self._ensure_connected()
        if routing_key is None:
            routing_key = queue_name # Default routing key to queue name if not specified
        try:
            self.channel.queue_declare(queue=queue_name, durable=True)
            logger.info(f"Queue '{queue_name}' declared successfully.")
            if exchange_name:
                self.channel.queue_bind(exchange=exchange_name, queue=queue_name, routing_key=routing_key)
                logger.info(f"Queue '{queue_name}' bound to exchange '{exchange_name}' with routing key '{routing_key}'.")
        except Exception as e:
            logger.error(f"Failed to declare or bind queue '{queue_name}': {e}")
            raise

    def publish(self, exchange_name: str, routing_key: str, message: Dict[str, Any]):
        self._ensure_connected()
        try:
            body = json.dumps(message)
            self.channel.basic_publish(
                exchange=exchange_name,
                routing_key=routing_key,
                body=body,
                properties=pika.BasicProperties(
                    delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE # Make message persistent
                )
            )
            # logger.debug(f"Published to exchange '{exchange_name}', routing key '{routing_key}': {message}")
        except Exception as e:
            logger.error(f"Failed to publish message to exchange '{exchange_name}', routing key '{routing_key}': {e}")
            # Consider re-raising or specific handling like dead-lettering
            raise

    def consume(self, queue_name: str, callback_function: Callable[[Dict[str, Any]], None], auto_ack=False):
        self._ensure_connected()
        
        def wrapper_callback(ch, method, properties, body):
            try:
                message = json.loads(body)
                # logger.debug(f"Received message from queue '{queue_name}': {message}")
                callback_function(message) # Call the user-provided callback
                if not auto_ack:
                    ch.basic_ack(delivery_tag=method.delivery_tag)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON message from queue '{queue_name}': {e}. Body: {body}")
                if not auto_ack:
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Don't requeue malformed message
            except Exception as e:
                logger.error(f"Error processing message from queue '{queue_name}': {e}")
                if not auto_ack:
                    # Requeue for transient errors, or nack for permanent ones
                    # For simplicity, nack without requeue here. Consider more sophisticated error handling.
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        
        try:
            self.channel.basic_qos(prefetch_count=1) # Process one message at a time
            self.channel.basic_consume(queue=queue_name, on_message_callback=wrapper_callback, auto_ack=auto_ack)
            logger.info(f"Starting to consume messages from queue '{queue_name}'. Waiting for messages...")
            self.channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Consumer interrupted. Stopping...")
            self.stop_consuming()
        except Exception as e:
            logger.error(f"Error while consuming from queue '{queue_name}': {e}")
            self.close()
            raise

    def stop_consuming(self):
        if self.channel and hasattr(self.channel, 'is_consuming') and self.channel.is_consuming:
            self.channel.stop_consuming()
            logger.info("Stopped consuming messages.")
        elif self.channel and not hasattr(self.channel, 'is_consuming'):
            # Fallback or alternative check if is_consuming is not available
            # This might indicate a different pika version or an unexpected state.
            # For now, we can try to stop it, but log a warning.
            logger.warning("'is_consuming' attribute not found on channel. Attempting to stop_consuming anyway.")
            try:
                self.channel.stop_consuming() # Try to stop, might raise an error if not in a consuming state
                logger.info("Stopped consuming messages (fallback attempt).")
            except Exception as e:
                logger.error(f"Error during fallback stop_consuming: {e}")
        else:
            logger.info("Channel is not consuming or not available.")

    def close(self):
        self.stop_consuming()
        if self.channel and self.channel.is_open:
            try:
                self.channel.close()
                logger.info("RabbitMQ channel closed.")
            except Exception as e:
                logger.error(f"Error closing RabbitMQ channel: {e}")
        if self.connection and self.connection.is_open:
            try:
                self.connection.close()
                logger.info("RabbitMQ connection closed.")
            except Exception as e:
                logger.error(f"Error closing RabbitMQ connection: {e}")
        self.channel = None
        self.connection = None

# Example usage (for testing purposes, typically not in a library file)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Configuration (ideally from a config file/env vars)
    RABBITMQ_HOST = 'localhost' # Replace with your RabbitMQ host if different
    RABBITMQ_PORT = 5672
    # RABBITMQ_USER = 'user'
    # RABBITMQ_PASS = 'password'

    # Topics and Queues from schemas.py or constants
    RAW_FRAMES_TOPIC = "raw_frames_exchange"
    PARSED_PACKETS_TOPIC = "parsed_packets_exchange"
    RAW_FRAMES_QUEUE = "raw_frames_queue"
    PARSED_PACKETS_QUEUE = "parsed_packets_queue"

    try:
        client = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)

        # Declare exchanges
        client.declare_exchange(RAW_FRAMES_TOPIC, exchange_type='direct')
        client.declare_exchange(PARSED_PACKETS_TOPIC, exchange_type='direct')

        # Declare queues and bind them
        client.declare_queue(RAW_FRAMES_QUEUE, RAW_FRAMES_TOPIC, RAW_FRAMES_QUEUE) # routing_key = queue_name
        client.declare_queue(PARSED_PACKETS_QUEUE, PARSED_PACKETS_TOPIC, PARSED_PACKETS_QUEUE)

        # Example publisher
        def publish_example():
            logger.info("Starting publisher example...")
            for i in range(5):
                raw_frame_message = {"timestamp": time.time(), "interface": "eth0", "frame_bytes": f"data{i}"}
                client.publish(RAW_FRAMES_TOPIC, RAW_FRAMES_QUEUE, raw_frame_message)
                logger.info(f"Sent raw frame: {raw_frame_message}")
                time.sleep(1)
            logger.info("Publisher example finished.")

        # Example consumer callback
        def raw_frame_processor(message: Dict[str, Any]):
            logger.info(f"Processing raw frame: {message}")
            # Simulate parsing
            parsed_packet = {
                "packet_id": f"pkt_{message['timestamp']}",
                "raw_frame_id": message['timestamp'],
                "layers": {"detail": f"parsed_{message['frame_bytes']}"}
            }
            # Publish to the next queue
            client.publish(PARSED_PACKETS_TOPIC, PARSED_PACKETS_QUEUE, parsed_packet)
            logger.info(f"Published parsed packet: {parsed_packet}")

        # Run publisher in a separate thread or process for testing, or call directly
        # For this example, we'll just call it. In a real app, consumers run continuously.
        # import threading
        # publisher_thread = threading.Thread(target=publish_example)
        # publisher_thread.start()

        # Start a consumer (this will block)
        # To test both, you'd run the publisher and consumer in separate scripts/terminals
        # or use threading as shown above (and ensure client is thread-safe or use separate instances)
        
        # publish_example() # Uncomment to publish some messages before starting consumer

        logger.info(f"Starting consumer for '{RAW_FRAMES_QUEUE}'. Press Ctrl+C to stop.")
        # client.consume(RAW_FRAMES_QUEUE, raw_frame_processor)
        # To run a consumer for parsed packets:
        # client.consume(PARSED_PACKETS_QUEUE, lambda msg: logger.info(f"Received parsed packet: {msg}"))

    except Exception as e:
        logger.error(f"An error occurred in the example: {e}")
    finally:
        if 'client' in locals() and client:
            client.close()
            logger.info("RabbitMQ client closed in finally block.")
