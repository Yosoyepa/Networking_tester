import pika
import json
import logging
import time
from typing import Callable, Optional, Dict, Any

logger = logging.getLogger(__name__)

class MessageConsumer:
    """
    A generic RabbitMQ message consumer.
    """
    def __init__(self, rabbitmq_host: str = 'localhost', rabbitmq_port: int = 5672, rabbitmq_user: Optional[str] = None, rabbitmq_password: Optional[str] = None):
        """
        Initializes the MessageConsumer.

        Args:
            rabbitmq_host: The hostname or IP address of the RabbitMQ server.
            rabbitmq_port: The port number of the RabbitMQ server.
            rabbitmq_user: The username for RabbitMQ authentication.
            rabbitmq_password: The password for RabbitMQ authentication.
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user # Added
        self.rabbitmq_password = rabbitmq_password # Added
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel: Optional[pika.adapters.blocking_connection.BlockingChannel] = None
        self.consumer_tag: Optional[str] = None
        self._connect()

    def _connect(self):
        """Establishes a connection to RabbitMQ and creates a channel."""        
        try:
            params = {
                'host': self.rabbitmq_host,
                'port': self.rabbitmq_port
            }
            if self.rabbitmq_user and self.rabbitmq_password:
                params['credentials'] = pika.PlainCredentials(self.rabbitmq_user, self.rabbitmq_password)

            self.connection = pika.BlockingConnection(pika.ConnectionParameters(**params))
            self.channel = self.connection.channel()
            logger.info(f"Successfully connected to RabbitMQ at {self.rabbitmq_host}:{self.rabbitmq_port}")
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"Failed to connect to RabbitMQ at {self.rabbitmq_host}:{self.rabbitmq_port}: {e}")
            self.connection = None
            self.channel = None
            # Consider retry logic or raising an exception for critical consumers

    def declare_queue(self, queue_name: str, durable: bool = True):
        """
        Declares a queue. This is idempotent.

        Args:
            queue_name: The name of the queue.
            durable: If True, the queue will survive a broker restart.
        """
        if not self.channel:
            logger.error("Cannot declare queue: No channel available. Connection might have failed.")
            return
        try:
            self.channel.queue_declare(queue=queue_name, durable=durable)
            logger.info(f"Queue '{queue_name}' declared/ensured successfully (durable={durable}).")
        except Exception as e:
            logger.error(f"Failed to declare queue '{queue_name}': {e}")

    def start_consuming(self, queue_name: str, callback_function: Callable[[Dict[str, Any]], bool], prefetch_count: int = 1):
        """
        Starts consuming messages from the specified queue.

        Args:
            queue_name: The name of the queue to consume from.
            callback_function: A function to be called when a message is received.
                               It should accept a dictionary (the JSON message body)
                               and return True if the message was processed successfully (for ACK),
                               or False otherwise (for NACK and requeue, or dead-lettering based on policy).
            prefetch_count: The maximum number of messages that the server will deliver, 
                            and that the client will hold pending acknowledgment. 
                            Set to 1 for fair dispatch and processing one message at a time.
        """
        if not self.channel or not self.connection or self.connection.is_closed:
            logger.warning("Connection to RabbitMQ is not active. Attempting to reconnect...")
            self._connect()
            if not self.channel or not self.connection or self.connection.is_closed:
                logger.error("Failed to start consuming: No active connection to RabbitMQ after attempting reconnect.")
                return

        self.declare_queue(queue_name) # Ensure queue exists
        self.channel.basic_qos(prefetch_count=prefetch_count) # For fair dispatch

        def _on_message_wrapper(ch, method, properties, body):
            try:
                message_dict = json.loads(body.decode('utf-8'))
                logger.debug(f"Received message from '{queue_name}': {message_dict}")
                
                # Execute the user-provided callback
                if callback_function(message_dict):
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                    logger.debug(f"Message acknowledged from '{queue_name}'.")
                else:
                    # Requeue the message if callback returns False. 
                    # Consider dead-letter exchange for messages that repeatedly fail.
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    logger.warning(f"Message NACKed and requeued from '{queue_name}'. Processing failed.")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON message from '{queue_name}': {e}. Message: {body[:200]}... Discarding (ACKing).")
                ch.basic_ack(delivery_tag=method.delivery_tag) # Acknowledge to remove from queue
            except Exception as e:
                logger.error(f"Unexpected error processing message from '{queue_name}': {e}. Message: {body[:200]}... Requeuing.")
                # Requeue on unexpected error, but be cautious about poison messages.
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

        self.consumer_tag = self.channel.basic_consume(
            queue=queue_name,
            on_message_callback=_on_message_wrapper,
            auto_ack=False # We will manually acknowledge
        )
        logger.info(f"Started consuming from queue '{queue_name}' with consumer tag '{self.consumer_tag}'. Waiting for messages...")
        try:
            self.channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Consumer interrupted by user. Stopping...")
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"AMQP Connection Error during consumption from '{queue_name}': {e}. Consumer stopped.")
            # Implement retry/reconnect logic here if desired for long-running consumers
        except Exception as e:
            logger.error(f"An unexpected error occurred during consumption from '{queue_name}': {e}. Consumer stopped.")
        finally:
            if self.channel and self.channel.is_open and self.consumer_tag:
                try:
                    self.channel.basic_cancel(self.consumer_tag)
                    logger.info(f"Cancelled consumer with tag '{self.consumer_tag}'.")
                except Exception as e_cancel:
                    logger.error(f"Error cancelling consumer: {e_cancel}")
            self.close() # Ensure connection is closed cleanly

    def stop_consuming(self):
        """Stops consuming messages."""
        if self.channel and self.consumer_tag:
            try:
                self.channel.basic_cancel(self.consumer_tag)
                logger.info(f"Consumer with tag '{self.consumer_tag}' cancelled.")
                # Note: For BlockingConnection, stopping consumption might also involve closing the channel/connection
                # or breaking out of the start_consuming() loop.
                # The start_consuming() method handles this in its finally block.
            except Exception as e:
                logger.error(f"Error cancelling consumer '{self.consumer_tag}': {e}")
        else:
            logger.info("No active consumer to stop or channel not available.")
        # self.close() # Typically called by the start_consuming loop's finally or when the app exits

    def close(self):
        """Closes the connection to RabbitMQ."""
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

if __name__ == '__main__':
    # Example Usage (requires a running RabbitMQ instance and a producer sending messages)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

    def my_message_processor(message_data: Dict[str, Any]) -> bool:
        logger.info(f"Processing message: {message_data}")
        # Simulate processing
        time.sleep(1)
        # Return True if processing was successful, False otherwise
        return True 

    # Example with credentials (replace with actual credentials or load from env)
    # consumer = MessageConsumer(rabbitmq_host='localhost', rabbitmq_user='user', rabbitmq_password='password')
    consumer = MessageConsumer(rabbitmq_host='localhost') # Original example for local testing without explicit creds
    if consumer.channel: # Check if connection was successful
        queue_name_to_consume = 'test_raw_frames_queue'
        consumer.declare_queue(queue_name_to_consume) # Ensure queue exists
        
        logger.info(f"Attempting to start consumer for queue: {queue_name_to_consume}")
        try:
            consumer.start_consuming(queue_name_to_consume, my_message_processor)
        except Exception as e:
            logger.error(f"Consumer example failed: {e}")
        finally:
            logger.info("Consumer example finished or was interrupted.")
            # The close() is handled by start_consuming's finally block or __exit__ if used with 'with'
    else:
        logger.error("Could not connect to RabbitMQ. Consumer not started.")
