import pika
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class MessageProducer:
    """
    A generic RabbitMQ message producer.
    """
    def __init__(self, rabbitmq_host: str = 'localhost', rabbitmq_port: int = 5672, rabbitmq_user: Optional[str] = None, rabbitmq_password: Optional[str] = None):
        """
        Initializes the MessageProducer.

        Args:
            rabbitmq_host: The hostname or IP address of the RabbitMQ server.
            rabbitmq_port: The port number of the RabbitMQ server.
            rabbitmq_user: The username for RabbitMQ authentication.
            rabbitmq_password: The password for RabbitMQ authentication.
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user
        self.rabbitmq_password = rabbitmq_password
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel: Optional[pika.adapters.blocking_connection.BlockingChannel] = None
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
            # Depending on the application's needs, this could raise an exception
            # or implement a retry mechanism.

    def declare_queue(self, queue_name: str, durable: bool = True):
        """
        Declares a queue.

        Args:
            queue_name: The name of the queue.
            durable: If True, the queue will survive a broker restart.
        """
        if not self.channel:
            logger.error("Cannot declare queue: No channel available. Connection might have failed.")
            return
        try:
            self.channel.queue_declare(queue=queue_name, durable=durable)
            logger.info(f"Queue '{queue_name}' declared successfully (durable={durable}).")
        except Exception as e:
            logger.error(f"Failed to declare queue '{queue_name}': {e}")


    def publish_message(self, queue_name: str, message_body: Dict[str, Any], exchange: str = '', delivery_mode: int = 2):
        """
        Publishes a message to the specified queue.

        Args:
            queue_name: The name of the target queue (used as routing_key if default exchange).
            message_body: The message content as a dictionary (will be JSON serialized).
            exchange: The exchange to publish to. Defaults to the default exchange.
            delivery_mode: 2 for persistent messages, 1 for transient.
        """
        if not self.channel or not self.connection or self.connection.is_closed:
            logger.warning("Connection to RabbitMQ is not active. Attempting to reconnect...")
            self._connect() # Attempt to reconnect
            if not self.channel or not self.connection or self.connection.is_closed:
                logger.error("Failed to publish message: No active connection to RabbitMQ after attempting reconnect.")
                return False
        
        # Ensure queue exists before publishing, especially if it's a direct-to-queue scenario
        # For robustness, applications should manage queue declarations appropriately.
        # Here, we'll re-declare it to be safe for this producer's context.
        self.declare_queue(queue_name=queue_name, durable=(delivery_mode == 2))

        try:
            json_message = json.dumps(message_body)
            self.channel.basic_publish(
                exchange=exchange,
                routing_key=queue_name, # For default exchange, routing_key is the queue name
                body=json_message,
                properties=pika.BasicProperties(
                    delivery_mode=delivery_mode, # Make message persistent
                    content_type='application/json'
                )
            )
            logger.debug(f"Message published to queue '{queue_name}': {message_body}")
            return True
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"AMQP Connection Error while publishing to '{queue_name}': {e}. Attempting to reconnect.")
            self._connect() # Attempt to reconnect
            if self.channel and self.connection and not self.connection.is_closed:
                try:
                    self.declare_queue(queue_name=queue_name, durable=(delivery_mode == 2)) # Re-declare after reconnect
                    self.channel.basic_publish(
                        exchange=exchange,
                        routing_key=queue_name,
                        body=json_message,
                        properties=pika.BasicProperties(delivery_mode=delivery_mode, content_type='application/json')
                    )
                    logger.info(f"Message successfully re-published to queue '{queue_name}' after reconnect.")
                    return True
                except Exception as e_retry:
                    logger.error(f"Failed to re-publish message to '{queue_name}' after reconnect: {e_retry}")
                    return False
            else:
                logger.error("Failed to re-establish connection for publishing.")
                return False

        except Exception as e:
            logger.error(f"Failed to publish message to queue '{queue_name}': {e}")
            return False

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
    # Example Usage (requires a running RabbitMQ instance)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    
    producer = MessageProducer(rabbitmq_host='localhost')
    if producer.channel: # Check if connection was successful
        queue_name = 'test_raw_frames_queue'
        producer.declare_queue(queue_name) # Declare the queue

        # Example raw frame message (simplified)
        example_raw_frame = {
            "timestamp": "2025-05-18T10:30:05.123Z",
            "interface": "eth0",
            "capture_source_identifier": "test_capture_001",
            "frame_bytes": "AP8A/wD/AP8AAQACAwQFBgYBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oz4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8="
        }
        
        if producer.publish_message(queue_name, example_raw_frame):
            logger.info(f"Test message published to '{queue_name}'. Check RabbitMQ management console.")
        else:
            logger.error(f"Failed to publish test message to '{queue_name}'.")
        
        producer.close()
    else:
        logger.error("Could not connect to RabbitMQ. Producer not started.")
