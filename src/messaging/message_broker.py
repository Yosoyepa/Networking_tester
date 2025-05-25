"""
Message broker utilities for RabbitMQ communication.
Provides a common interface for all services to interact with RabbitMQ.
"""

import pika
import json
import logging
import time
from typing import Callable, Optional, Dict, Any
from contextlib import contextmanager
import os


class MessageBroker:
    """RabbitMQ message broker wrapper."""
    
    def __init__(self, host: str = 'localhost', port: int = 5672, 
                 username: str = 'guest', password: str = 'guest',
                 virtual_host: str = '/'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.virtual_host = virtual_host
        self.connection = None
        self.channel = None
        self.logger = logging.getLogger(__name__)
        
        # Load from environment variables if available
        self.host = os.getenv('RABBITMQ_HOST', self.host)
        self.port = int(os.getenv('RABBITMQ_PORT', self.port))
        self.username = os.getenv('RABBITMQ_USERNAME', self.username)
        self.password = os.getenv('RABBITMQ_PASSWORD', self.password)
    
    def connect(self, max_retries: int = 5, retry_delay: int = 2) -> bool:
        """Establish connection to RabbitMQ with retry logic."""
        for attempt in range(max_retries):
            try:
                credentials = pika.PlainCredentials(self.username, self.password)
                parameters = pika.ConnectionParameters(
                    host=self.host,
                    port=self.port,
                    virtual_host=self.virtual_host,
                    credentials=credentials,
                    heartbeat=600,
                    blocked_connection_timeout=300
                )
                
                self.connection = pika.BlockingConnection(parameters)
                self.channel = self.connection.channel()
                self.logger.info(f"Successfully connected to RabbitMQ at {self.host}:{self.port}")
                return True
                
            except Exception as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    self.logger.error("Failed to connect to RabbitMQ after all retries")
                    return False
        
        return False
    
    def disconnect(self):
        """Close connection to RabbitMQ."""
        try:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
                self.logger.info("Disconnected from RabbitMQ")
        except Exception as e:
            self.logger.error(f"Error disconnecting from RabbitMQ: {e}")
    
    def declare_queue(self, queue_name: str, durable: bool = True) -> bool:
        """Declare a queue."""
        try:
            if not self.channel:
                self.logger.error("No channel available. Call connect() first.")
                return False
            
            self.channel.queue_declare(queue=queue_name, durable=durable)
            self.logger.debug(f"Queue '{queue_name}' declared")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to declare queue '{queue_name}': {e}")
            return False
    
    def publish_message(self, queue_name: str, message: str, 
                       exchange: str = '', persistent: bool = True) -> bool:
        """Publish a message to a queue."""
        try:
            if not self.channel:
                self.logger.error("No channel available. Call connect() first.")
                return False
            
            properties = pika.BasicProperties(
                delivery_mode=2 if persistent else 1  # Make message persistent
            )
            
            self.channel.basic_publish(
                exchange=exchange,
                routing_key=queue_name,
                body=message,
                properties=properties
            )
            
            self.logger.debug(f"Message published to queue '{queue_name}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish message to '{queue_name}': {e}")
            return False
    
    def consume_messages(self, queue_name: str, callback: Callable,
                        auto_ack: bool = False) -> bool:
        """Start consuming messages from a queue."""
        try:
            if not self.channel:
                self.logger.error("No channel available. Call connect() first.")
                return False
            
            def wrapper(ch, method, properties, body):
                try:
                    callback(ch, method, properties, body)
                    if not auto_ack:
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            
            self.channel.basic_consume(
                queue=queue_name,
                on_message_callback=wrapper,
                auto_ack=auto_ack
            )
            
            self.logger.info(f"Started consuming from queue '{queue_name}'")
            self.channel.start_consuming()
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to consume from queue '{queue_name}': {e}")
            return False
    
    def setup_queues(self, queue_names: list) -> bool:
        """Setup multiple queues at once."""
        success = True
        for queue_name in queue_names:
            if not self.declare_queue(queue_name):
                success = False
        return success
    
    @contextmanager
    def connection_context(self):
        """Context manager for automatic connection management."""
        try:
            if self.connect():
                yield self
            else:
                raise Exception("Failed to connect to RabbitMQ")
        finally:
            self.disconnect()