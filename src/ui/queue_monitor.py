#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Utility module for monitoring RabbitMQ queues in the networking_tester CLI."""

import logging
import pika
import json
import time
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class QueueMonitor:
    """
    Utility class for monitoring RabbitMQ queues and diagnosing service issues.
    """
    
    def __init__(self, host='localhost', port=5672, username=None, password=None):
        """Initialize the QueueMonitor with connection information."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connection = None
        self.channel = None
        
    def connect(self):
        """Establish a connection to RabbitMQ."""
        try:
            connection_params = {
                'host': self.host,
                'port': self.port
            }
            if self.username and self.password:
                connection_params['credentials'] = pika.PlainCredentials(self.username, self.password)
            
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(**connection_params))
            self.channel = self.connection.channel()
            logger.info(f"Successfully connected to RabbitMQ at {self.host}:{self.port}")
            return True
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            return False
    
    def close(self):
        """Close the RabbitMQ connection."""
        if self.connection and self.connection.is_open:
            self.connection.close()
            logger.info("RabbitMQ connection closed")
    
    def get_queue_info(self, queue_name: str) -> Dict:
        """
        Get information about a queue, including message count.
        
        Args:
            queue_name: The name of the queue to check
            
        Returns:
            A dictionary with queue information
        """
        if not self.channel:
            logger.error("Not connected to RabbitMQ")
            return {"error": "Not connected"}
        
        try:
            # Declare the queue passively to get info without creating it if it doesn't exist
            result = self.channel.queue_declare(queue=queue_name, passive=True)
            return {
                "queue": queue_name,
                "message_count": result.method.message_count,
                "consumer_count": result.method.consumer_count,
                "exists": True
            }
        except pika.exceptions.ChannelClosedByBroker:
            # Queue doesn't exist
            # We need to reopen the channel as it gets closed on error
            self.channel = self.connection.channel()
            return {
                "queue": queue_name,
                "exists": False,
                "message_count": 0,
                "consumer_count": 0
            }
            
    def check_pipeline_status(self, pipeline_queues: List[str]) -> Dict[str, Dict]:
        """
        Check the status of a processing pipeline by examining each queue.
        
        Args:
            pipeline_queues: A list of queue names in processing order
            
        Returns:
            A dictionary with status information for each queue
        """
        result = {}
        
        if not self.connect():
            return {"error": "Failed to connect to RabbitMQ"}
            
        try:
            for queue in pipeline_queues:
                result[queue] = self.get_queue_info(queue)
                
            return result
        finally:
            self.close()
    
    def get_sample_messages(self, queue_name: str, count: int = 3, peek_only: bool = True) -> List[Dict]:
        """
        Get some sample messages from a queue for debugging.
        
        Args:
            queue_name: The queue to fetch messages from
            count: Maximum number of messages to retrieve
            peek_only: If True, don't remove messages from the queue
            
        Returns:
            A list of message dictionaries
        """
        messages = []
        
        if not self.connect():
            return [{"error": "Failed to connect to RabbitMQ"}]
            
        try:
            # Check if queue exists
            queue_info = self.get_queue_info(queue_name)
            if not queue_info.get("exists", False):
                return [{"error": f"Queue '{queue_name}' does not exist"}]
                
            # Fetch messages
            for _ in range(count):
                method_frame, header_frame, body = self.channel.basic_get(
                    queue=queue_name,
                    auto_ack=not peek_only
                )
                
                if method_frame:
                    try:
                        message_data = json.loads(body)
                        messages.append(message_data)
                    except json.JSONDecodeError:
                        messages.append({"error": "Non-JSON message", "raw": body[:100]})
                else:
                    break # No more messages
                    
            return messages
        finally:
            self.close()
    
    def diagnose(self) -> Dict:
        """
        Run a comprehensive diagnosis of the queue system.
        
        Returns:
            A dictionary with diagnostic information
        """
        diagnosis = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "connection": {"host": self.host, "port": self.port},
            "queues": {},
            "issues": [],
            "recommendations": []
        }
        
        # List of queues to check in the pipeline order
        pipeline_queues = [
            "raw_frames_queue",
            "parsed_packets_queue", 
            "feature_vectors_queue",
            "qos_predictions_queue",
            "analysis_results_queue"
        ]
        
        if not self.connect():
            diagnosis["issues"].append("Failed to connect to RabbitMQ")
            diagnosis["recommendations"].append("Ensure RabbitMQ is running and accessible")
            return diagnosis
            
        try:
            # Check all pipeline queues
            for queue in pipeline_queues:
                info = self.get_queue_info(queue)
                diagnosis["queues"][queue] = info
                
                if not info.get("exists", False):
                    diagnosis["issues"].append(f"Queue '{queue}' does not exist")
                    diagnosis["recommendations"].append(f"Check if the service that creates '{queue}' is running")
                elif info.get("consumer_count", 0) == 0:
                    diagnosis["issues"].append(f"No consumers for queue '{queue}'")
                    diagnosis["recommendations"].append(f"Check if the service that consumes from '{queue}' is running")
            
            # Look for message accumulation or blockages
            for i, queue in enumerate(pipeline_queues):
                # Skip the last queue in the pipeline
                if i >= len(pipeline_queues) - 1:
                    continue
                    
                current_queue = diagnosis["queues"][queue]
                next_queue = diagnosis["queues"].get(pipeline_queues[i+1], {})
                
                if (current_queue.get("exists", False) and 
                    current_queue.get("message_count", 0) > 0 and 
                    next_queue.get("exists", False) and
                    next_queue.get("message_count", 0) == 0):
                    diagnosis["issues"].append(f"Messages in '{queue}' but none in '{pipeline_queues[i+1]}'")
                    diagnosis["recommendations"].append(f"Check the service that processes '{queue}' to '{pipeline_queues[i+1]}'")
            
            # Final recommendations
            if not diagnosis["issues"]:
                diagnosis["status"] = "ok" 
                diagnosis["summary"] = "All pipeline queues exist and have consumers"
            else:
                diagnosis["status"] = "issues_detected"
                diagnosis["summary"] = f"Found {len(diagnosis['issues'])} issues in the message pipeline"
                diagnosis["recommendations"].append("Check the logs of relevant services for errors")
                
            return diagnosis
        finally:
            self.close()


def run_diagnostics(config):
    """Run diagnostics on the messaging system and print results."""
    # Extract RabbitMQ config
    rabbitmq_config = config.get('rabbitmq', {})
    rabbitmq_host = rabbitmq_config.get('host', 'localhost')
    rabbitmq_port = rabbitmq_config.get('port', 5672)
    rabbitmq_user = rabbitmq_config.get('user')
    rabbitmq_password = rabbitmq_config.get('password')
    
    print("\nRunning message pipeline diagnostics...")
    monitor = QueueMonitor(
        host=rabbitmq_host,
        port=rabbitmq_port,
        username=rabbitmq_user,
        password=rabbitmq_password
    )
    
    diagnosis = monitor.diagnose()
    
    print(f"\nDiagnostic results (as of {diagnosis.get('timestamp', 'now')}):")
    print(f"Status: {diagnosis.get('status', 'unknown').upper()}")
    print(f"Summary: {diagnosis.get('summary', 'No summary available')}")
    
    # Queue status
    print("\nQueue Status:")
    for queue, info in diagnosis.get("queues", {}).items():
        status = "✓ EXISTS" if info.get("exists", False) else "✗ MISSING"
        messages = info.get("message_count", 0)
        consumers = info.get("consumer_count", 0)
        print(f"  {queue}: {status} | Messages: {messages} | Consumers: {consumers}")
    
    # Issues
    if diagnosis.get("issues"):
        print("\nIssues Detected:")
        for i, issue in enumerate(diagnosis["issues"], 1):
            print(f"  {i}. {issue}")
    
    # Recommendations
    if diagnosis.get("recommendations"):
        print("\nRecommendations:")
        for i, rec in enumerate(diagnosis["recommendations"], 1):
            print(f"  {i}. {rec}")
            
    return diagnosis

if __name__ == "__main__":
    # For testing directly
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    monitor = QueueMonitor()
    result = monitor.diagnose()
    print(json.dumps(result, indent=2))
