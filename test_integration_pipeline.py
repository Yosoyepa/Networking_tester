#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests for the distributed networking_tester pipeline.
Tests the complete flow from packet ingestion to statistics collection.
"""

import unittest
import logging
import time
import threading
import json
import os
import sys
import tempfile
import shutil
from typing import Dict, Any, List
from datetime import datetime

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from src.capture.frame_capture import PacketIngestorService
from src.parsing.packet_parser_service import PacketParserService
from src.statistics.statistics_collector_service import StatisticsCollectorService
from src.messaging.message_broker import MessageBroker
from src.messaging.schemas import MessageSchemas, StatisticsMessage
from src.utils.simple_logging import setup_logging


class IntegrationTestBase(unittest.TestCase):
    """Base class for integration tests."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        setup_logging(level=logging.INFO)
        cls.logger = logging.getLogger(__name__)
        
        # Test configuration
        cls.test_pcap_file = os.path.join(project_root, 'data', 'captures', 'test1.pcap')
        cls.services = {}
        cls.service_threads = {}
        cls.collected_statistics = []
        
        # Setup message broker for monitoring
        cls.monitor_broker = MessageBroker()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests."""
        cls._stop_all_services()
        if hasattr(cls, 'monitor_broker'):
            cls.monitor_broker.disconnect()
    
    def setUp(self):
        """Set up each test."""
        self.collected_statistics.clear()
        self._stop_all_services()
        time.sleep(1)  # Allow services to fully stop
    
    def tearDown(self):
        """Clean up after each test."""
        self._stop_all_services()
    
    @classmethod
    def _stop_all_services(cls):
        """Stop all running services."""
        for service_name, service in cls.services.items():
            try:
                service.stop()
                cls.logger.info(f"Stopped {service_name}")
            except Exception as e:
                cls.logger.warning(f"Error stopping {service_name}: {e}")
        
        cls.services.clear()
        cls.service_threads.clear()
    
    def _start_service_in_thread(self, service_name: str, service_obj: Any, target_method: str = 'start'):
        """Start a service in a separate thread."""
        def run_service():
            try:
                getattr(service_obj, target_method)()
            except Exception as e:
                self.logger.error(f"Error in {service_name}: {e}")
        
        thread = threading.Thread(target=run_service, daemon=True)
        thread.start()
        
        self.services[service_name] = service_obj
        self.service_threads[service_name] = thread
        
        time.sleep(0.5)  # Allow service to start
        return thread
    
    def _wait_for_file_ingestion_completion(self, timeout: int = 30):
        """Wait for file ingestion to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if 'ingestor' in self.services:
                status = self.services['ingestor'].get_status()
                if not status.get('is_running', False):
                    self.logger.info("File ingestion completed")
                    return True
            time.sleep(0.5)
        
        return False
    
    def _setup_statistics_monitor(self):
        """Setup monitoring for statistics messages."""
        if not self.monitor_broker.connect():
            self.fail("Failed to connect monitor broker")
        
        if not self.monitor_broker.declare_queue(MessageSchemas.STATISTICS_QUEUE):
            self.fail("Failed to declare statistics queue")
        
        def stats_callback(ch, method, properties, body):
            try:
                stats_msg = StatisticsMessage.from_json(body.decode('utf-8'))
                self.collected_statistics.append(stats_msg)
                self.logger.info(f"Collected statistics: {len(self.collected_statistics)}")
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as e:
                self.logger.error(f"Error processing statistics message: {e}")
        
        # Start consuming in a separate thread
        def consume_stats():
            try:
                self.monitor_broker.channel.basic_consume(
                    queue=MessageSchemas.STATISTICS_QUEUE,
                    on_message_callback=stats_callback
                )
                self.monitor_broker.channel.start_consuming()
            except Exception as e:
                self.logger.error(f"Error consuming statistics: {e}")
        
        stats_thread = threading.Thread(target=consume_stats, daemon=True)
        stats_thread.start()
        return stats_thread


class TestPipelineIntegration(IntegrationTestBase):
    """Test complete pipeline integration."""
    
    def test_pcap_file_processing_pipeline(self):
        """Test complete pipeline with PCAP file processing."""
        self.logger.info("=== Testing PCAP File Processing Pipeline ===")
        
        # Verify test file exists
        if not os.path.exists(self.test_pcap_file):
            self.skipTest(f"Test PCAP file not found: {self.test_pcap_file}")
        
        # Setup statistics monitoring
        stats_thread = self._setup_statistics_monitor()
        
        # Start services in correct order
        
        # 1. Start packet parser
        parser_service = PacketParserService()
        self._start_service_in_thread('parser', parser_service)
        self.logger.info("✓ Packet parser started")
        
        # 2. Start statistics collector
        stats_service = StatisticsCollectorService(stats_window_seconds=5)  # Short window for testing
        self._start_service_in_thread('statistics', stats_service)
        self.logger.info("✓ Statistics collector started")
        
        # 3. Start packet ingestor with file
        ingestor_service = PacketIngestorService(max_packets=50)  # Limit for testing
        self._start_service_in_thread('ingestor', ingestor_service, 'ingest_from_file')
        
        # Wait for file ingestion to complete
        self.assertTrue(
            self._wait_for_file_ingestion_completion(timeout=30),
            "File ingestion did not complete within timeout"
        )
        self.logger.info("✓ File ingestion completed")
        
        # Wait for statistics to be published
        time.sleep(10)  # Allow time for processing and statistics aggregation
        
        # Verify results
        self.assertGreater(len(self.collected_statistics), 0, "No statistics were collected")
        
        # Verify ingestor processed packets
        ingestor_status = self.services['ingestor'].get_status()
        self.assertGreater(ingestor_status['packet_count'], 0, "No packets were ingested")
        
        # Verify parser processed packets
        parser_status = self.services['parser'].get_status()
        self.assertGreater(parser_status['processed_count'], 0, "No packets were parsed")
        
        # Verify statistics collector processed packets
        stats_status = self.services['statistics'].get_status()
        self.assertGreater(stats_status['processed_count'], 0, "No packets were processed by statistics collector")
        
        # Verify statistics content
        latest_stats = self.collected_statistics[-1]
        stats_data = latest_stats.statistics
        
        self.assertIn('summary', stats_data)
        self.assertGreater(stats_data['summary']['total_packets'], 0)
        self.assertIn('protocols', stats_data)
        
        self.logger.info("✓ Pipeline integration test passed")
        
        # Print summary
        self.logger.info(f"Summary:")
        self.logger.info(f"  - Packets ingested: {ingestor_status['packet_count']}")
        self.logger.info(f"  - Packets parsed: {parser_status['processed_count']}")
        self.logger.info(f"  - Statistics collected: {len(self.collected_statistics)}")
        self.logger.info(f"  - Total packets in stats: {stats_data['summary']['total_packets']}")
    
    def test_service_startup_order(self):
        """Test that services can start in different orders."""
        self.logger.info("=== Testing Service Startup Order ===")
        
        # Test starting ingestor first (should handle queue creation)
        ingestor_service = PacketIngestorService(max_packets=10)
        
        # This should not fail even if other services aren't running
        self.assertTrue(ingestor_service.start(), "Ingestor failed to start when started first")
        ingestor_service.stop()
        
        self.logger.info("✓ Service startup order test passed")
    
    def test_error_handling(self):
        """Test error handling in the pipeline."""
        self.logger.info("=== Testing Error Handling ===")
        
        # Test with non-existent PCAP file
        ingestor_service = PacketIngestorService()
        result = ingestor_service.ingest_from_file("non_existent_file.pcap")
        
        self.assertFalse(result, "Ingestor should return False for non-existent file")
        
        self.logger.info("✓ Error handling test passed")


class TestMessageFlow(IntegrationTestBase):
    """Test message flow between services."""
    
    def test_message_broker_connection(self):
        """Test message broker connection and queue setup."""
        self.logger.info("=== Testing Message Broker Connection ===")
        
        broker = MessageBroker()
        
        # Test connection
        self.assertTrue(broker.connect(), "Failed to connect to RabbitMQ")
        
        # Test queue setup
        self.assertTrue(
            broker.setup_queues(MessageSchemas.get_queue_names()),
            "Failed to setup queues"
        )
        
        # Test message publishing
        test_message = json.dumps({"test": "message"})
        self.assertTrue(
            broker.publish_message(MessageSchemas.RAW_PACKETS_QUEUE, test_message),
            "Failed to publish test message"
        )
        
        broker.disconnect()
        self.logger.info("✓ Message broker test passed")
    
    def test_queue_names_consistency(self):
        """Test that queue names are consistent across the system."""
        self.logger.info("=== Testing Queue Names Consistency ===")
        
        queue_names = MessageSchemas.get_queue_names()
        
        # Verify all expected queues are defined
        expected_queues = [
            MessageSchemas.RAW_PACKETS_QUEUE,
            MessageSchemas.PARSED_PACKETS_QUEUE,
            MessageSchemas.STATISTICS_QUEUE,
            MessageSchemas.ML_INFERENCE_QUEUE,
            MessageSchemas.ALERTS_QUEUE
        ]
        
        for queue in expected_queues:
            self.assertIn(queue, queue_names, f"Queue {queue} not in queue names list")
        
        self.logger.info("✓ Queue names consistency test passed")


class TestPerformance(IntegrationTestBase):
    """Test pipeline performance."""
    
    def test_throughput(self):
        """Test pipeline throughput with limited packet count."""
        self.logger.info("=== Testing Pipeline Throughput ===")
        
        if not os.path.exists(self.test_pcap_file):
            self.skipTest(f"Test PCAP file not found: {self.test_pcap_file}")
        
        # Start services
        parser_service = PacketParserService()
        self._start_service_in_thread('parser', parser_service)
        
        stats_service = StatisticsCollectorService(stats_window_seconds=3)
        self._start_service_in_thread('statistics', stats_service)
        
        # Measure ingestion time
        start_time = time.time()
        
        ingestor_service = PacketIngestorService(max_packets=100)
        success = ingestor_service.ingest_from_file(self.test_pcap_file)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        self.assertTrue(success, "File ingestion failed")
        
        # Wait for processing to complete
        time.sleep(5)
        
        # Get final statistics
        ingestor_status = ingestor_service.get_status()
        packets_processed = ingestor_status['packet_count']
        
        if packets_processed > 0:
            throughput = packets_processed / processing_time
            self.logger.info(f"Processed {packets_processed} packets in {processing_time:.2f}s")
            self.logger.info(f"Throughput: {throughput:.2f} packets/second")
            
            # Basic performance assertion (should process at least 10 packets/second)
            self.assertGreater(throughput, 10, "Throughput too low")
        
        self.logger.info("✓ Throughput test passed")


def run_integration_tests():
    """Run all integration tests."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestPipelineIntegration,
        TestMessageFlow,
        TestPerformance
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    print("=== networking_tester Integration Tests ===")
    print()
    
    success = run_integration_tests()
    
    print()
    if success:
        print("✓ All integration tests passed!")
        sys.exit(0)
    else:
        print("✗ Some integration tests failed!")
        sys.exit(1)
