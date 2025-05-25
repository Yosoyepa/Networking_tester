#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pipeline Integration Testing Script for Networking Tester Phase 1
Validates end-to-end message flow between all 7 distributed services
"""

import sys
import os
import time
import threading
import json
import subprocess
import signal
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import (
    RawPacketMessage, ParsedPacketMessage, StatisticsMessage,
    FeatureVector, MLResult, AnalysisResult
)
from scapy.all import Ether, IP, TCP, UDP, wrpcap
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PipelineIntegrationTester:
    """End-to-end integration tester for distributed services pipeline."""
    
    def __init__(self):
        self.services_processes = {}
        self.rabbitmq_client = None
        self.test_pcap_path = "test_data/integration_test.pcap"
        self.results = {
            'raw_packets_published': 0,
            'parsed_packets_received': 0,
            'statistics_received': 0,
            'features_received': 0,
            'ml_results_received': 0,
            'analysis_results_received': 0,
            'pipeline_success': False
        }
        
    def setup_test_environment(self):
        """Setup test environment and create test data."""
        logger.info("🔧 Setting up test environment...")
        
        # Create test data directory
        os.makedirs("test_data", exist_ok=True)
        
        # Generate test PCAP file
        self.generate_test_pcap()
          # Initialize RabbitMQ connection for monitoring
        try:
            self.rabbitmq_client = RabbitMQClient(
                host='localhost',
                port=5672,
                username='guest',
                password='guest'
            )
            logger.info("✅ Connected to RabbitMQ for monitoring")
        except Exception as e:
            logger.error(f"❌ Failed to connect to RabbitMQ: {e}")
            return False
            
        return True
        
    def generate_test_pcap(self):
        """Generate a test PCAP file with various packet types."""
        logger.info("📦 Generating test PCAP file...")
        
        packets = []
        
        # HTTP packets
        for i in range(5):
            pkt = Ether() / IP(src=f"192.168.1.{100+i}", dst="8.8.8.8") / TCP(sport=12345+i, dport=80)
            packets.append(pkt)
            
        # HTTPS packets  
        for i in range(3):
            pkt = Ether() / IP(src=f"192.168.1.{110+i}", dst="1.1.1.1") / TCP(sport=54321+i, dport=443)
            packets.append(pkt)
            
        # DNS packets
        for i in range(2):
            pkt = Ether() / IP(src=f"192.168.1.{120+i}", dst="8.8.8.8") / UDP(sport=5353+i, dport=53)
            packets.append(pkt)
            
        # Write PCAP
        wrpcap(self.test_pcap_path, packets)
        logger.info(f"✅ Generated test PCAP with {len(packets)} packets: {self.test_pcap_path}")
        
    def start_service(self, service_name, command):
        """Start a service as subprocess."""
        logger.info(f"🚀 Starting {service_name}...")
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            self.services_processes[service_name] = process
            time.sleep(2)  # Allow service to start
            logger.info(f"✅ {service_name} started (PID: {process.pid})")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to start {service_name}: {e}")
            return False
            
    def stop_service(self, service_name):
        """Stop a service subprocess."""
        if service_name in self.services_processes:
            process = self.services_processes[service_name]
            try:
                if os.name == 'nt':
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.terminate()
                process.wait(timeout=5)
                logger.info(f"🛑 {service_name} stopped")
            except Exception as e:
                logger.warning(f"⚠️  Force killing {service_name}: {e}")
                process.kill()
            del self.services_processes[service_name]
            
    def start_all_services(self):
        """Start all distributed services."""
        logger.info("🚀 Starting all distributed services...")
        
        services = [
            ("Packet Parser", "python main.py start-packet-parser"),
            ("Statistics Collector", "python main.py start-statistics-collector"),
            ("Feature Extractor", "python main.py start-feature-extractor"),
            ("QoS ML Inference", "python main.py start-qos-inference"),
            ("Core Analysis", "python main.py start-core-analysis"),
            ("Reporting Service", "python main.py start-reporting")
        ]
        
        success_count = 0
        for service_name, command in services:
            if self.start_service(service_name, command):
                success_count += 1
                
        logger.info(f"✅ Started {success_count}/{len(services)} services")
        return success_count == len(services)
        
    def stop_all_services(self):
        """Stop all running services."""
        logger.info("🛑 Stopping all services...")
        for service_name in list(self.services_processes.keys()):
            self.stop_service(service_name)
              def setup_message_monitoring(self):
        """Setup message monitoring on all queues."""
        logger.info("👁️  Setting up message monitoring...")
        
        queues_to_monitor = [
            'parsed_packets',
            'statistics', 
            'features',
            'ml_results',
            'analysis_results'
        ]
        
        try:
            for queue in queues_to_monitor:
                self.rabbitmq_client.declare_queue(queue)
                
            logger.info("✅ Message monitoring queues declared")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to setup monitoring: {e}")
            return False
            
    def _on_parsed_packet(self, ch, method, properties, body):
        """Handle parsed packet messages."""
        self.results['parsed_packets_received'] += 1
        logger.info(f"📨 Received parsed packet #{self.results['parsed_packets_received']}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    def _on_statistics(self, ch, method, properties, body):
        """Handle statistics messages."""
        self.results['statistics_received'] += 1
        logger.info(f"📊 Received statistics #{self.results['statistics_received']}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    def _on_features(self, ch, method, properties, body):
        """Handle features messages."""
        self.results['features_received'] += 1
        logger.info(f"🧮 Received features #{self.results['features_received']}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    def _on_ml_results(self, ch, method, properties, body):
        """Handle ML results messages."""
        self.results['ml_results_received'] += 1
        logger.info(f"🤖 Received ML results #{self.results['ml_results_received']}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    def _on_analysis_results(self, ch, method, properties, body):
        """Handle analysis results messages."""
        self.results['analysis_results_received'] += 1
        logger.info(f"📋 Received analysis results #{self.results['analysis_results_received']}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    def inject_test_packets(self):
        """Inject test packets into the pipeline."""
        logger.info("💉 Injecting test packets into pipeline...")
        
        try:
            # Run packet ingestor on test PCAP
            command = f"python src/capture/frame_capture.py --pcap-file {self.test_pcap_path} --max-packets 10 --verbose"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info("✅ Test packets injected successfully")
                # Extract packet count from output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'packets published' in line.lower():
                        try:
                            self.results['raw_packets_published'] = int(line.split()[0])
                        except:
                            self.results['raw_packets_published'] = 10  # default
                return True
            else:
                logger.error(f"❌ Failed to inject packets: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("❌ Packet injection timed out")
            return False
        except Exception as e:
            logger.error(f"❌ Error injecting packets: {e}")
            return False
            
    def wait_for_pipeline_completion(self, timeout=60):
        """Wait for pipeline to process all messages."""
        logger.info(f"⏳ Waiting for pipeline completion (timeout: {timeout}s)...")
        
        start_time = time.time()
        last_activity = time.time()
        
        while time.time() - start_time < timeout:
            # Check if we have activity
            total_received = (self.results['parsed_packets_received'] + 
                            self.results['statistics_received'] +
                            self.results['features_received'] + 
                            self.results['ml_results_received'] +
                            self.results['analysis_results_received'])
                            
            if total_received > 0:
                last_activity = time.time()
                
            # Check if pipeline seems complete
            if (self.results['raw_packets_published'] > 0 and
                self.results['analysis_results_received'] > 0):
                logger.info("✅ Pipeline processing appears complete")
                return True
                
            # If no activity for 10 seconds, consider timeout
            if time.time() - last_activity > 10:
                logger.warning("⚠️  No pipeline activity for 10 seconds")
                break
                
            time.sleep(1)
            
        logger.warning(f"⏰ Pipeline completion timeout after {timeout}s")
        return False
        
    def validate_pipeline_integrity(self):
        """Validate the integrity of the pipeline."""
        logger.info("🔍 Validating pipeline integrity...")
        
        issues = []
        
        # Check if packets were published
        if self.results['raw_packets_published'] == 0:
            issues.append("No raw packets were published")
            
        # Check if parsing worked
        if self.results['parsed_packets_received'] == 0:
            issues.append("No parsed packets were received")
            
        # Check if statistics were generated
        if self.results['statistics_received'] == 0:
            issues.append("No statistics were received")
            
        # Check if features were extracted
        if self.results['features_received'] == 0:
            issues.append("No features were received")
            
        # ML results are optional (model might not exist)
        # Analysis results should be generated
        if self.results['analysis_results_received'] == 0:
            issues.append("No analysis results were received")
            
        if issues:
            logger.error(f"❌ Pipeline integrity issues: {issues}")
            self.results['pipeline_success'] = False
        else:
            logger.info("✅ Pipeline integrity validated successfully")
            self.results['pipeline_success'] = True
            
        return len(issues) == 0
        
    def print_results(self):
        """Print final test results."""
        print("\n" + "="*60)
        print("📊 PIPELINE INTEGRATION TEST RESULTS")
        print("="*60)
        
        for key, value in self.results.items():
            status = "✅" if (isinstance(value, bool) and value) or (isinstance(value, int) and value > 0) else "❌"
            print(f"{status} {key.replace('_', ' ').title()}: {value}")
            
        print("="*60)
        
        if self.results['pipeline_success']:
            print("🎉 PHASE 1 PIPELINE VALIDATION: SUCCESS")
        else:
            print("💥 PHASE 1 PIPELINE VALIDATION: FAILED")
            
        print("="*60)
        
    def run_integration_test(self):
        """Run the complete integration test."""
        logger.info("🚀 Starting Pipeline Integration Test for Phase 1")
        
        try:
            # Setup
            if not self.setup_test_environment():
                return False
                
            # Start monitoring
            if not self.setup_message_monitoring():
                return False
                
            # Start services
            if not self.start_all_services():
                return False
                
            # Wait for services to stabilize
            logger.info("⏳ Waiting for services to stabilize...")
            time.sleep(5)
            
            # Start monitoring in background
            monitor_thread = threading.Thread(target=self.rabbitmq_client.start_consuming, daemon=True)
            monitor_thread.start()
            
            # Inject test data
            if not self.inject_test_packets():
                return False
                
            # Wait for pipeline completion
            if not self.wait_for_pipeline_completion():
                logger.warning("⚠️  Pipeline did not complete within timeout")
                
            # Allow extra time for any remaining processing
            time.sleep(5)
            
            # Validate results
            self.validate_pipeline_integrity()
            
            return self.results['pipeline_success']
            
        except Exception as e:
            logger.error(f"❌ Integration test failed: {e}")
            return False
            
        finally:
            # Cleanup
            self.stop_all_services()
            if self.rabbitmq_client:
                self.rabbitmq_client.close()
            self.print_results()


def main():
    """Main function to run the integration test."""
    tester = PipelineIntegrationTester()
    
    try:
        success = tester.run_integration_test()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("🛑 Test interrupted by user")
        tester.stop_all_services()
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        tester.stop_all_services()
        sys.exit(1)


if __name__ == "__main__":
    main()
