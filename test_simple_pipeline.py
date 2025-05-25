#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simplified Pipeline Integration Testing Script for Networking Tester Phase 1
Validates service startup and basic connectivity
"""

import sys
import os
import time
import subprocess
import signal
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from scapy.all import Ether, IP, TCP, UDP, wrpcap
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimplePipelineTester:
    """Simplified pipeline tester for Phase 1 validation."""
    
    def __init__(self):
        self.services_processes = {}
        self.test_pcap_path = "test_data/integration_test.pcap"
        self.results = {
            'services_started': 0,
            'services_expected': 6,
            'test_data_created': False,
            'packet_injection_success': False,
            'all_services_healthy': False
        }
        
    def setup_test_environment(self):
        """Setup test environment and create test data."""
        logger.info("🔧 Setting up test environment...")
        
        # Create test data directory
        os.makedirs("test_data", exist_ok=True)
        
        # Generate test PCAP file
        self.generate_test_pcap()
        
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
        self.results['test_data_created'] = True
        
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
            time.sleep(3)  # Allow service to start
            
            # Check if process is still running
            if process.poll() is None:
                logger.info(f"✅ {service_name} started successfully (PID: {process.pid})")
                self.results['services_started'] += 1
                return True
            else:
                stdout, stderr = process.communicate()
                logger.error(f"❌ {service_name} failed to start. stderr: {stderr.decode()}")
                return False
                
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
            ("Packet Parser", "python main.py start-parser"),
            ("Statistics Collector", "python main.py start-stats-collector"),
            ("Feature Extractor", "python main.py start-feature-extractor"),
            ("QoS ML Inference", "python main.py start-qos-inference"),
            ("Core Analysis", "python main.py start-core-analysis"),
            ("Reporting Service", "python main.py start-reporting")
        ]
        
        for service_name, command in services:
            self.start_service(service_name, command)
                
        logger.info(f"✅ Started {self.results['services_started']}/{self.results['services_expected']} services")
        
        # Check if all services are healthy
        if self.results['services_started'] == self.results['services_expected']:
            self.results['all_services_healthy'] = True
            
        return self.results['all_services_healthy']
        
    def stop_all_services(self):
        """Stop all running services."""
        logger.info("🛑 Stopping all services...")
        for service_name in list(self.services_processes.keys()):
            self.stop_service(service_name)
            
    def test_packet_injection(self):
        """Test packet injection through the packet ingestor."""
        logger.info("💉 Testing packet injection...")
        
        try:            # Run packet ingestor on test PCAP
            command = f"python src/capture/frame_capture.py --file {self.test_pcap_path} --max-packets 5 --verbose"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info("✅ Packet injection test completed successfully")
                logger.info(f"Output: {result.stdout[:200]}...")  # Show first 200 chars
                self.results['packet_injection_success'] = True
                return True
            else:
                logger.error(f"❌ Packet injection failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("❌ Packet injection timed out")
            return False
        except Exception as e:
            logger.error(f"❌ Error during packet injection: {e}")
            return False
            
    def check_services_health(self):
        """Check if all services are still running."""
        logger.info("🔍 Checking services health...")
        
        healthy_services = 0
        for service_name, process in self.services_processes.items():
            if process.poll() is None:
                logger.info(f"✅ {service_name} is healthy")
                healthy_services += 1
            else:
                logger.warning(f"⚠️  {service_name} has stopped")
                
        logger.info(f"📊 {healthy_services}/{len(self.services_processes)} services are healthy")
        return healthy_services == len(self.services_processes)
        
    def print_results(self):
        """Print final test results."""
        print("\n" + "="*60)
        print("📊 PHASE 1 SIMPLE PIPELINE TEST RESULTS")
        print("="*60)
        
        print(f"✅ Test Data Created: {self.results['test_data_created']}")
        print(f"🚀 Services Started: {self.results['services_started']}/{self.results['services_expected']}")
        print(f"💉 Packet Injection Success: {self.results['packet_injection_success']}")
        print(f"🏥 All Services Healthy: {self.results['all_services_healthy']}")
        
        print("="*60)
        
        # Calculate overall success
        success_criteria = [
            self.results['test_data_created'],
            self.results['services_started'] >= 5,  # At least 5/6 services
            self.results['packet_injection_success']
        ]
        
        if all(success_criteria):
            print("🎉 PHASE 1 BASIC VALIDATION: SUCCESS")
            print("✅ Core distributed services are operational")
        else:
            print("💥 PHASE 1 BASIC VALIDATION: FAILED")
            print("❌ Some core services or functionality failed")
            
        print("="*60)
        
    def run_basic_validation(self):
        """Run the basic validation test."""
        logger.info("🚀 Starting Phase 1 Basic Pipeline Validation")
        
        try:
            # Setup
            if not self.setup_test_environment():
                return False
                
            # Start services
            if not self.start_all_services():
                logger.warning("⚠️  Not all services started, but continuing...")
                
            # Wait for services to stabilize
            logger.info("⏳ Waiting for services to stabilize...")
            time.sleep(10)
            
            # Check health
            self.check_services_health()
                
            # Test packet injection
            self.test_packet_injection()
            
            # Final health check
            time.sleep(5)
            final_health = self.check_services_health()
            
            return final_health and self.results['packet_injection_success']
            
        except Exception as e:
            logger.error(f"❌ Validation test failed: {e}")
            return False
            
        finally:
            # Cleanup
            self.stop_all_services()
            self.print_results()


def main():
    """Main function to run the validation test."""
    tester = SimplePipelineTester()
    
    try:
        success = tester.run_basic_validation()
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
