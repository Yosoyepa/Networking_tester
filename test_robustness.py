#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robustness tester script for networking_tester.
This script runs multiple CLI commands to test the application's robustness.
"""

import os
import sys
import argparse
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class RobustnessTester:
    """Class to test the robustness of the networking_tester application."""
    
    def __init__(self, main_script="main.py", test_pcap="data/captures/test_ethernet2_v3.pcap"):
        """Initialize the tester with paths."""
        self.main_script = main_script
        self.test_pcap = test_pcap
        self.results = {
            "passed": 0,
            "failed": 0,
            "tests": []
        }
    
    def run_command(self, command, name, expected_return_code=0, timeout=30):
        """
        Run a command and check if it returns the expected code.
        
        Args:
            command (str): The command to run
            name (str): A descriptive name for the test
            expected_return_code (int): The expected return code (0 for success)
            timeout (int): Timeout in seconds
            
        Returns:
            bool: True if the command returned the expected code, False otherwise
        """
        logger.info(f"Running test: {name}")
        logger.info(f"Command: {command}")
        
        test_result = {
            "name": name,
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "expected_return_code": expected_return_code
        }
        
        try:
            # Run the command
            process = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True
            )
            
            # Capture output
            stdout = process.stdout
            stderr = process.stderr
            return_code = process.returncode
            
            test_result["stdout"] = stdout
            test_result["stderr"] = stderr
            test_result["return_code"] = return_code
            
            # Check if the return code matches the expected code
            if return_code == expected_return_code:
                logger.info(f"Test PASSED: {name}")
                test_result["result"] = "PASS"
                self.results["passed"] += 1
                return True
            else:
                logger.error(f"Test FAILED: {name} (Expected: {expected_return_code}, Got: {return_code})")
                logger.error(f"stderr: {stderr}")
                test_result["result"] = "FAIL"
                self.results["failed"] += 1
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Test TIMEOUT: {name} (Timeout: {timeout}s)")
            test_result["result"] = "TIMEOUT"
            test_result["return_code"] = None
            self.results["failed"] += 1
            return False
            
        except Exception as e:
            logger.error(f"Test ERROR: {name} ({str(e)})")
            test_result["result"] = "ERROR"
            test_result["error"] = str(e)
            self.results["failed"] += 1
            return False
            
        finally:
            # Add the test result to the results list
            self.results["tests"].append(test_result)
    
    def run_basic_tests(self):
        """Run basic functionality tests."""
        tests = [
            {
                "name": "Help command",
                "command": f"python {self.main_script} --help"
            },
            {
                "name": "Version command",
                "command": f"python {self.main_script} --version"
            }
        ]
        
        for test in tests:
            self.run_command(**test)
    
    def run_pcap_analysis_tests(self):
        """Run tests for PCAP file analysis."""
        tests = [
            {
                "name": "Basic PCAP analysis",
                "command": f"python {self.main_script} --file {self.test_pcap}"
            },
            {
                "name": "PCAP analysis with output format",
                "command": f"python {self.main_script} --file {self.test_pcap} --output-format json"
            },
            {
                "name": "PCAP analysis with report file",
                "command": f"python {self.main_script} --file {self.test_pcap} --report-file test_report.json"
            }
        ]
        
        for test in tests:
            self.run_command(**test)
    
    def run_ai_feature_tests(self):
        """Run tests for AI features."""
        tests = [
            {
                "name": "AI analysis",
                "command": f"python {self.main_script} --file {self.test_pcap} --ai-analysis"
            },
            {
                "name": "AI analysis with custom model path",
                "command": f"python {self.main_script} --file {self.test_pcap} --ai-analysis --model-path data/models/ai_anomaly_detector.joblib"
            }
        ]
        
        for test in tests:
            self.run_command(**test)
    
    def run_error_handling_tests(self):
        """Run tests for error handling."""
        tests = [
            {
                "name": "Invalid file path",
                "command": f"python {self.main_script} --file nonexistent_file.pcap",
                "expected_return_code": 1  # Expect failure
            },
            {
                "name": "Invalid option combination",
                "command": f"python {self.main_script} --live --file {self.test_pcap}",
                "expected_return_code": 1  # Expect failure
            },
            {
                "name": "Invalid configuration",
                "command": f"python {self.main_script} --config nonexistent_config.yaml",
                "expected_return_code": 1  # Expect failure
            }
        ]
        
        for test in tests:
            self.run_command(**test)
    
    def run_all_tests(self):
        """Run all robustness tests."""
        logger.info("Starting robustness tests...")
        
        # Run test suites
        self.run_basic_tests()
        self.run_pcap_analysis_tests()
        self.run_ai_feature_tests()
        self.run_error_handling_tests()
        
        # Print summary
        logger.info("Robustness tests completed.")
        logger.info(f"Tests passed: {self.results['passed']}")
        logger.info(f"Tests failed: {self.results['failed']}")
        
        return self.results["failed"] == 0


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run networking_tester robustness tests')
    
    parser.add_argument('--main-script', 
                        help='Path to the main script (default: main.py)',
                        default='main.py')
    
    parser.add_argument('--test-pcap', 
                        help='Path to a test PCAP file',
                        default='data/captures/test_ethernet2_v3.pcap')
    
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    
    tester = RobustnessTester(main_script=args.main_script, test_pcap=args.test_pcap)
    success = tester.run_all_tests()
    
    # Set exit code based on test results
    sys.exit(0 if success else 1)
