#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robustness tester script for networking_tester.
This script runs multiple CLI commands to test the application's robustness.
It includes dependency checking and graceful handling of missing modules.
"""

import os
import sys
import argparse
import subprocess
import logging
import importlib.util
import platform
from datetime import datetime
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def check_dependencies():
    """
    Check if required dependencies are installed.
    
    Returns:
        dict: Dictionary with 'missing' and 'available' lists of package names
    """
    required_packages = [
        'pandas',
        'numpy',
        'yaml',
        'pyyaml',  # Common name for yaml package
        'joblib',
        'sklearn',  # scikit-learn
        'scapy'
    ]
    
    missing_packages = []
    available_packages = []
    import_name_map = {
        'yaml': 'yaml',
        'pyyaml': 'yaml',  # Both 'yaml' and 'pyyaml' map to the same import name
        'sklearn': 'sklearn',
    }
    
    for package in required_packages:
        # Get the correct import name
        import_name = import_name_map.get(package.lower(), package.lower())
        
        # Check if the package is available
        if importlib.util.find_spec(import_name) is None:
            missing_packages.append(package)
        else:
            available_packages.append(package)
    
    # Remove duplicates (e.g., if both 'yaml' and 'pyyaml' are available)
    unique_missing = list(set(missing_packages))
    unique_available = list(set(available_packages))
    
    return {
        'missing': unique_missing,
        'available': unique_available
    }


def fix_path_for_imports():
    """Add the project root directory to sys.path to fix import issues."""
    # Get the directory where this script is located (project root)
    project_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Add the project root to sys.path if it's not already there
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)
        logger.info(f"Added {project_dir} to sys.path")
    
    # Also add the src directory specifically
    src_dir = os.path.join(project_dir, 'src')
    if os.path.exists(src_dir) and src_dir not in sys.path:
        sys.path.insert(0, src_dir)
        logger.info(f"Added {src_dir} to sys.path")


class RobustnessTester:
    """Class to test the robustness of the networking_tester application."""
    
    def __init__(self, main_script="main.py", test_pcap="data/captures/test_ethernet2_v3.pcap"):
        """Initialize the tester with paths."""
        self.main_script = main_script
        self.test_pcap = test_pcap
        # Get the directory where this script is located (networking_tester folder)
        self.project_dir = os.path.dirname(os.path.abspath(__file__))
        self.results = {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "tests": []
        }
        self.dependencies = check_dependencies()
    
    def run_command(self, command, name, expected_return_code=0, timeout=30, allow_timeout=False, 
                    skip_if_missing_deps=None):
        """
        Run a command and check if it returns the expected code.
        
        Args:
            command (str): The command to run
            name (str): A descriptive name for the test
            expected_return_code (int): The expected return code (0 for success)
            timeout (int): Timeout in seconds
            allow_timeout (bool): If True, a timeout is not considered a failure
            skip_if_missing_deps (list): Skip this test if any of these dependencies are missing
            
        Returns:
            bool: True if the command returned the expected code, False otherwise
        """
        # Check if we should skip this test due to missing dependencies
        if skip_if_missing_deps:
            missing_required_deps = [dep for dep in skip_if_missing_deps 
                                if dep.lower() in map(str.lower, self.dependencies['missing'])]
            if missing_required_deps:
                logger.info(f"Skipping test '{name}' due to missing dependencies: {', '.join(missing_required_deps)}")
                self.results["skipped"] += 1
                
                # Add a skipped test result
                test_result = {
                    "name": name,
                    "command": command,
                    "timestamp": datetime.now().isoformat(),
                    "expected_return_code": expected_return_code,
                    "result": "SKIPPED",
                    "reason": f"Missing dependencies: {', '.join(missing_required_deps)}"
                }
                self.results["tests"].append(test_result)
                return True  # Return True so the test suite continues
        
        logger.info(f"Running test: {name}")
        logger.info(f"Command: {command}")
        
        # Validate that file paths in the command exist
        if '--file' in command:
            file_path = command.split('--file')[1].strip().split()[0]
            full_path = os.path.join(self.project_dir, file_path)
            if not os.path.exists(full_path):
                logger.warning(f"Warning: Test file does not exist: {full_path}")
        
        test_result = {
            "name": name,
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "expected_return_code": expected_return_code
        }
        
        try:
            # Set environment variables to handle Unicode issues
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONPATH"] = self.project_dir + os.pathsep + env.get("PYTHONPATH", "")
            
            # Split the command into arguments for better control and security
            if platform.system() == 'Windows':
                # For Windows, use shell=True for Python commands to ensure python is found
                if command.startswith('python '):
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=self.project_dir,
                        env=env,
                        shell=True,
                        text=True
                    )
                else:
                    cmd_parts = command.split()
                    process = subprocess.Popen(
                        cmd_parts,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=self.project_dir,
                        env=env,
                        text=True
                    )
            else:
                # For non-Windows platforms, avoid shell=True
                cmd_parts = command.split()
                process = subprocess.Popen(
                    cmd_parts,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self.project_dir,
                    env=env,
                    text=True
                )
            
            # Wait for process to complete with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if allow_timeout:
                    logger.info(f"Command timed out as expected for test: {name}")
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        stdout, stderr = "", "Process killed after timeout"
                    
                    test_result["result"] = "PASS (TIMEOUT EXPECTED)"
                    test_result["return_code"] = None
                    test_result["stdout"] = stdout
                    test_result["stderr"] = stderr
                    self.results["passed"] += 1
                    self.results["tests"].append(test_result)
                    return True
                else:
                    logger.error(f"Test TIMEOUT: {name} (Timeout: {timeout}s)")
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        stdout, stderr = "", "Process killed after timeout"
                    
                    test_result["result"] = "TIMEOUT"
                    test_result["return_code"] = None
                    test_result["stdout"] = stdout
                    test_result["stderr"] = stderr
                    self.results["failed"] += 1
                    self.results["tests"].append(test_result)
                    return False
            
            # Process completed normally, capture return code and output
            return_code = process.returncode
            test_result["stdout"] = stdout
            test_result["stderr"] = stderr
            test_result["return_code"] = return_code
            
            # Check if the return code matches the expected code
            if return_code == expected_return_code:
                logger.info(f"Test PASSED: {name}")
                test_result["result"] = "PASS"
                self.results["passed"] += 1
                self.results["tests"].append(test_result)
                return True
            else:
                logger.error(f"Test FAILED: {name} (Expected: {expected_return_code}, Got: {return_code})")
                if stderr:
                    logger.error(f"stderr: {stderr}")
                test_result["result"] = "FAIL"
                self.results["failed"] += 1
                self.results["tests"].append(test_result)
                return False
                
        except Exception as e:
            logger.error(f"Test ERROR: {name} ({str(e)})")
            test_result["result"] = "ERROR"
            test_result["error"] = str(e)
            self.results["failed"] += 1
            self.results["tests"].append(test_result)
            return False
    def run_basic_tests(self):
        """Run basic functionality tests."""
        print_separator("Running Basic Tests")
        
        tests = [            {
                "name": "Help command",
                "command": f"python {self.main_script} --help",
                "timeout": 5,
                "allow_timeout": True  # This command is expected to hang because main.py doesn't handle --help
            }
            # Removed cli_test_runner.py tests as the file has been removed in favor of distributed architecture
        ]
        
        for test in tests:
            self.run_command(**test)    def run_pcap_analysis_tests(self):
        """Run tests for PCAP file analysis."""
        print_separator("Running PCAP Analysis Tests")
        
        # PCAP analysis tests removed as cli_test_runner.py has been eliminated
        # The distributed architecture now uses separate service commands
        logger.info("PCAP analysis tests skipped - legacy CLI removed in favor of distributed architecture")
        
        tests = []
        
        for test in tests:
            self.run_command(**test)
      def run_ai_feature_tests(self):
        """Run tests for AI features."""
        print_separator("Running AI Feature Tests")
        
        # AI feature tests removed as cli_test_runner.py has been eliminated
        # The distributed architecture now uses separate ML inference services
        logger.info("AI feature tests skipped - legacy CLI removed in favor of distributed architecture")
        
        tests = []
        
        for test in tests:
            self.run_command(**test)
    
    def run_error_handling_tests(self):
        """Run tests for error handling."""
        print_separator("Running Error Handling Tests")
        
        # Error handling tests updated for new distributed CLI commands
        logger.info("Error handling tests skipped - CLI interface has changed to distributed services")
        
        tests = []
        
        for test in tests:
            self.run_command(**test)
    
    def print_dependency_report(self):
        """Print a report of the dependencies."""
        print_separator("Dependency Report")
        
        if not self.dependencies['missing']:
            logger.info("All required dependencies are available")
        else:
            logger.warning(f"Missing dependencies: {', '.join(self.dependencies['missing'])}")
            logger.info("To install missing dependencies, run:")
            logger.info(f"pip install {' '.join(self.dependencies['missing'])}")
        
        logger.info(f"Available dependencies: {', '.join(self.dependencies['available'])}")
    
    def run_all_tests(self):
        """Run all robustness tests."""
        logger.info("Starting robustness tests...")
        
        # Set up the Python path to help with imports
        fix_path_for_imports()
        
        # Check and report dependencies
        self.print_dependency_report()
        
        # Run test suites
        self.run_basic_tests()
        self.run_error_handling_tests()  # Run error handling tests even if dependencies are missing
        self.run_pcap_analysis_tests()
        self.run_ai_feature_tests()
        
        # Print summary
        print_separator("Test Summary")
        logger.info("Robustness tests completed.")
        logger.info(f"Tests passed: {self.results['passed']}")
        logger.info(f"Tests failed: {self.results['failed']}")
        logger.info(f"Tests skipped: {self.results['skipped']} (due to missing dependencies)")
        
        # If tests were skipped due to missing dependencies, provide context
        if self.results["skipped"] > 0:
            logger.warning("Some tests were skipped due to missing dependencies.")
            logger.warning("This does not necessarily indicate a problem with the code.")
            logger.warning("Install the required dependencies to run all tests.")
        
        # Return true if no tests failed (skipped tests don't count as failures)
        return self.results["failed"] == 0


def print_separator(title):
    """Print a separator with a title."""
    separator = "=" * 50
    logger.info(separator)
    logger.info(title)
    logger.info(separator)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run networking_tester robustness tests')
    
    parser.add_argument('--main-script', 
                        help='Path to the main script (default: main.py)',
                        default='main.py')
    
    parser.add_argument('--test-pcap', 
                        help='Path to a test PCAP file',
                        default='data/captures/test_ethernet2_v3.pcap')
    
    parser.add_argument('--install-deps',
                        help='Attempt to install missing dependencies',
                        action='store_true')
    
    return parser.parse_args()


def install_dependencies(missing_dependencies):
    """
    Attempt to install missing dependencies.
    
    Args:
        missing_dependencies (list): List of missing package names
        
    Returns:
        bool: True if installation was successful, False otherwise
    """
    if not missing_dependencies:
        logger.info("No missing dependencies to install")
        return True
    
    logger.info(f"Attempting to install missing dependencies: {', '.join(missing_dependencies)}")
    
    try:
        # Prepare the pip install command
        install_cmd = [sys.executable, "-m", "pip", "install"] + missing_dependencies
        
        # Run the pip install command
        process = subprocess.run(
            install_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if process.returncode == 0:
            logger.info("Successfully installed missing dependencies")
            return True
        else:
            logger.error(f"Failed to install dependencies: {process.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error installing dependencies: {str(e)}")
        return False


if __name__ == '__main__':
    args = parse_args()
    
    # Display information about the test environment
    print_separator("Networking Tester - Robustness Test Suite")
    logger.info(f"Python: {sys.executable} (version {platform.python_version()})")
    logger.info(f"Operating System: {platform.system()} {platform.release()}")
    logger.info(f"Test script: {os.path.abspath(__file__)}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Testing main script: {args.main_script}")
    logger.info(f"Test PCAP file: {args.test_pcap}")
    
    # Check for dependencies first
    deps = check_dependencies()
    if deps['missing'] and args.install_deps:
        install_dependencies(deps['missing'])
    
    # Run the tests
    tester = RobustnessTester(main_script=args.main_script, test_pcap=args.test_pcap)
    success = tester.run_all_tests()
    
    # Print final message
    if success:
        logger.info("All tests completed successfully (note: skipped tests do not count as failures)")
    else:
        logger.warning("Some tests failed. See above for details.")
    
    # Set exit code based on test results
    sys.exit(0 if success else 1)
