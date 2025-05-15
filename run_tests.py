#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test runner script for networking_tester.
This script runs all the unit tests and reports results.
"""

import os
import sys
import unittest
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def run_tests(pattern=None, verbosity=1, failfast=False):
    """
    Run all unit tests matching the given pattern.
    
    Args:
        pattern (str): Pattern to match test files
        verbosity (int): Verbosity level (1-3)
        failfast (bool): Stop on first failure
    
    Returns:
        bool: True if all tests pass, False otherwise
    """
    logger.info("Starting test run...")
    
    # Set the start directory for test discovery
    start_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tests')
    logger.info(f"Discovering tests in {start_dir}")
    
    # Create test suite
    if pattern:
        logger.info(f"Using pattern: {pattern}")
        suite = unittest.defaultTestLoader.discover(start_dir, pattern=pattern)
    else:
        suite = unittest.defaultTestLoader.discover(start_dir)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=verbosity, failfast=failfast)
    result = runner.run(suite)
    
    # Report results
    logger.info(f"Tests run: {result.testsRun}")
    logger.info(f"Errors: {len(result.errors)}")
    logger.info(f"Failures: {len(result.failures)}")
    logger.info(f"Skipped: {len(result.skipped)}")
    
    return len(result.errors) == 0 and len(result.failures) == 0


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run networking_tester unit tests')
    
    parser.add_argument('--pattern', '-p', 
                        help='Pattern to match test files (default: test_*.py)',
                        default='test_*.py')
    
    parser.add_argument('--verbosity', '-v', 
                        help='Verbosity level (1-3)',
                        type=int, choices=[1, 2, 3], 
                        default=2)
    
    parser.add_argument('--failfast', '-f', 
                        help='Stop on first failure',
                        action='store_true')
    
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    success = run_tests(pattern=args.pattern, verbosity=args.verbosity, failfast=args.failfast)
    
    # Set exit code based on test results
    sys.exit(0 if success else 1)
