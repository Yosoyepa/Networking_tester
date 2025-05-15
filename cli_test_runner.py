#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Entry point for CLI headless tests for networking_tester."""

import os
import sys
import logging
import argparse
import pandas as pd
import numpy as np

from src.utils.logging_config import setup_logging
from src.ai_monitoring.anomaly_detector import AnomalyDetector
from src.core.engine import AnalysisEngine
from src.ui.menu_handler import run_main_loop

def run_feature_mismatch_test(model_path, scaler_path):
    """
    Run a test to verify that feature mismatches are handled correctly.
    This is a standalone test for our fixed functionality.
    
    Args:
        model_path: Path to the joblib model file
        scaler_path: Path to the joblib scaler file
        
    Returns:
        bool: True if the test passes, False otherwise
    """
    logger = logging.getLogger(__name__)
    logger.info("Running feature mismatch test")
    
    try:
        # Create anomaly detector with the specified model
        detector = AnomalyDetector(model_path, scaler_path)
        
        # Verify the model is loaded
        if not detector.is_trained():
            logger.error("Feature mismatch test failed: Model not loaded")
            return False
            
        # Create test data with some features that don't match what the model was trained on
        test_data = pd.DataFrame({
            'timestamp': [1000, 2000, 3000],
            'ip_version': [4, 4, 4],
            'ip_len': [60, 80, 100],
            'tcp_flags': [16, 24, 16],
            'new_feature_1': [500, 600, 700],  # New feature not in original training
            'new_feature_2': [800, 900, 1000]  # Another new feature
        })
        
        # Try to predict with mismatched features
        result = detector.predict(test_data)
        
        # Verify we got a result array of the expected length
        if not isinstance(result, np.ndarray) or len(result) != len(test_data):
            logger.error(f"Feature mismatch test failed: Unexpected result type or length: {type(result)}, {len(result) if hasattr(result, '__len__') else 'no length'}")
            return False
            
        logger.info("Feature mismatch test passed: Successfully made predictions with mismatched features")
        print("Feature mismatch test passed: Successfully made predictions with mismatched features")
        return True
        
    except Exception as e:
        logger.error(f"Feature mismatch test failed with exception: {str(e)}")
        return False

def parse_args():
    """Parse command line arguments for headless mode."""
    parser = argparse.ArgumentParser(description="Networking Tester CLI Tests")
    
    parser.add_argument("--headless", action="store_true", 
                      help="Run in headless mode (no UI)")
    
    parser.add_argument("--test-ai-feature-mismatch", action="store_true",
                      help="Test the AI feature mismatch handling")
    
    parser.add_argument("--model-path", type=str,
                      help="Path to the anomaly detector model")
    
    parser.add_argument("--scaler-path", type=str,
                      help="Path to the anomaly detector scaler")
                      
    parser.add_argument("--file", type=str,
                      help="Path to a PCAP file to analyze")
                      
    parser.add_argument("--live", action="store_true",
                      help="Run a live capture")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Setup logging first
    setup_logging()
    logger = logging.getLogger(__name__)
    
    args = parse_args()
    
    if args.headless:
        # Headless mode for automated testing
        if args.test_ai_feature_mismatch:
            if not args.model_path or not args.scaler_path:
                logger.error("Model path and scaler path are required for feature mismatch test")
                sys.exit(1)
                
            success = run_feature_mismatch_test(args.model_path, args.scaler_path)
            sys.exit(0 if success else 1)
        elif args.live and args.file:
            logger.error("--live and --file options cannot be used together")
            sys.exit(1)
        elif not args.file and not args.live:
            logger.error("Either --file or --live option is required in headless mode")
            sys.exit(1)
        elif args.file and not os.path.exists(args.file):
            logger.error(f"PCAP file not found: {args.file}")
            sys.exit(1)
            
        # Add more headless mode functionality here as needed
        logger.info("Headless mode not fully implemented for this option")
        sys.exit(1)
    else:
        # Interactive mode - normal operation
        run_main_loop()

if __name__ == "__main__":
    main()
