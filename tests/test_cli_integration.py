#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CLI integration tests for the networking_tester program."""

import os
import sys
import unittest
import subprocess
import tempfile
import shutil
from pathlib import Path

class CLIIntegrationTests(unittest.TestCase):
    """Integration tests for the networking_tester CLI interface."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment once for all tests."""
        # Get the directory where the networking_tester code is
        cls.project_dir = Path(__file__).parent.parent.absolute()
        cls.main_script = os.path.join(cls.project_dir, "main.py")  # Changed to main.py for distributed architecture
        cls.test_pcap = os.path.join(cls.project_dir, "data", "captures", "test_ethernet2_v3.pcap")
        
        # Create a temporary directory for test outputs
        cls.temp_dir = tempfile.mkdtemp()
        cls.temp_report = os.path.join(cls.temp_dir, "test_report.json")
        
        # Environment variables to ensure consistent behavior
        cls.env = os.environ.copy()
        cls.env["PYTHONIOENCODING"] = "utf-8"
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests have run."""
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)
    
    def _run_command(self, args):
        """Helper to run a command and return the result."""
        cmd = [sys.executable, self.main_script] + args
        proc = subprocess.run(
            cmd,
            cwd=self.project_dir,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'  # Replace problematic Unicode characters
        )
        return proc
    
    def test_file_not_found(self):
        """Test that the program returns an error for a non-existent file."""
        result = self._run_command(["--file", "nonexistent_file.pcap", "--headless"])
        self.assertNotEqual(result.returncode, 0, "Program should fail with non-existent file")
        self.assertIn("not found", result.stderr.lower() + result.stdout.lower())
    
    def test_invalid_options(self):
        """Test handling of invalid option combinations."""
        result = self._run_command(["--live", "--file", self.test_pcap, "--headless"])
        self.assertNotEqual(result.returncode, 0, "Program should fail with incompatible options")
        self.assertIn("cannot be used together", result.stderr.lower() + result.stdout.lower())
    
    def test_anomaly_detector_feature_mismatch_handling(self):
        """
        Test that the anomaly detector handles feature mismatches correctly.
        
        This is our primary test for the fixed functionality.
        """
        # First, let's verify the model exists so we can skip the test if it doesn't
        model_path = os.path.join(self.project_dir, "data", "models", "ai_anomaly_detector.joblib")
        scaler_path = os.path.join(self.project_dir, "data", "models", "ai_anomaly_detector_scaler.joblib")
        
        if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
            self.skipTest("AI model files not found, skipping feature mismatch test")
        
        # Use the --ai-test-mismatch option that should be added to trigger feature mismatch test
        # This option would run a predefined test with features that don't match the model
        result = self._run_command([
            "--test-ai-feature-mismatch", 
            "--model-path", model_path,
            "--scaler-path", scaler_path,
            "--headless"
        ])
        
        # If our fix works, the command should succeed
        self.assertEqual(result.returncode, 0, 
                         f"Feature mismatch test failed: {result.stderr}")
        self.assertIn("feature mismatch test passed", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
