"""
Simple test file to check if we can create and use a PerformanceMLAnalyzer.
"""

import pandas as pd
import sys
import os

# Add project root to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

# Try to import the class
try:
    from src.ai_monitoring import PerformanceMLAnalyzer
    print("Success: PerformanceMLAnalyzer imported")
    
    # Try to instantiate the class
    analyzer = PerformanceMLAnalyzer()
    print("Success: PerformanceMLAnalyzer instantiated")
    
    # Try to call a method
    description = analyzer.get_description()
    print("Success: Got description:", description.get('name'))
    
except ImportError as e:
    print(f"Import Error: {e}")
except Exception as e:
    print(f"Other Error: {e}")

print("Test completed")
