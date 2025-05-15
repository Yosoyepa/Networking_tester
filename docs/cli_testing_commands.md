# Networking Tester CLI Commands for Testing

This document provides a comprehensive set of CLI commands for testing the networking_tester application's robustness.

## Basic Commands

```powershell
# Display help information
python main.py --help

# Run the application with default settings
python main.py

# Version information
python main.py --version

# Run in debug mode
python main.py --debug
```

## Live Capture Commands

```powershell
# Start a live capture on default interface
python main.py --live

# Start a live capture on a specific interface
python main.py --live --interface eth0

# Capture with a specific duration (in seconds)
python main.py --live --duration 30

# Capture with a packet limit
python main.py --live --max-packets 100

# Apply a capture filter (BPF syntax)
python main.py --live --filter "tcp port 80"

# Capture with specific output format
python main.py --live --output-format json

# Save the capture to a file
python main.py --live --save-pcap capture.pcap

# Combination of options
python main.py --live --interface eth0 --duration 60 --filter "ip and not broadcast" --save-pcap capture.pcap
```

## PCAP File Analysis Commands

```powershell
# Analyze a PCAP file
python main.py --file data/captures/test_ethernet2_v3.pcap

# Analyze multiple PCAP files
python main.py --file data/captures/test_ethernet2_v3.pcap data/captures/test_flow_debug.pcap

# Analyze with a specific output format
python main.py --file data/captures/test_ethernet2_v3.pcap --output-format json

# Save report to a specific file
python main.py --file data/captures/test_ethernet2_v3.pcap --report-file my_report.json

# Apply a display filter
python main.py --file data/captures/test_ethernet2_v3.pcap --display-filter "tcp.port == 443"
```

## AI Features Testing Commands

```powershell
# Run with AI anomaly detection
python main.py --file data/captures/test_ethernet2_v3.pcap --ai-analysis

# Specify a custom model path
python main.py --file data/captures/test_ethernet2_v3.pcap --ai-analysis --model-path data/models/custom_model.joblib

# Train a new AI model with a PCAP file
python main.py --train-model --training-file data/captures/test_ethernet2_v3.pcap

# Specify custom output paths for trained model
python main.py --train-model --training-file data/captures/test_ethernet2_v3.pcap --model-output data/models/my_model.joblib --scaler-output data/models/my_scaler.joblib

# Run with AI analysis but disable specific AI components
python main.py --file data/captures/test_ethernet2_v3.pcap --ai-analysis --disable-qos-analysis

# Set anomaly threshold
python main.py --file data/captures/test_ethernet2_v3.pcap --ai-analysis --anomaly-threshold 0.8
```

## Reporting and Output Commands

```powershell
# Generate report only (no visualization)
python main.py --file data/captures/test_ethernet2_v3.pcap --report-only

# Specify report format
python main.py --file data/captures/test_ethernet2_v3.pcap --report-format json

# Specify report file
python main.py --file data/captures/test_ethernet2_v3.pcap --report-file my_custom_report.json

# Enable verbose output
python main.py --file data/captures/test_ethernet2_v3.pcap --verbose

# Quiet mode (minimal output)
python main.py --file data/captures/test_ethernet2_v3.pcap --quiet
```

## Advanced Features and Edge Cases

```powershell
# Run with a custom configuration file
python main.py --config my_custom_config.yaml

# Test with an empty capture file
python main.py --file empty.pcap

# Test with a very large capture file
python main.py --file large_capture.pcap --memory-limit 1024

# Test with malformed packets
python main.py --file malformed_packets.pcap

# Run with specific log level
python main.py --log-level DEBUG

# Specify log file
python main.py --log-file my_custom.log

# Run with time constraints
python main.py --file data/captures/test_ethernet2_v3.pcap --start-time "2025-05-15 12:00:00" --end-time "2025-05-15 13:00:00"

# Test database integration
python main.py --file data/captures/test_ethernet2_v3.pcap --db-store

# Test with concurrency
python main.py --file data/captures/test_ethernet2_v3.pcap --parallel-processing 4

# Run unit tests
python -m unittest discover tests

# Run specific test case
python -m unittest tests.test_anomaly_detector

# Run tests with coverage
python -m coverage run -m unittest discover tests
python -m coverage report
python -m coverage html
```

## Error Handling and Robustness Testing

```powershell
# Test with invalid interface
python main.py --live --interface nonexistent_interface

# Test with invalid file path
python main.py --file nonexistent_file.pcap

# Test with invalid filter syntax
python main.py --live --filter "invalid syntax"

# Test with invalid configuration
python main.py --config invalid_config.yaml

# Test with insufficient permissions
# Run without admin rights when capturing on restricted interfaces

# Test with conflicting options
python main.py --live --file data/captures/test_ethernet2_v3.pcap

# Test with extreme values
python main.py --live --duration 9999999
python main.py --live --max-packets 0
python main.py --file data/captures/test_ethernet2_v3.pcap --anomaly-threshold 2.0

# Test with special characters in file paths
python main.py --file "data/captures/test file with spaces.pcap"
python main.py --file "data/captures/test_file_with_$pecial_chars.pcap"

# Interrupt handling (press Ctrl+C during execution)
```

## Interactive Mode Commands

```powershell
# Start in interactive mode
python main.py --interactive

# Expected interactive commands:
# - help
# - start_capture
# - stop_capture
# - load_file data/captures/test_ethernet2_v3.pcap
# - show_statistics
# - detect_anomalies
# - generate_report
# - exit
```

Note: Some of these commands may not be implemented in the current version of networking_tester and would serve as feature suggestions for future development. Adjust commands based on the actual CLI interface of your application.
