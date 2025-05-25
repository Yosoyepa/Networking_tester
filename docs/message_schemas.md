# Message Queue Data Schemas

This document defines the data schemas for messages passed between services via the message queue.

## Phase 1 Schemas

### 1. Raw Frames Message

*   **Queue/Topic Name:** `raw_frames_queue`
*   **Description:** Contains a raw network frame captured by the Packet Ingestor Service.
*   **Producer:** Packet Ingestor Service
*   **Consumer(s):** Packet Parser Service
*   **Format:** JSON
*   **Schema:**
    ```json
    {
        "timestamp": "ISO8601_string",  // Timestamp of capture (e.g., "2025-05-18T10:30:05.123Z")
        "interface": "string",          // Network interface name (e.g., "eth0", "wlan0") or "PCAP_FILE"
        "capture_source_identifier": "string", // e.g., filename if from PCAP, or a unique ID for a live capture session
        "frame_bytes": "base64_encoded_string" // Raw frame data as a Base64 encoded string
    }
    ```
*   **Example:**
    ```json
    {
        "timestamp": "2025-05-18T14:22:10.543Z",
        "interface": "eth0",
        "capture_source_identifier": "live_capture_session_001",
        "frame_bytes": "AP8A/wD/AP8AAQACAwQFBgYBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oz4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8="
    }
    ```

### 2. Parsed Packets Message

*   **Queue/Topic Name:** `parsed_packets_queue`
*   **Description:** Contains structured data extracted from a network frame by the Packet Parser Service.
*   **Producer:** Packet Parser Service
*   **Consumer(s):** Feature Extractor Service, Core Analysis & Aggregation Service, Statistics Collector Service (initially)
*   **Format:** JSON
*   **Schema:**
    *   The schema should be flexible enough to accommodate various protocols. It will be a nested JSON object.
    *   A `packet_id` should be included to uniquely identify the parsed packet, potentially linking back to the raw frame or for downstream correlation.
    *   It should include the original `timestamp` and `interface` from the Raw Frame message for context.
    ```json
    {
        "packet_id": "uuid_string",          // Unique identifier for this parsed packet
        "raw_frame_timestamp": "ISO8601_string", // Timestamp from the original Raw Frame message
        "parsing_timestamp": "ISO8601_string", // Timestamp when parsing was completed
        "source_interface": "string",        // Interface from the original Raw Frame message
        "capture_source_identifier": "string", // Identifier from the original Raw Frame message
        "layers": {
            "ethernet": { // Example: Ethernet II
                "destination_mac": "string", // e.g., "00:1A:2B:3C:4D:5E"
                "source_mac": "string",      // e.g., "00:1A:2B:3C:4D:5F"
                "ethertype": "hex_string"    // e.g., "0x0800" for IPv4
            },
            "dot11": { // Example: IEEE 802.11 (WiFi) - mutually exclusive with ethernet usually
                "type_subtype": "integer",   // e.g., 32 (Data frame)
                "flags": "string",           // e.g., "ToDS"
                "duration_id": "integer",
                "address1": "string",        // Receiver Address (RA)
                "address2": "string",        // Transmitter Address (TA)
                "address3": "string",        // Destination Address (DA) or BSSID
                "address4": "string",        // Optional Source Address (SA)
                "sequence_control": "integer",
                "qos_control": "object",     // Optional, if QoS data frame
                "ht_control": "object",      // Optional, if HT frame
                // ... other 802.11 specific fields like signal strength if available from capture
            },
            "ip": { // Example: IPv4 or IPv6
                "version": "integer",        // e.g., 4 or 6
                "source_ip": "string",       // e.g., "192.168.1.100"
                "destination_ip": "string",  // e.g., "8.8.8.8"
                "protocol": "integer",       // e.g., 6 for TCP, 17 for UDP
                "ttl": "integer",
                "length": "integer",
                // ... other IP fields (DSCP, flags, fragment offset etc.)
            },
            "tcp": {
                "source_port": "integer",
                "destination_port": "integer",
                "sequence_number": "long",
                "acknowledgment_number": "long",
                "flags": {
                    "syn": "boolean",
                    "ack": "boolean",
                    "fin": "boolean",
                    "rst": "boolean",
                    "psh": "boolean",
                    "urg": "boolean"
                },
                "window_size": "integer",
                "checksum": "hex_string",
                "urgent_pointer": "integer",
                "options": "object" // Key-value pairs for TCP options
            },
            "udp": {
                "source_port": "integer",
                "destination_port": "integer",
                "length": "integer",
                "checksum": "hex_string"
            },
            "icmp": {
                "type": "integer",
                "code": "integer",
                "checksum": "hex_string",
                // ... other ICMP fields (e.g., id, sequence for echo)
            },
            "payload": { // Application layer data or unparsed remainder
                "payload_bytes_base64": "base64_encoded_string", // First N bytes or all of it
                "payload_length_original": "integer" // Original length of the payload
            }
            // ... other protocol layers as needed (e.g., ARP, DNS, HTTP headers)
        },
        "parsing_errors": ["string_array"] // Optional: List of errors encountered during parsing
    }
    ```
*   **Example (Simplified for an IPv4/TCP packet):**
    ```json
    {
        "packet_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "raw_frame_timestamp": "2025-05-18T14:22:10.543Z",
        "parsing_timestamp": "2025-05-18T14:22:10.550Z",
        "source_interface": "eth0",
        "capture_source_identifier": "live_capture_session_001",
        "layers": {
            "ethernet": {
                "destination_mac": "00:AA:BB:CC:DD:EE",
                "source_mac": "00:11:22:33:44:55",
                "ethertype": "0x0800"
            },
            "ip": {
                "version": 4,
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.5",
                "protocol": 6,
                "ttl": 64,
                "length": 52
            },
            "tcp": {
                "source_port": 54321,
                "destination_port": 80,
                "sequence_number": 1000,
                "acknowledgment_number": 0,
                "flags": { "syn": true, "ack": false, "fin": false, "rst": false, "psh": false, "urg": false },
                "window_size": 65535,
                "checksum": "0xabcd",
                "urgent_pointer": 0,
                "options": { "mss": 1460 }
            },
            "payload": {
                "payload_bytes_base64": "SGVsbG8gd29ybGQ=",
                "payload_length_original": 11
            }
        },
        "parsing_errors": []
    }
    ```

## Phase 2 Schemas

### 1. Feature Vectors Message

*   **Queue/Topic Name:** `feature_vectors_queue` (Proposed)
*   **Description:** Contains numerical feature vectors extracted from a parsed packet, suitable for ML model consumption.
*   **Producer:** Feature Extractor Service
*   **Consumer(s):** QoS ML Inference Service, Core Analysis & Aggregation Service
*   **Format:** JSON
*   **Schema (based on `well_architecture_tasks.md` and typical feature sets):
    ```json
    {
        "schema_version": "1.0",
        "feature_vector_id": "uuid_string",       // Unique identifier for this feature vector
        "parsed_packet_id": "uuid_string",        // ID of the source Parsed Packet message
        "raw_frame_id": "uuid_string",            // ID of the original Raw Frame message (if available/passed through)
        "extraction_timestamp": "ISO8601_string",// Timestamp when feature extraction was completed
        "source_info": {                        // Copied from Parsed Packet message for context
            "type": "string",                   // e.g., "live_capture", "pcap_file"
            "identifier": "string"              // e.g., "eth0", "my_capture.pcap"
        },
        "features": {                           // Dictionary of extracted features
            "frame_length": "number",
            "timestamp": "number",              // Packet timestamp (float, e.g., epoch time)
            "ip_version": "number",
            "ip_ihl": "number",
            "ip_tos": "number",
            "dscp": "number",
            "ip_len": "number",
            "ip_id": "number",
            "ip_flags": "number",               // Integer representation of IP flags
            "ip_frag": "number",
            "ip_ttl": "number",
            "ip_protocol": "number",
            "ip_src": "string",                 // Source IP Address (kept as string for now)
            "ip_dst": "string",                 // Destination IP Address (kept as string for now)
            "is_ip": "number",                  // 0 or 1
            "is_tcp": "number",                 // 0 or 1
            "is_udp": "number",                 // 0 or 1
            "is_icmp": "number",                // 0 or 1
            "src_port": "number",
            "dst_port": "number",
            "tcp_seq": "number",
            "tcp_ack": "number",
            "tcp_dataofs": "number",
            "tcp_reserved": "number",
            "tcp_flags": "number",              // Integer representation of TCP flags
            "tcp_window": "number",
            "tcp_chksum": "number",
            "tcp_urgptr": "number",
            "udp_len": "number",
            "udp_chksum": "number",
            "icmp_type": "number",
            "icmp_code": "number",
            "icmp_chksum": "number",
            "is_wifi": "number",                // 0 or 1
            "wifi_fc_type": "number",
            "wifi_fc_subtype": "number",
            "wifi_fc_to_ds": "number",
            "wifi_fc_from_ds": "number",
            "wifi_fc_more_frag": "number",
            "wifi_fc_retry": "number",
            "wifi_fc_pwr_mgt": "number",
            "wifi_fc_more_data": "number",
            "wifi_fc_protected": "number",
            "wifi_fc_order": "number",
            "wifi_duration_id": "number",
            "wifi_addr1": "string",              // WiFi MAC Address (kept as string for now)
            "wifi_addr2": "string",
            "wifi_addr3": "string",
            "wifi_addr4": "string",
            "wifi_tid": "number",
            "payload_length": "number"
            // ... any other numerical features ...
        }
    }
    ```
*   **Example:**
    ```json
    {
        "schema_version": "1.0",
        "feature_vector_id": "f1e2d3c4-b5a6-7890-1234-abcdef123456",
        "parsed_packet_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "raw_frame_id": "r1r2r3r4-e5f6-7890-1234-567890abcdef",
        "extraction_timestamp": "2025-05-18T14:22:10.560Z",
        "source_info": {
            "type": "live_capture",
            "identifier": "eth0"
        },
        "features": {
            "frame_length": 60,
            "timestamp": 1747563730.543,
            "ip_version": 4,
            "ip_ihl": 5,
            "ip_tos": 0,
            "dscp": 0,
            "ip_len": 40,
            "ip_id": 12345,
            "ip_flags": 2, // Assuming DF flag
            "ip_frag": 0,
            "ip_ttl": 64,
            "ip_protocol": 6,
            "ip_src": "192.168.1.10",
            "ip_dst": "10.0.0.5",
            "is_ip": 1,
            "is_tcp": 1,
            "is_udp": 0,
            "is_icmp": 0,
            "src_port": 54321,
            "dst_port": 80,
            "tcp_seq": 1000,
            "tcp_ack": 0,
            "tcp_dataofs": 5,
            "tcp_reserved": 0,
            "tcp_flags": 2, // SYN flag
            "tcp_window": 65535,
            "tcp_chksum": 43981, // Example checksum value (0xabcd)
            "tcp_urgptr": 0,
            "udp_len": 0,
            "udp_chksum": 0,
            "icmp_type": 0,
            "icmp_code": 0,
            "icmp_chksum": 0,
            "is_wifi": 0,
            "wifi_fc_type": 0,
            "wifi_fc_subtype": 0,
            "wifi_fc_to_ds": 0,
            "wifi_fc_from_ds": 0,
            "wifi_fc_more_frag": 0,
            "wifi_fc_retry": 0,
            "wifi_fc_pwr_mgt": 0,
            "wifi_fc_more_data": 0,
            "wifi_fc_protected": 0,
            "wifi_fc_order": 0,
            "wifi_duration_id": 0,
            "wifi_addr1": "00:00:00:00:00:00",
            "wifi_addr2": "00:00:00:00:00:00",
            "wifi_addr3": "00:00:00:00:00:00",
            "wifi_addr4": "00:00:00:00:00:00",
            "wifi_tid": 0,
            "payload_length": 0 // Assuming no payload in this TCP SYN example
        }
    }
    ```

### 2. QoS Predictions Message

*   **Queue/Topic Name:** `qos_predictions_queue` (Proposed)
*   **Description:** Contains the QoS prediction results from the ML Inference Service for a given feature vector.
*   **Producer:** QoS ML Inference Service
*   **Consumer(s):** Core Analysis & Aggregation Service, Reporting Service (potentially)
*   **Format:** JSON
*   **Schema:**
    ```json
    {
        "schema_version": "1.0",
        "qos_prediction_id": "uuid_string",     // Unique identifier for this prediction
        "feature_vector_id": "uuid_string",    // ID of the source Feature Vector message
        "model_id": "string",                   // Identifier of the ML model used for prediction (e.g., model version, path)
        "prediction_timestamp": "ISO8601_string",// Timestamp when prediction was made
        "source_info": {                        // Copied from Feature Vector message for context
            "type": "string",
            "identifier": "string"
        },
        "qos_score": "number",                 // Predicted QoS score (e.g., a probability or a custom metric)
        "is_anomaly": "boolean",               // Flag indicating if the packet/flow is considered an anomaly
        "prediction_details": {               // Optional: Additional details from the model
            "model_type": "string",           // e.g., "GMM", "VAE", "RandomForest_v2.3"
            "raw_prediction": "any",          // Raw output from the model (e.g., probabilities per class)
            "confidence": "number",           // Optional: Confidence score of the prediction
            "contributing_features": "object" // Optional: Features that contributed most to the prediction
        }
    }
    ```
*   **Example:**
    ```json
    {
        "schema_version": "1.0",
        "qos_prediction_id": "p1q2r3s4-t5u6-v7w8-x9y0-zabcdef12345",
        "feature_vector_id": "f1e2d3c4-b5a6-7890-1234-abcdef123456",
        "model_id": "qos_model_v1.2.pkl",
        "prediction_timestamp": "2025-05-18T14:22:10.570Z",
        "source_info": {
            "type": "live_capture",
            "identifier": "eth0"
        },
        "qos_score": 0.85,
        "is_anomaly": false,
        "prediction_details": {
            "model_type": "RandomForest_QoS_v1.2",
            "raw_prediction": [0.15, 0.85],
            "confidence": 0.92
        }
    }
    ```

This completes the definition of the initial data schemas. The next step according to Task 1.1 would be to set up a local message queue instance. However, I cannot perform that action directly.
