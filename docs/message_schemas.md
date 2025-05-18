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

This completes the definition of the initial data schemas. The next step according to Task 1.1 would be to set up a local message queue instance. However, I cannot perform that action directly.
