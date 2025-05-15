# AI Monitoring Approach in networking_tester

This document outlines the approach for integrating Artificial Intelligence (AI) / Machine Learning (ML)
capabilities into the `networking_tester` project. The goal is to monitor and analyze network traffic
for security, Quality of Service (QoS), and performance aspects.

## Core Modules

The AI monitoring functionality resides within the `src/ai_monitoring/` package and consists of the
following key components:

1.  **`PacketFeatureExtractor` (`feature_extractor.py`)**:
    *   **Purpose**: To convert raw and analyzed packet data (from existing analyzers like `ProtocolAnalyzer`, `IEEE802_3_Analyzer`) into a numerical format (feature vectors) suitable for ML models.
    *   **Procedure**: It extracts various fields from packet headers and analysis metadata, such as packet length, protocol type (encoded numerically), source/destination ports, TCP flags (as binary features), DSCP values, Wi-Fi specific attributes (like TID, signal strength if available), and timestamps.
    *   **Output**: A dictionary of features for each packet, or a Pandas DataFrame when processing multiple packets.

2.  **`AnomalyDetector` (`anomaly_detector.py`)**:
    *   **Purpose**: To identify unusual or suspicious network packets or flows that might indicate security threats or network problems.
    *   **Procedure**:
        *   Utilizes an `IsolationForest` algorithm from `scikit-learn`. This is an unsupervised learning algorithm effective for outlier detection.
        *   Features extracted by `PacketFeatureExtractor` are first scaled using `StandardScaler`.
        *   The model can be trained on a baseline of "normal" traffic. If a pre-trained model is not available, it can be trained on the initial set of captured data.
        *   During prediction, it assigns an anomaly score to each packet/flow. Scores below a certain threshold (or predictions of -1 by the model) are flagged as anomalies.
    *   **Output**: For each input sample, it provides an anomaly prediction (-1 for anomaly, 1 for normal) and an anomaly score.
    *   **"Quality Values" (Security)**:
        *   Anomaly Score: A numerical value indicating how anomalous a sample is.
        *   Prediction: A binary label (Normal/Anomalous).
        *   Description: The model's parameters and the general behavior of Isolation Forest.

3.  **`QoSMLAnalyzer` (`qos_analyzer_ml.py`)**:
    *   **Purpose**: To assess and interpret QoS markings in network traffic and identify potential QoS issues.
    *   **Procedure**:
        *   Analyzes Differentiated Services Code Point (DSCP) values from IP packet headers and User Priority (UP) / TID values from 802.11 Wi-Fi QoS control fields.
        *   It maps these numerical values to their standard textual meanings (e.g., Best Effort, Expedited Forwarding for DSCP; Voice, Video, Best Effort, Background for Wi-Fi Access Categories).
        *   Initially, this module uses a rule-based approach for interpretation based on common standards (e.g., RFCs for DSCP, IEEE 802.11 for Wi-Fi UP).
        *   Future enhancements may include ML models to learn QoS patterns or detect deviations from expected QoS policies.
    *   **Output**: The input feature set augmented with columns describing the meaning of QoS markings (e.g., `dscp_meaning`, `wifi_ac_name`) and a basic assessment of `qos_concerns`.
    *   **"Quality Values" (QoS)**:
        *   DSCP Name and Description (e.g., "Expedited Forwarding (EF) - High priority, low-latency").
        *   Wi-Fi Access Category Name and Description (e.g., "Voice (AC_VO) - Voice over IP").
        *   Identified QoS concerns based on heuristics (e.g., "High priority for very small packet").

4.  **`PerformanceMLAnalyzer` (`performance_analyzer_ml.py`)**:
    *   **Purpose**: To analyze packet characteristics relevant to network performance, with the long-term goal of estimating speeds and identifying bottlenecks.
    *   **Procedure**:
        *   Initial version focuses on per-packet features. It categorizes packets by size (Small, Medium, Large) as a rudimentary indicator.
        *   Provides general notes on the typical performance implications of common protocols (e.g., TCP's reliability vs. UDP's speed for real-time).
        *   **Important Note**: True performance metrics like throughput (Mbps/Gbps) and latency require analyzing sequences of packets over time (flow analysis). This is a more complex feature planned for future development. The current module lays groundwork by identifying packet-level attributes.
    *   **Output**: The input feature set augmented with `packet_size_category` and `protocol_performance_note`.
    *   **"Quality Values" (Performance)**:
        *   Packet Size Category (e.g., "Large Packet").
        *   Protocol Performance Note (e.g., "UDP (fast, unreliable)").
        *   (Future) Estimated throughput, latency, jitter.

## Integration and Workflow

1.  **Data Collection**: `FrameCapture` captures packets.
2.  **Basic Analysis**: `AnalysisEngine` uses `IEEE802_3_Analyzer`, `IEEE802_11_Analyzer`, `ProtocolAnalyzer` to perform initial parsing and data extraction for each packet.
3.  **Feature Extraction**: The output from `AnalysisEngine` is passed to `PacketFeatureExtractor` to generate numerical features.
4.  **AI Analysis**: The extracted features (typically as a Pandas DataFrame) are then fed into:
    *   `AnomalyDetector` for security assessment.
    *   `QoSMLAnalyzer` for QoS assessment.
    *   `PerformanceMLAnalyzer` for performance insights.
5.  **Results**: Each AI module augments the data with its findings (predictions, scores, interpretations).
6.  **Reporting/UI**: These augmented results will be made available to the `reporting` module and the `ui` module for display to the user, including the descriptions of the AI procedures and the "quality values" obtained.

## Future Enhancements

*   **Flow-based Analysis**: Implement logic to group packets into flows for more context-aware AI analysis (crucial for accurate performance metrics and some security scenarios).
*   **Advanced ML Models**: Explore other ML algorithms (e.g., LSTMs for sequential data, GNNs for network topology) as the system matures.
*   **Online Learning**: Adapt models over time as network behavior changes.
*   **User Feedback Loop**: Allow users to label anomalies to improve model accuracy.
*   **Model Management**: Robust system for versioning, deploying, and monitoring ML models.

This approach provides a foundational framework for integrating AI into `networking_tester`, starting with practical per-packet analysis and paving the way for more sophisticated techniques.
