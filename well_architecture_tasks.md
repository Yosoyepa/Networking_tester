# Design Plan: Scalable and Sustainable Architecture for `networking_tester`

## 1. Executive Summary & Goals
This plan outlines a phased architectural redesign for the `networking_tester` project. The primary objective is to evolve the system into a scalable, resilient, and maintainable platform for network traffic capture, analysis, and ML-based QoS anomaly detection.

**Key Goals:**
1.  **Achieve High Scalability & Throughput:** Enable the system to efficiently ingest and process large volumes of network traffic (IEEE 802.3 & 802.11) by adopting a distributed, asynchronous architecture.
2.  **Enhance ML Capabilities & Management:** Facilitate scalable ML inference, robust model management (training, versioning, deployment), and easy updates for QoS anomaly detection.
3.  **Improve System Robustness & Extensibility:** Create a resilient system tolerant to component failures and easily extensible for new protocols, analysis types, and ML models.

## 2. Current Situation Analysis
The `networking_tester` project is currently a Python-based CLI application with a modular structure (`src/core/engine.py` as the orchestrator, separate modules for capture, analysis, AI monitoring, etc.). Configuration is managed via `config/settings.yaml`. Documentation (`ai_monitoring_approach.md`, `arquitectura.md`) indicates a primarily sequential processing flow within the `AnalysisEngine`.

**Key Pain Points & Limitations (relative to User Task goals):**
*   **Scalability Bottleneck:** The `AnalysisEngine` processes packets largely sequentially, limiting throughput for high-volume traffic.
*   **Coupled ML Processing:** ML feature extraction and inference are tightly coupled with the main packet processing loop, hindering independent scaling of ML tasks.
*   **Basic ML Model Management:** Relies on file paths in `settings.yaml`, lacking robust versioning, deployment, and dynamic update mechanisms for ML models.
*   **Resilience:** The current monolithic-like execution (even if internally modular) presents single points of failure.
*   **Extensibility:** While modules exist, integrating fundamentally new, resource-intensive analysis types or scaling specific parts of the analysis pipeline independently is challenging.
*   **Operational Complexity at Scale:** Deploying and managing multiple instances for distributed capture or analysis would be manual and complex.
*   **Observed Issues:** Log files indicate potential issues with feature mismatches in `AnomalyDetector` and error handling in some components, suggesting areas for robustness improvement.

## 3. Proposed Solution / Refactoring Strategy

### 3.1. High-Level Design / Architectural Overview
The proposed solution is an event-driven, microservices-oriented architecture. This architecture decouples components, allowing for independent scaling, development, and deployment, addressing the core requirements of scalability, resilience, and maintainability.

**Core Principles:**
*   **Asynchronous Communication:** Services communicate via message queues, enabling loose coupling and load balancing.
*   **Service Specialization:** Each service has a well-defined responsibility.
*   **Horizontal Scalability:** Individual services can be scaled out by running multiple instances.
*   **Data-Driven Workflows:** Packet data and analysis results flow through a pipeline of services.

**Textual Diagram (Mermaid.js):**
```mermaid
graph TD
    subgraph User Interaction
        CLI[CLI / UI]
    end

    subgraph Data Ingestion & Initial Processing
        NI[Network Interface] --> IngestorSvc[Packet Ingestor Service(s)]
        PCAPIn[PCAP Files] --> IngestorSvc
        IngestorSvc -- Raw Frames (bytes + metadata) --> MQ_Raw[Message Queue: Raw Frames]
        MQ_Raw --> ParserSvc[Packet Parser Service(s)]
        ParserSvc -- Parsed Packet Data (JSON) --> MQ_Parsed[Message Queue: Parsed Packets]
    end

    subgraph Feature Extraction & ML Pipeline
        MQ_Parsed --> FeatExtSvc[Feature Extractor Service(s)]
        FeatExtSvc -- Feature Vectors (JSON/Optimized Format) --> MQ_Features[Message Queue: Features]
        MQ_Features --> QoS_ML_Svc[QoS ML Inference Service(s)]
        QoS_ML_Svc -- QoS Anomaly Results --> MQ_MLResults[Message Queue: ML Results]
    end

    subgraph Analysis, Aggregation & Storage
        MQ_Parsed --> CoreAnalysisSvc[Core Analysis & Aggregation Service(s)]
        MQ_Features --> CoreAnalysisSvc
        MQ_MLResults --> CoreAnalysisSvc
        CoreAnalysisSvc --> PDS[Processed Data Store (e.g., Elasticsearch, Time-Series DB)]
        IngestorSvc -.-> RawPcapStore[Raw PCAP Store (e.g., S3/MinIO)]
    end

    subgraph ML Operations & Model Management
        MLOpsPipeline[MLOps Pipeline (Training, Evaluation, Versioning)]
        MLOpsPipeline --> ModelReg[ML Model Registry (e.g., MLflow, S3)]
        ModelReg <--> QoS_ML_Svc
        PDS --> MLOpsPipeline
    end

    subgraph Reporting & Alerting
        CLI --> APIGateway[API Gateway (Optional)]
        APIGateway --> IngestorSvc
        APIGateway --> ReportingSvc[Reporting Service]
        APIGateway --> AlertSvc[Alerting Service]
        ReportingSvc --> PDS
        CoreAnalysisSvc -.-> AlertSvc
    end

    %% Styling
    style CLI fill:#f9f,stroke:#333,stroke-width:2px
    style MQ_Raw fill:#ccf,stroke:#333,stroke-width:2px
    style MQ_Parsed fill:#ccf,stroke:#333,stroke-width:2px
    style MQ_Features fill:#ccf,stroke:#333,stroke-width:2px
    style MQ_MLResults fill:#ccf,stroke:#333,stroke-width:2px
    style PDS fill:#cfc,stroke:#333,stroke-width:2px
    style RawPcapStore fill:#cfc,stroke:#333,stroke-width:2px
    style ModelReg fill:#cfc,stroke:#333,stroke-width:2px
```

### 3.2. Key Components / Modules

1.  **Packet Ingestor Service:**
    *   **Responsibilities:** Captures raw frames from network interfaces (using Scapy) or reads from PCAP files. Adds essential metadata (timestamp, source interface). Publishes raw frame data (e.g., serialized bytes) to the `Raw Frames` queue. Optionally archives raw PCAPs to `Raw PCAP Store`.
    *   **Based on:** `src/capture/frame_capture.py`.
2.  **Packet Parser Service:**
    *   **Responsibilities:** Consumes raw frames. Parses L2 (Ethernet, 802.11), L3 (IP), L4 (TCP, UDP, ICMP) headers. Extracts protocol fields. Publishes structured "Parsed Packet Data" (e.g., JSON) to the `Parsed Packets` queue.
    *   **Based on:** `src/analysis/ieee802_3_analyzer.py`, `src/analysis/ieee802_11_analyzer.py`, `src/analysis/protocol_analyzer.py`.
3.  **Feature Extractor Service:**
    *   **Responsibilities:** Consumes "Parsed Packet Data". Generates numerical feature vectors suitable for ML models, focusing on QoS-relevant features. Publishes "Feature Vectors" to the `Features` queue.
    *   **Based on:** `src/ai_monitoring/feature_extractor.py`.
4.  **QoS ML Inference Service:**
    *   **Responsibilities:** Consumes "Feature Vectors". Loads appropriate QoS anomaly detection models from the `ML Model Registry`. Performs inference. Publishes "QoS Anomaly Results" (scores, flags) to the `ML Results` queue.
    *   **Based on:** `src/ai_monitoring/anomaly_detector.py` (adapted for QoS models).
5.  **Core Analysis & Aggregation Service:**
    *   **Responsibilities:** Consumes "Parsed Packet Data", "Feature Vectors", and "ML Results". Performs flow analysis (stateful, may require careful design for distribution), rule-based anomaly detection (non-ML), statistics collection, and correlates ML results with packet data. Persists comprehensive analysis results and aggregated statistics to the `Processed Data Store`. Can trigger alerts.
    *   **Based on:** `src/analysis/flow_analyzer.py`, `src/analysis/rule_based_anomaly_detector.py`, `src/analysis/statistics_collector.py`.
6.  **MLOps Pipeline & Model Registry:**
    *   **Responsibilities:** (Offline/Separate) Manages the lifecycle of ML models: training (using data from `Processed Data Store` or dedicated datasets), evaluation, versioning, and deployment to the `ML Model Registry`. The inference services consume models from this registry.
    *   **Based on:** Concepts from `src/ai_monitoring/qos_analyzer_ml.py` (training aspects), `src/ai_monitoring/performance_analyzer_ml.py` (training aspects).
7.  **Reporting Service:**
    *   **Responsibilities:** Provides an API or interface (callable by CLI) to generate reports in various formats (JSON, CSV, console). Queries data from the `Processed Data Store`.
    *   **Based on:** `src/reporting/report_generator.py`.
8.  **Alerting Service:**
    *   **Responsibilities:** Consumes alert-triggering events (e.g., from `Core Analysis Service` or `ML Inference Service`). Sends notifications based on configuration.
    *   **Based on:** `src/utils/alerter.py`.
9.  **Data Stores:**
    *   `Raw PCAP Store`: For archival of raw captures (e.g., S3, MinIO).
    *   `Processed Data Store`: For structured analysis results, features, statistics (e.g., Elasticsearch for search/analytics, InfluxDB for time-series stats, or a relational DB like PostgreSQL for structured results).
    *   `ML Model Registry`: For storing and versioning ML models (e.g., MLflow, S3 with a metadata layer).
10. **Message Queues:**
    *   Technology like Kafka, RabbitMQ, or Pulsar for inter-service communication. Topics: `Raw Frames`, `Parsed Packets`, `Features`, `ML Results`.
11. **CLI / API Gateway:**
    *   The existing CLI (`main.py`, `src/ui/menu_handler.py`) will be adapted to interact with this new architecture, potentially through an API Gateway that routes requests to the appropriate services or by publishing "command" messages to specific queues.

### 3.3. Detailed Action Plan / Phases

#### **Phase 1: Foundational Refactoring & Core Pipeline Decoupling**
*   **Objective(s):** Decouple packet capture, parsing, and basic analysis. Introduce message queues for asynchronous processing. Improve robustness of core components. Establish a basic data flow.
*   **Priority:** High

*   **Task 1.1: Define Core Data Schemas & Message Queue Setup**
    *   **Rationale/Goal:** Establish clear data contracts for messages passed between initial services. Set up a development/local message queue instance.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** Documented schemas for "Raw Frames" and "Parsed Packets". Message queue (e.g., RabbitMQ or Kafka) running locally.
*   **Task 1.2: Refactor Packet Ingestor**
    *   **Rationale/Goal:** Create a standalone `Packet Ingestor` component (can be a Python script/class initially) that captures/reads packets and publishes them to the "Raw Frames" queue.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** `Packet Ingestor` successfully publishes raw frames. Existing `src/capture` logic adapted.
*   **Task 1.3: Develop Packet Parser Service**
    *   **Rationale/Goal:** Create a `Packet Parser Service` that consumes from "Raw Frames" queue, performs L2-L4 parsing, and publishes to "Parsed Packets" queue.
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Service consumes raw frames and publishes structured parsed packet data. Logic from `src/analysis` (protocol/Ethernet/WiFi analyzers) integrated.
*   **Task 1.4: Develop Basic Statistics Collector Service**
    *   **Rationale/Goal:** Create a service that consumes "Parsed Packets" and computes basic statistics (similar to current `StatisticsCollector`). Store stats in a simple file or log output initially.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** Service consumes parsed packets and generates aggregate statistics. `src/analysis/statistics_collector.py` logic adapted.
*   **Task 1.5: Adapt CLI for New Workflow**
    *   **Rationale/Goal:** Modify `main.py` and `src/ui/menu_handler.py` to trigger the `Packet Ingestor` and display results from the `Statistics Collector Service`.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** CLI can initiate capture/PCAP processing and display basic statistics using the new decoupled components.
*   **Task 1.6: Robustness Review of Core Analyzers**
    *   **Rationale/Goal:** Address known issues (e.g., `EDecimal` error in `ieee802_11_analyzer.py`, `AttributeError` in `ieee802_3_analyzer.py` from logs) and improve error handling in parsing components.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** Core parsers are more resilient to malformed or unexpected packet structures. Unit tests cover edge cases.

#### **Phase 2: ML Integration & Scalability Enhancements**
*   **Objective(s):** Integrate ML feature extraction and QoS anomaly inference as scalable services. Introduce dedicated data stores.
*   **Priority:** High (after Phase 1)

*   **Task 2.1: Develop Feature Extractor Service**
    *   **Rationale/Goal:** Create a service that consumes "Parsed Packets", extracts ML features, and publishes "Feature Vectors".
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** Service operational. `src/ai_monitoring/feature_extractor.py` logic adapted.
*   **Task 2.2: Develop QoS ML Inference Service**
    *   **Rationale/Goal:** Create a service that consumes "Feature Vectors", loads QoS anomaly models, performs inference, and publishes "ML Results".
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Service operational. `src/ai_monitoring/anomaly_detector.py` logic adapted. Robust handling of feature mismatches (as indicated by `anomaly_detector_fixed.py` and logs).
*   **Task 2.3: Implement Basic ML Model Registry**
    *   **Rationale/Goal:** Set up a simple model store (e.g., S3 bucket or shared filesystem with a manifest file) for versioning and accessing ML models.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** QoS ML Inference Service can load models from this registry.
*   **Task 2.4: Develop Core Analysis & Aggregation Service (Initial Version)**
    *   **Rationale/Goal:** Create a service to consume "Parsed Packets", "Feature Vectors", and "ML Results". Correlate data and store combined results in a chosen `Processed Data Store` (e.g., Elasticsearch or PostgreSQL).
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Service stores comprehensive analysis data. Basic flow analysis and rule-based anomaly detection integrated.
*   **Task 2.5: Develop Reporting Service (Initial Version)**
    *   **Rationale/Goal:** Create a service that can query the `Processed Data Store` and generate reports (JSON, CSV initially).
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** CLI can request reports from this service. `src/reporting/report_generator.py` logic adapted.
*   **Task 2.6: Containerize Key Services**
    *   **Rationale/Goal:** Dockerize services developed in Phase 1 & 2 (Ingestor, Parser, Feature Extractor, ML Inference, Aggregator) to prepare for scalable deployment.
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Dockerfiles for each service. Services can be run using Docker Compose locally.

#### **Phase 3: Advanced Features, Full Distribution & MLOps**
*   **Objective(s):** Implement advanced analysis features, deploy services for full distribution (e.g., Kubernetes), establish a robust MLOps pipeline, and enhance operability.
*   **Priority:** Medium (after Phase 2)

*   **Task 3.1: Enhance Flow Analyzer for Distributed State**
    *   **Rationale/Goal:** Refactor `FlowAnalyzer` logic within the `Core Analysis & Aggregation Service` to handle distributed state if the service is scaled (e.g., using a distributed cache like Redis or by partitioning flows).
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Flow analysis works correctly across multiple instances of the aggregation service.
*   **Task 3.2: Implement MLOps Pipeline**
    *   **Rationale/Goal:** Develop a pipeline for automated ML model training, evaluation, versioning, and deployment to the `ML Model Registry`.
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Documented MLOps workflow. Scripts/tools for model training and deployment. Integration with `ML Model Registry`.
*   **Task 3.3: Implement Other ML-based Analyzers (e.g., Performance)**
    *   **Rationale/Goal:** Develop and integrate other ML-based analyzers (like `PerformanceMLAnalyzer`) as separate inference services or as part of the existing ML service structure.
    *   **Estimated Effort:** M per analyzer
    *   **Deliverable/Criteria for Completion:** New ML analysis capabilities integrated into the pipeline.
*   **Task 3.4: Full Deployment & Orchestration**
    *   **Rationale/Goal:** Deploy services using an orchestrator like Kubernetes for production-grade scalability, resilience, and management.
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Kubernetes deployment manifests. System running in a orchestrated environment.
*   **Task 3.5: Advanced Monitoring & Alerting**
    *   **Rationale/Goal:** Integrate comprehensive monitoring (metrics, logs, traces) for all services. Enhance `Alerting Service`.
    *   **Estimated Effort:** M
    *   **Deliverable/Criteria for Completion:** Monitoring dashboards. Alerting rules configured.
*   **Task 3.6: Extensibility Framework (Plugin System)**
    *   **Rationale/Goal:** Design and implement a plugin system to allow easier addition of new protocol parsers, feature extractors, or analysis modules without modifying core service code.
    *   **Estimated Effort:** L
    *   **Deliverable/Criteria for Completion:** Documented plugin API. Example plugin implemented.

### 3.4. Data Model Changes
*   **Message Queue Payloads:**
    *   **Raw Frames:** `{ "timestamp": "ISO8601", "interface": "eth0", "frame_bytes": "base64_encoded_string" }`
    *   **Parsed Packets:** Rich JSON structure representing decoded layers and fields (e.g., Ethernet, IP, TCP/UDP, WiFi details). Similar to what `all_analyzed_data` currently stores per packet, but standardized.
    *   **Feature Vectors:** `{ "packet_id": "unique_id_ref_parsed_packet", "timestamp": "ISO8601", "features": { "feat1": val1, ... } }`
    *   **ML Results:** `{ "packet_id": "unique_id_ref_parsed_packet", "model_id": "qos_anomaly_v1", "anomaly_score": 0.85, "is_anomaly": true, "details": {...} }`
*   **Processed Data Store:**
    *   Schema will depend on the chosen database.
    *   If Elasticsearch: Documents per packet/flow, indexed for querying.
    *   If Time-Series DB: Metrics like packet counts, protocol distributions, anomaly rates over time.
    *   If Relational DB: Tables for packets, flows, features, anomalies, statistics.
*   **ML Model Registry:**
    *   Metadata for each model: name, version, creation date, training data reference, performance metrics, path to model file.

### 3.5. API Design / Interface Changes
*   **Service-to-Service:** Primarily via message queues.
*   **API Gateway (if implemented):**
    *   `POST /capture/start`: Start live capture. Params: interface, filter, duration, etc.
    *   `POST /capture/pcap`: Submit PCAP for analysis.
    *   `GET /reports/{report_id}`: Retrieve a generated report.
    *   `POST /reports`: Request a new report. Params: time_range, filters, format.
    *   `GET /models`: List available ML models.
    *   `POST /models/{model_name}/deploy`: Deploy a specific model version.
*   **CLI Changes:**
    *   Will be refactored to interact with the API Gateway or publish commands to message queues.
    *   New commands for managing distributed capture, querying status, managing ML models (if exposed via CLI).

## 4. Key Considerations & Risk Mitigation

### 4.1. Technical Risks & Challenges
*   **Complexity of Distributed Systems:** Managing multiple services, inter-service communication, data consistency.
    *   **Mitigation:** Phased rollout, start with local process-based "services" communicating via local queues before full distribution. Use mature technologies (Kafka, Kubernetes). Invest in robust logging and monitoring from Phase 1.
*   **Stateful Analysis (Flows):** Distributing flow analysis requires careful state management.
    *   **Mitigation:** Use a distributed cache (e.g., Redis) for flow state, or partition flow data to specific aggregator instances. Start with simpler flow metrics in early phases.
*   **Message Queue Performance/Reliability:** The MQ becomes a critical component.
    *   **Mitigation:** Choose a robust MQ (e.g., Kafka). Implement dead-letter queues and retry mechanisms in services. Monitor MQ health.
*   **Data Volume in Processed Data Store:** Can grow very large.
    *   **Mitigation:** Choose a scalable data store. Implement data retention policies and archiving.
*   **ML Model Deployment & Management:** Ensuring correct model versions are used by inference services.
    *   **Mitigation:** Implement a proper ML Model Registry (e.g., MLflow). Version models and track their lineage.
*   **Feature Consistency:** Ensuring features extracted for training match those at inference time. (Log files indicate this is a current issue).
    *   **Mitigation:** Standardize feature extraction logic. Version feature extraction pipelines alongside models. Implement schema validation for feature vectors. Robust error handling in `AnomalyDetector` for feature mismatches.

### 4.2. Dependencies
*   **Internal (Task-to-Task):** Clearly defined by phases. Phase 2 depends on successful completion of Phase 1 components.
*   **External:**
    *   **Team Skills:** Requires expertise in distributed systems, message queues, containerization (Docker/Kubernetes), chosen data stores, and MLOps practices.
        *   **Mitigation:** Training, hiring, or phased adoption of technologies.
    *   **Infrastructure:** Requires infrastructure for message queues, data stores, and service deployment (potentially cloud or on-premise Kubernetes).
        *   **Mitigation:** Start with local/dev setups, plan infrastructure needs per phase.

### 4.3. Non-Functional Requirements (NFRs) Addressed
*   **Scalability:**
    *   Horizontally scalable services (Ingestors, Parsers, Feature Extractors, ML Inference, Aggregators).
    *   Asynchronous processing via message queues allows services to consume data at their own pace and handle bursts.
*   **Sustainability/Maintainability:**
    *   Microservices promote separation of concerns, making individual components easier to understand, develop, test, and maintain.
    *   Clear interfaces (message schemas, API contracts) reduce coupling.
*   **Resilience:**
    *   Decoupled services: failure of one service (e.g., ML inference) does not necessarily halt the entire pipeline (e.g., parsing and basic stats can continue).
    *   Message queues provide buffering and allow for retries if a consumer service is temporarily unavailable.
    *   Dead-letter queues can capture messages that consistently fail processing for later analysis.
*   **Extensibility:**
    *   New protocol parsers can be added as new instances/versions of the `Packet Parser Service` or by updating it.
    *   New ML models or analysis types can be introduced as new services consuming relevant data from the message queues.
    *   A plugin system (Phase 3) would further formalize this.
*   **Deployability/Operability:**
    *   Containerization (Docker) simplifies packaging and deployment.
    *   Orchestration (Kubernetes) automates deployment, scaling, and management of services.
    *   Centralized logging and monitoring (to be implemented) are crucial for operating a distributed system.
*   **Security (Considerations):**
    *   Secure inter-service communication (e.g., mTLS if deployed in Kubernetes).
    *   Secure access to data stores and ML model registry.
    *   Input validation at service boundaries.
    *   Regular security updates for all components and dependencies.

## 5. Success Metrics / Validation Criteria
*   **Scalability:**
    *   Measure maximum packet ingestion rate (packets/sec or Gbps) the system can handle before significant performance degradation or message queue backlog. Target a significant improvement (e.g., 5x, 10x) over baseline if measurable.
    *   Ability to scale individual services (e.g., ML inference workers) independently based on load.
*   **ML Model Management:**
    *   Time taken to deploy a new (retrained) QoS anomaly detection model to production inference services (e.g., < 1 hour).
    *   System supports versioning of ML models.
*   **Resilience:**
    *   System continues partial operation (e.g., data ingestion and parsing) if an ML inference service fails.
    *   Demonstrate successful retries and DLQ usage for transient errors.
*   **Extensibility:**
    *   Time/effort required to add support for a new, simple protocol analyzer or a new rule-based anomaly.
*   **Maintainability:**
    *   Code complexity metrics (e.g., cyclomatic complexity) for individual services remain manageable.
    *   Ease of onboarding new developers to specific services.
*   **Performance (QoS Anomaly Detection):**
    *   Accuracy, precision, recall, F1-score of the QoS anomaly detection models on benchmark datasets.
    *   End-to-end latency from packet ingestion to anomaly alert for critical anomalies.

## 6. Assumptions Made
*   The primary goal is a significant architectural shift towards a distributed system to meet scalability and long-term sustainability goals.
*   The team is willing to adopt new technologies like message queues (e.g., Kafka/RabbitMQ) and containerization (Docker), and potentially orchestration (Kubernetes).
*   The existing Python codebase (`src/` modules) provides a good foundation for the logic within the new services, but will require refactoring for service boundaries and asynchronous communication.
*   "High volume of traffic" implies a need for processing capabilities beyond what a single, monolithic application can typically handle efficiently and resiliently.
*   The focus for ML is initially on QoS anomaly detection, but the architecture should support other ML-driven analyses in the future.
*   The existing `settings.yaml` will serve as a base for service configurations, potentially managed by a dedicated configuration service or deployment-specific mechanisms in later phases.

## 7. Open Questions / Areas for Further Investigation
*   **Specific Message Queue Choice:** Kafka (high throughput, stream processing capabilities) vs. RabbitMQ (simpler, flexible routing) vs. Pulsar? Depends on specific performance needs and operational expertise.
*   **Specific Processed Data Store Choice:** Elasticsearch (good for search and Kibana dashboards), InfluxDB (time-series specific), ClickHouse (fast analytics), or a traditional RDBMS like PostgreSQL with JSONB? Depends on query patterns and data types.
*   **Stateful Analysis Strategy for Flows:** Deep dive into how flow state will be managed across distributed `Core Analysis & Aggregation Service` instances.
*   **Existing Infrastructure Constraints:** Are there any existing infrastructure limitations or preferences (e.g., cloud provider, existing Kubernetes cluster) that should influence technology choices?
*   **Budget for Infrastructure:** Cloud costs or on-premise hardware for a distributed system.
*   **Team's Current Expertise:** What is the team's current familiarity with microservices, message queues, Docker, Kubernetes, and specific data stores? This will influence the learning curve and implementation timeline.
*   **Definition of "High Volume":** Quantifying this (e.g., packets/sec, Gbps, daily data size) would help in capacity planning and technology selection.
*   **Real-time Alerting Requirements:** What are the latency expectations for critical anomaly alerts? This impacts the design of the alerting pipeline.
*   **Security Requirements for Inter-Service Communication and Data At Rest:** Specific compliance or security posture needs.