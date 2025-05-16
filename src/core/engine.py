import logging
import time
from datetime import datetime
import os
import pandas as pd
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, ARP, Dot11, Raw, rdpcap # Added rdpcap

from src.utils.config_manager import ConfigManager
from src.utils.alerter import Alerter

from src.capture.frame_capture import FrameCapture
from src.analysis.protocol_analyzer import ProtocolAnalyzer
from src.analysis.ieee802_11_analyzer import IEEE802_11_Analyzer
from src.analysis.ieee802_3_analyzer import IEEE802_3_Analyzer
from src.analysis.flow_analyzer import FlowAnalyzer
from src.analysis.rule_based_anomaly_detector import RuleBasedAnomalyDetector # Corrected import
from src.analysis.statistics_collector import StatisticsCollector # Added missing import
from src.reporting.report_generator import ReportGenerator
from src.storage.database_handler import DatabaseHandler

# AI Monitoring Imports
from src.ai_monitoring.feature_extractor import PacketFeatureExtractor
from src.ai_monitoring import AnomalyDetector as AIAnomalyDetector
from src.ai_monitoring import QoSMLAnalyzer
from src.ai_monitoring import PerformanceMLAnalyzer

logger = logging.getLogger(__name__)

class AnalysisEngine:
    def __init__(self):
        logger.info("Initializing AnalysisEngine...")
        self.config = ConfigManager
        
        self.analyzers = {} 
        self._load_analyzers()

        self.live_capture_packets_to_write = []
        self.current_output_pcap_path = None

        self.frame_capturer = FrameCapture(packet_processing_callback=self._process_and_store_packet)
        self.stats_collector = StatisticsCollector(self.config) # Now defined
        self.report_generator = ReportGenerator()
        self.db_handler = DatabaseHandler()
        self.alerter = Alerter(self.config)

        self.all_analyzed_data = []
        self.is_running = False

        # AI Components
        self.feature_extractor = PacketFeatureExtractor()
        # self.ai_anomaly_detector = AIAnomalyDetector() # Deferred initialization or re-initialization in _load_ai_model if needed
        self.qos_ml_analyzer = QoSMLAnalyzer()
        self.performance_ml_analyzer = PerformanceMLAnalyzer()

        # Define model and scaler paths
        _default_model_file_path = os.path.join(os.getcwd(), 'data', 'models', 'ai_anomaly_detector.joblib')
        self.ai_model_path = self.config.get('ai_monitoring.model_save_path', _default_model_file_path)

        model_path_base, model_ext = os.path.splitext(self.ai_model_path)
        self.ai_scaler_path = f"{model_path_base}_scaler{model_ext}"
        
        # Initialize AIAnomalyDetector here, it can be empty and loaded by _load_ai_model
        self.ai_anomaly_detector = AIAnomalyDetector() 

        self._load_ai_model()

    def _load_analyzers(self):
        """Loads and configures packet analyzers."""
        self.analyzers = {
            "protocol": ProtocolAnalyzer(self.config),
            "wifi": IEEE802_11_Analyzer(self.config),
            "ethernet": IEEE802_3_Analyzer(self.config),
            "flow": FlowAnalyzer(self.config),
            "rule_anomaly": RuleBasedAnomalyDetector(self.config)
        }
        loaded_analyzer_names = [analyzer.__class__.__name__ for analyzer in self.analyzers.values()]
        logger.info(f"Loaded {len(self.analyzers)} standard analyzers: {loaded_analyzer_names}")

    def _ensure_model_dir_exists(self):
        model_dir = os.path.dirname(self.ai_model_path)
        if not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)
            logger.info(f"Created directory for AI model: {model_dir}")

    def _load_ai_model(self):
        """Loads the pre-trained AI anomaly detection model if it exists."""
        self._ensure_model_dir_exists() # Ensure directory exists first
        try:
            if os.path.exists(self.ai_model_path) and os.path.getsize(self.ai_model_path) > 0:
                # Pass both model and scaler paths to the load_model method
                self.ai_anomaly_detector.load_model(self.ai_model_path, self.ai_scaler_path)
                logger.info(f"AI Anomaly Detection model and scaler loaded from {self.ai_model_path} and {self.ai_scaler_path}")
            else:
                logger.info(f"No pre-trained AI Anomaly Detection model found at {self.ai_model_path} or model file is empty. Model will need training.")
        except Exception as e:
            logger.error(f"Error loading AI model from {self.ai_model_path}: {e}", exc_info=True)
    
    def _process_and_store_packet(self, packet):
        """Processes a single packet and stores it if PCAP writing is enabled for the current run."""
        if self.current_output_pcap_path:
            self.live_capture_packets_to_write.append(packet)
        
        self._process_packet_core_logic(packet)

    def _process_packet_core_logic(self, packet):
        """The core logic for processing a single packet."""
        if not self.is_running: 
            return

        current_analysis = {
            'capture_timestamp': datetime.now().isoformat(),
            'raw_packet_length': len(packet),
            'original_packet': packet # Store the original Scapy packet
        }

        try:
            detailed_analysis_results = self._determine_packet_type_and_analyze(packet)
            current_analysis.update(detailed_analysis_results)
        except Exception as e:
            logger.error(f"Critical error in _determine_packet_type_and_analyze for packet: {e}", exc_info=True)
            current_analysis['analysis_error'] = f"Core analysis failed: {e}"
            current_analysis.setdefault('protocol_details', {"error": "Core analysis failed"})
            current_analysis.setdefault('ethernet_details', {"error": "Core analysis failed"})
            current_analysis.setdefault('wifi_details', {"error": "Core analysis failed"})
            current_analysis.setdefault('flow_analysis', {"error": "Core analysis failed"})
            current_analysis.setdefault('anomaly_analysis', {'detected_anomalies': [], "error": "Rule-based anomaly detection failed"})
        
        summary_details = current_analysis.get('protocol_details', {})
        
        src_ip = summary_details.get('src_ip', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        src_port = summary_details.get('src_port', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        dst_ip = summary_details.get('dst_ip', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        dst_port = summary_details.get('dst_port', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        protocol = summary_details.get('protocol', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        
        # Add a flag to identify packet type (WiFi/Ethernet/Other)
        packet_type = "WiFi" if packet.haslayer(Dot11) else "Ethernet" if packet.haslayer(Ether) else "Other"
        
        summary_line = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} Proto: {protocol} Type: {packet_type}"
        
        current_analysis['packet_summary'] = {
            'summary_line': summary_line, 
            'packet_type': packet_type,
            **(summary_details if isinstance(summary_details, dict) else {})
        }

        self.stats_collector.process_packet_analysis(current_analysis)
        self.all_analyzed_data.append(current_analysis)

        if self.db_handler.is_enabled:
            self.db_handler.save_analysis(current_analysis)

        anomaly_info = current_analysis.get('anomaly_analysis', {})
        if isinstance(anomaly_info, dict) and anomaly_info.get('detected_anomalies'):
            for anomaly_item in anomaly_info['detected_anomalies']:
                if isinstance(anomaly_item, dict):
                    self.alerter.send_alert(anomaly_item.get('message', 'Unknown Rule-Based Anomaly'), 
                                            severity="WARNING", details=anomaly_item)
                else:
                    logger.warning(f"Malformed rule-based anomaly data item: {anomaly_item}")

    def _determine_packet_type_and_analyze(self, packet):
        """Determines packet type and runs relevant standard analyzers."""
        analysis_results = {}
        analysis_results['protocol_details'] = self.analyzers["protocol"].analyze_packet(packet)

        # First check for explicit WiFi (Dot11) packets
        if packet.haslayer(Dot11):
            analysis_results['wifi_details'] = self.analyzers["wifi"].analyze_packet(packet, analysis_results)
            # Still process ethernet if it's encapsulated
            if packet.haslayer(Ether):
                analysis_results['ethernet_details'] = self.analyzers["ethernet"].analyze_packet(packet, analysis_results)
            else:
                analysis_results.setdefault('ethernet_details', {"info": "Not Ethernet"})
        elif packet.haslayer(Ether):
            # Process as Ethernet first
            analysis_results['ethernet_details'] = self.analyzers["ethernet"].analyze_packet(packet, analysis_results)
            # Then try to identify as WiFi through inference
            wifi_analysis = self.analyzers["wifi"].analyze_packet(packet, analysis_results)
            # Check if it was successfully identified as WiFi
            if 'wifi_details' in wifi_analysis and 'error' not in wifi_analysis['wifi_details']:
                analysis_results['wifi_details'] = wifi_analysis['wifi_details']
            else:
                analysis_results.setdefault('wifi_details', {"info": "Not Wi-Fi"})
        else:
            analysis_results.setdefault('ethernet_details', {"info": "Not Ethernet"})
            analysis_results.setdefault('wifi_details', {"info": "Not Wi-Fi"})
            
        analysis_results['flow_analysis'] = self.analyzers["flow"].analyze_packet(packet, analysis_results)
        analysis_results['anomaly_analysis'] = self.analyzers["rule_anomaly"].analyze_packet(packet, analysis_results)
        return analysis_results

    def run_live_capture(self, interface=None, count=0, timeout=None, bpf_filter=None, output_pcap_path=None):
        logger.info(f"Starting live capture run: interface={interface}, count={count}, timeout={timeout}, filter='{bpf_filter}', write_to='{output_pcap_path}'")
        self.is_running = True
        self.stats_collector.reset()
        self.all_analyzed_data = []
        self.live_capture_packets_to_write = []
        self.current_output_pcap_path = output_pcap_path

        if interface == "auto" or interface is None:
            interface = self.config.get('capture.default_interface', None)
            if interface == "auto" or interface is None:
                 logger.info("No specific interface provided, Scapy will attempt to choose one.")
                 interface = None
        
        self.frame_capturer.start_capture(interface, count, timeout, bpf_filter)
        self.is_running = False
        
        if self.current_output_pcap_path and self.live_capture_packets_to_write:
            logger.info(f"Writing {len(self.live_capture_packets_to_write)} captured packets to {self.current_output_pcap_path}")
            self.frame_capturer.write_pcap(self.live_capture_packets_to_write, self.current_output_pcap_path)
        elif self.current_output_pcap_path:
             logger.warning(f"No packets were captured. PCAP file '{self.current_output_pcap_path}' will not be written.")
        self.current_output_pcap_path = None
        logger.info("Live capture run finished.")
        self._finalize_run()

    def run_from_pcap(self, pcap_file_path):
        logger.info(f"Starting PCAP file run: {pcap_file_path}")
        if not os.path.exists(pcap_file_path):
            logger.error(f"PCAP file not found: {pcap_file_path}")
            print(f"Error: PCAP file '{pcap_file_path}' not found.")
            return
        self.is_running = True
        self.stats_collector.reset()
        self.all_analyzed_data = []
        self.live_capture_packets_to_write = [] 
        self.current_output_pcap_path = None 
        self.frame_capturer.read_pcap(pcap_file_path) # This calls _process_and_store_packet internally
        self.is_running = False
        logger.info(f"PCAP file run finished for {pcap_file_path}.")
        self._finalize_run()

    def _finalize_run(self, ai_results=None): # Added ai_results parameter
        """Common tasks after a capture/pcap run is complete."""
        logger.info("Finalizing run...")
        final_stats = self.stats_collector.get_statistics()
        report_format_config = self.config.get('reporting.default_format', 'console')
        report_formats = report_format_config if isinstance(report_format_config, list) else [report_format_config]

        for report_format in report_formats:
            if report_format == 'console':
                # Pass stats and ai_results to print_to_console
                self.report_generator.print_to_console(self.all_analyzed_data, final_stats, ai_results=ai_results)
            else:
                # Pass stats and ai_results to generate_report
                self.report_generator.generate_report(self.all_analyzed_data, report_format, final_stats, ai_results=ai_results)

        logger.info("Final Statistics (also included in reports):")
        for key, value in final_stats.items():
            logger.info(f"  {key}: {value}" if not isinstance(value, dict) else f"  {key}:")
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    logger.info(f"    {sub_key}: {sub_value}")
        print("\nRun finalized. Reports generated and stats logged.")
        if ai_results and not ai_results.get("error"):
            print("AI Analysis results have also been included in the reports.")
        elif ai_results and ai_results.get("error"):
            print(f"AI Analysis was attempted but resulted in an error: {ai_results.get('error')}")
        print(f"Total packets processed: {final_stats.get('total_packets_processed', 0)}")

    def run_ai_analysis_on_session_data(self, generate_report_after=False):
        """Runs AI-powered analysis on the currently loaded session data.
        Returns a dictionary with structured AI analysis results.
        If generate_report_after is True, it will also trigger report generation.
        """
        ai_results = {
            "security_analysis": None,
            "qos_analysis": None,
            "performance_analysis": None
        }

        if not self.all_analyzed_data:
            logger.warning("No session data available for AI analysis.")
            # print("No session data to analyze. Please run a capture or load a PCAP first.")
            return {"error": "No session data to analyze. Please run a capture or load a PCAP first."}

        logger.info(f"Starting AI analysis on {len(self.all_analyzed_data)} processed packets' original data.")
        original_packets = [entry['original_packet'] for entry in self.all_analyzed_data if 'original_packet' in entry and entry['original_packet'] is not None]
        
        if not original_packets:
            logger.warning("No valid original packets found for AI feature extraction.")
            # print("Could not extract features for AI: no raw packet data found in session.")
            return {"error": "Could not extract features for AI: no raw packet data found in session."}

        logger.info(f"Extracting features from {len(original_packets)} packets for AI...")
        features_df = self.feature_extractor.extract_features_to_dataframe(original_packets)

        if features_df.empty:
            logger.warning("Feature extraction for AI resulted in an empty DataFrame.")
            # print("Feature extraction for AI yielded no data.")
            return {"error": "Feature extraction for AI yielded no data."}

        logger.info(f"AI Feature extraction complete. Shape: {features_df.shape}")
        # print(f"\\n--- AI Analysis Results ---") # Moved to menu_handler

        # 1. AI Security Anomaly Detection
        # print("\\n[AI Security Anomaly Detection]") # Moved to menu_handler
        model_name_sec = self.ai_anomaly_detector.model.__class__.__name__ if self.ai_anomaly_detector.model else 'N/A'
        sec_desc = f"Uses an {model_name_sec} model to identify outliers."
        # print(f"Description: {sec_desc}") # Moved to menu_handler
        
        sec_analysis_result = {
            "description": sec_desc,
            "model_name": model_name_sec,
            "status": "Not run",
            "packets_analyzed": 0,
            "anomalies_detected": 0,
            "quality_value": 0.0,
            "anomaly_details_sample": "N/A"
        }

        if not self.ai_anomaly_detector.is_trained():
            # print("AI Anomaly Detector is not trained. Training on current data (assumed normal)...") # Moved
            # print("For production, train with 'Train AI Model' option using clean normal traffic.") # Moved
            sec_analysis_result["status"] = "Model not trained. Attempting on-the-fly training."
            try:
                self.ai_anomaly_detector.train(features_df)
                # print(f"AI Detector temporarily trained on current session data.") # Moved
                sec_analysis_result["status"] = "Model temporarily trained on current session data."
            except Exception as e:
                logger.error(f"On-the-fly AI model training failed: {e}", exc_info=True)
                # print(f"Error training AI model on current data: {e}. Skipping AI anomaly detection.") # Moved
                sec_analysis_result["status"] = f"Error training model on current data: {e}"

        if self.ai_anomaly_detector.is_trained():
            try:
                predictions = self.ai_anomaly_detector.predict(features_df)
                anomalies_mask = predictions == -1
                num_anomalies = anomalies_mask.sum()
                total_analyzed = len(features_df)
                quality_value_security = (1 - (num_anomalies / total_analyzed)) * 100 if total_analyzed > 0 else 100.0
                
                sec_analysis_result.update({
                    "status": "Completed",
                    "packets_analyzed": total_analyzed,
                    "anomalies_detected": int(num_anomalies), # Ensure it's a Python int
                    "quality_value": float(quality_value_security), # Ensure it's a Python float
                })
                # print(f"Packets analyzed by AI: {total_analyzed}") # Moved
                # print(f"Potential anomalies by AI: {num_anomalies}") # Moved
                # print(f"AI Security Quality Value: {quality_value_security:.2f}%") # Moved

                if num_anomalies > 0:
                    # print(f"Details of {min(num_anomalies, 5)} AI anomalies (features):") # Moved
                    sample_anomalies_df = features_df[anomalies_mask].head()
                    # Convert DataFrame to a more serializable format if needed for reports (e.g., list of dicts or string)
                    sec_analysis_result["anomaly_details_sample"] = sample_anomalies_df.to_dict(orient='records')
                    # print(features_df[anomalies_mask].head().to_string()) # Moved
            except Exception as e:
                logger.error(f"AI anomaly prediction error: {e}", exc_info=True)
                # print(f"Error during AI anomaly prediction: {e}") # Moved
                sec_analysis_result["status"] = f"Error during prediction: {e}"
        else:
            # print("AI Anomaly Detector not trained. Skipping AI anomaly detection.") # Moved
             if sec_analysis_result["status"] not in ["Model not trained. Attempting on-the-fly training.", "Model temporarily trained on current session data."]:
                sec_analysis_result["status"] = "Model not trained and on-the-fly training failed or was not attempted."
        
        ai_results["security_analysis"] = sec_analysis_result

        # 2. AI QoS Analysis
        # print("\\n[AI QoS Analysis]") # Moved
        qos_desc = self.qos_ml_analyzer.get_description()
        # print(f"Description: {qos_desc}") # Moved
        qos_analysis_result = {
            "description": qos_desc,
            "summary": "N/A",
            "quality_value": 0.0,
            "details_sample": [],
            "status": "Not run"
        }
        try:
            qos_raw_results = self.qos_ml_analyzer.analyze_qos_features(features_df.copy())
            if isinstance(qos_raw_results, dict):
                qos_analysis_result.update({
                    "summary": qos_raw_results.get('summary', "No QoS summary."),
                    "quality_value": float(qos_raw_results.get('quality_value', 0.0)),
                    "details_sample": qos_raw_results.get('details', [])[:5], # Take first 5
                    "status": "Completed"
                })
                # print(qos_analysis_result["summary"]) # Moved
                # if 'quality_value' in qos_raw_results: print(f"AI QoS Quality Value: {qos_analysis_result['quality_value']:.2f}%") # Moved
                # if qos_analysis_result['details_sample']: # Moved
                #     print("AI QoS Details (sample):") # Moved
                #     for detail in qos_analysis_result['details_sample']: print(f"  - {detail}") # Moved
            else:
                qos_analysis_result["summary"] = str(qos_raw_results)
                qos_analysis_result["status"] = "Completed (raw output)"
                # print(str(qos_raw_results)) # Moved
        except Exception as e:
            logger.error(f"AI QoS analysis error: {e}", exc_info=True)
            # print(f"Error in AI QoS analysis: {e}") # Moved
            qos_analysis_result["status"] = f"Error: {e}"
        ai_results["qos_analysis"] = qos_analysis_result

        # 3. AI Performance Analysis
        # print("\\n[AI Performance Analysis]") # Moved
        perf_desc = self.performance_ml_analyzer.get_description()
        # print(f"Description: {perf_desc}") # Moved
        perf_analysis_result = {
            "description": perf_desc,
            "summary": "N/A",
            "quality_value": 0.0,
            "details_sample": [],
            "status": "Not run"
        }
        try:
            perf_raw_results = self.performance_ml_analyzer.analyze_performance_features(features_df.copy())
            if isinstance(perf_raw_results, dict):
                perf_analysis_result.update({
                    "summary": perf_raw_results.get('summary', "No Performance summary."),
                    "quality_value": float(perf_raw_results.get('quality_value', 0.0)),
                    "details_sample": perf_raw_results.get('details', [])[:5], # Take first 5
                    "status": "Completed"
                })
                # print(perf_analysis_result["summary"]) # Moved
                # if 'quality_value' in perf_raw_results: print(f"AI Performance Quality Value: {perf_analysis_result['quality_value']:.2f}%") # Moved
                # if perf_analysis_result['details_sample']: # Moved
                #     print("AI Performance Details (sample):") # Moved
                #     for detail in perf_analysis_result['details_sample']: print(f"  - {detail}") # Moved
            else:
                perf_analysis_result["summary"] = str(perf_raw_results)
                perf_analysis_result["status"] = "Completed (raw output)"
                # print(str(perf_raw_results)) # Moved
        except Exception as e:
            logger.error(f"AI performance analysis error: {e}", exc_info=True)
            # print(f"Error in AI performance analysis: {e}") # Moved
            perf_analysis_result["status"] = f"Error: {e}"
        ai_results["performance_analysis"] = perf_analysis_result
        
        logger.info("AI analysis on session data completed and results structured.")
        # print("\\n--- End of AI Analysis Results ---") # Moved to menu_handler or console formatter

        if generate_report_after:
            logger.info("Triggering report generation after AI analysis.")
            # Call _finalize_run with ai_results to include them in the standard reports
            self._finalize_run(ai_results=ai_results)
        
        return ai_results

    def _read_packets_for_training(self, pcap_filepath):
        """Helper to read packets directly from a PCAP file for training purposes."""
        try:
            # Check if FrameCapture has a direct method (preferred)
            if hasattr(self.frame_capturer, 'read_packets_from_pcap'):
                return self.frame_capturer.read_packets_from_pcap(pcap_filepath)
            else: # Fallback to using scapy.rdpcap directly
                logger.info(f"Reading packets directly using rdpcap from {pcap_filepath} for training.")
                return rdpcap(pcap_filepath)
        except Exception as e:
            logger.error(f"Failed to read packets from {pcap_filepath} using any method: {e}", exc_info=True)
            print(f"Error: Could not read packets from {pcap_filepath} for training. {e}")
            return []

    def train_ai_anomaly_model(self, pcap_filepath_normal_traffic=None):
        """Trains the AI anomaly detection model."""
        logger.info("Starting AI anomaly model training process...")
        print("\nStarting AI anomaly model training...")
        features_df_normal = pd.DataFrame()
        normal_packets = []

        if pcap_filepath_normal_traffic:
            if not os.path.exists(pcap_filepath_normal_traffic):
                logger.error(f"PCAP for training not found: {pcap_filepath_normal_traffic}")
                print(f"Error: PCAP file for training not found: {pcap_filepath_normal_traffic}")
                return False
            print(f"Loading normal traffic from PCAP: {pcap_filepath_normal_traffic}...")
            normal_packets = self._read_packets_for_training(pcap_filepath_normal_traffic)
            if not normal_packets:
                 # Error already printed by _read_packets_for_training
                if not self.all_analyzed_data: return False # Fail if no other data source
        
        if not normal_packets and self.all_analyzed_data:
            logger.info("Using current session data (assumed normal) for training.")
            print("Attempting to use current session data for training (assumed normal)...")
            normal_packets = [entry['original_packet'] for entry in self.all_analyzed_data if 'original_packet' in entry and entry['original_packet'] is not None]
            if not normal_packets:
                logger.warning("No valid original packets in session data for training.")
                print("No packet data in current session to use for training.")
                return False
        elif not normal_packets:
             logger.warning("No data for training (no PCAP provided/failed, no session data).")
             print("No data for training. Load/run capture or provide PCAP for training.")
             return False

        if normal_packets:
            logger.info(f"Extracting features from {len(normal_packets)} packets for training.")
            features_df_normal = self.feature_extractor.extract_features_to_dataframe(normal_packets)
        
        if features_df_normal.empty:
            logger.warning("Feature extraction for training yielded no data.")
            print("Could not extract features from provided data for training.")
            return False
        
        print(f"Training AI Anomaly Detector with {len(features_df_normal)} data points...")
        try:
            # Ensure model directory exists before training
            self._ensure_model_dir_exists()
            # Pass both model_save_path and scaler_save_path to train_model
            self.ai_anomaly_detector.train_model(features_df_normal, self.ai_model_path, self.ai_scaler_path)
            
            logger.info("AI Anomaly Detector trained successfully.")
            print("AI Anomaly Detector trained successfully.")
            print(f"Model saved to {self.ai_model_path}")
            print(f"Scaler saved to {self.ai_scaler_path}")
            return True
        except Exception as e:
            logger.error(f"AI model training/saving error: {e}", exc_info=True)
            print(f"Error during AI model training or saving: {e}")
            return False

    def shutdown(self):
        """Gracefully shuts down the analysis engine."""
        logger.info("Shutting down Analysis Engine...")
        # Perform any necessary cleanup here, e.g., close resources, save state
        if hasattr(self, 'packet_capturer') and self.packet_capturer and hasattr(self.packet_capturer, 'stop_capture') and self.packet_capturer.is_capturing():
            logger.info("Stopping active packet capture...")
            self.packet_capturer.stop_capture()
            # Optionally, wait for the capture thread to finish if it's running in a separate thread

        # If there are other resources like database connections, close them here
        # For example:
        # if self.db_connection:
        #     self.db_connection.close()

        logger.info("Analysis Engine shut down successfully.")
