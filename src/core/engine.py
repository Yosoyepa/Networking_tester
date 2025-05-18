import logging
import time
from datetime import datetime
import os
from pathlib import Path # Added Path
import pandas as pd
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, ARP, Dot11, Raw, rdpcap # Added rdpcap
import json # Added for JSON operations

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
from src.ai_monitoring import QoSMLAnalyzer # Corrected import
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
        self.qos_ml_analyzer = QoSMLAnalyzer(config_manager=self.config) # Pass config_manager
        self.performance_ml_analyzer = PerformanceMLAnalyzer(config_manager=self.config) # Pass config_manager

        # Define model and scaler paths using ConfigManager and project root
        project_root = Path(__file__).resolve().parent.parent.parent
        
        default_model_filename = "ai_anomaly_detector.joblib"
        default_model_rel_path = Path("data") / "models" / default_model_filename
        model_rel_path_str = self.config.get('ai_monitoring.anomaly_detector_model_path', str(default_model_rel_path))
        self.ai_model_path = str(project_root / model_rel_path_str)

        default_scaler_filename = "ai_anomaly_detector_scaler.joblib"
        default_scaler_rel_path = Path("data") / "models" / default_scaler_filename
        scaler_rel_path_str = self.config.get('ai_monitoring.anomaly_detector_scaler_path', str(default_scaler_rel_path))
        self.ai_scaler_path = str(project_root / scaler_rel_path_str)
        
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

    def run_live_capture(self, interface=None, count=0, timeout=None, bpf_filter=None, output_pcap_path=None, cli_report_format=None):
        logger.info(f"Starting live capture run: interface={interface}, count={count}, timeout={timeout}, filter='{bpf_filter}', write_to='{output_pcap_path}'")
        self.is_running = True
        self.stats_collector.reset()
        self.all_analyzed_data = []
        self.live_capture_packets_to_write = []
        self.current_output_pcap_path = output_pcap_path
        self.cli_report_format = cli_report_format # Store for _finalize_run

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
        self._finalize_run(cli_report_format=self.cli_report_format)

    def run_from_pcap(self, pcap_file_path, cli_report_format=None):
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
        self.cli_report_format = cli_report_format # Store for _finalize_run
        self.frame_capturer.read_pcap(pcap_file_path) # This calls _process_and_store_packet internally
        self.is_running = False
        logger.info(f"PCAP file run finished for {pcap_file_path}.")
        self._finalize_run(cli_report_format=self.cli_report_format)

    def _finalize_run(self, ai_results=None, cli_report_format=None):
        """Common tasks after a capture/pcap run is complete."""
        logger.info("Finalizing run...")
        final_stats = self.stats_collector.get_statistics()
        
        report_format_config = cli_report_format if cli_report_format else self.config.get('reporting.default_format', 'console')
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
        if ai_results and not (isinstance(ai_results, dict) and ai_results.get("error")):
            print("AI Analysis results have also been included in the reports.")
        elif ai_results and isinstance(ai_results, dict) and ai_results.get("error"):
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
            "performance_analysis": None,
            "error": None # To store any top-level error during AI processing
        }

        if not self.all_analyzed_data:
            logger.warning("No session data available for AI analysis.")
            return {"error": "No session data to analyze. Please run a capture or load a PCAP first."}

        logger.info(f"Starting AI analysis on {len(self.all_analyzed_data)} processed packets' original data.")
        original_packets = [entry['original_packet'] for entry in self.all_analyzed_data if 'original_packet' in entry and entry['original_packet'] is not None]
        
        if not original_packets:
            logger.warning("No valid original packets found for AI feature extraction.")
            return {"error": "Could not extract features for AI: no raw packet data found in session."}

        logger.info(f"Extracting features from {len(original_packets)} packets for AI...")
        features_df = self.feature_extractor.extract_features_to_dataframe(original_packets)

        if features_df.empty:
            logger.warning("Feature extraction for AI resulted in an empty DataFrame.")
            return {"error": "Feature extraction for AI yielded no data."}

        logger.info(f"AI Feature extraction complete. Shape: {features_df.shape}")

        # 1. AI Security Anomaly Detection
        model_name_sec = self.ai_anomaly_detector.model.__class__.__name__ if self.ai_anomaly_detector.model else 'N/A'
        # Get description from the AIAnomalyDetector if it has a get_description method, else create one.
        # Assuming AIAnomalyDetector might not have get_description(), so creating a basic one.
        sec_desc_dict = {
            "name": "AI Security Anomaly Detector",
            "procedure": f"Uses a pre-trained {model_name_sec} model (or one trained on-the-fly if no pre-trained model is found) to identify network traffic anomalies that could indicate security issues. Anomalies are detected as outliers in the feature space.",
            "features_used": "Various packet features (e.g., lengths, flags, inter-arrival times - depends on feature_extractor).",
            "output": "Identifies packets as normal or anomalous (-1).",
            "quality_metrics": "Quality score (0-100) based on the percentage of non-anomalous packets. Lower scores indicate more anomalies."
        }

        sec_analysis_result = {
            "description": sec_desc_dict, # Store the descriptive dictionary
            "model_name": model_name_sec,
            "status": "Not run",
            "packets_analyzed": 0,
            "anomalies_detected": 0,
            "quality_score": 0.0, # Renamed from quality_value for consistency
            "text_summary": "Security analysis not performed or encountered an issue.", # New field for text summary
            "anomaly_details_sample": [] # Changed from "N/A" to empty list for consistency
        }

        if not self.ai_anomaly_detector.is_trained():
            sec_analysis_result["status"] = "Model not trained. Attempting on-the-fly training."
            sec_analysis_result["text_summary"] = "Security model not trained. Attempting to train on current session data."
            try:
                self.ai_anomaly_detector.train(features_df)
                sec_analysis_result["status"] = "Model temporarily trained on current session data."
                sec_analysis_result["text_summary"] = "Security model was trained on-the-fly using current session data."
            except Exception as e:
                logger.error(f"On-the-fly AI model training failed: {e}", exc_info=True)
                error_msg = f"Error training model on current data: {e}"
                sec_analysis_result["status"] = error_msg
                sec_analysis_result["text_summary"] = f"Security analysis failed during on-the-fly training: {e}"

        if self.ai_anomaly_detector.is_trained():
            try:
                predictions = self.ai_anomaly_detector.predict(features_df)
                anomalies_mask = predictions == -1
                num_anomalies = anomalies_mask.sum()
                total_analyzed = len(features_df)
                quality_score_security = (1 - (num_anomalies / total_analyzed)) * 100 if total_analyzed > 0 else 100.0
                
                summary_txt = f"Security Analysis ({total_analyzed} samples): Detected {num_anomalies} potential anomalies."
                if num_anomalies == 0:
                    summary_txt += " No security anomalies detected based on the AI model."
                else:
                    summary_txt += f" This represents { (num_anomalies/total_analyzed)*100 if total_analyzed > 0 else 0:.2f}% of the analyzed traffic."

                sec_analysis_result.update({
                    "status": "Completed",
                    "packets_analyzed": total_analyzed,
                    "anomalies_detected": int(num_anomalies),
                    "quality_score": float(quality_score_security),
                    "text_summary": summary_txt
                })

                if num_anomalies > 0:
                    # Providing a sample of anomalous features can be very verbose.
                    # Instead, we can list indices or a brief note.
                    # For now, keeping the sample but UI should handle it gracefully.
                    sample_anomalies_df = features_df[anomalies_mask].head()
                    sec_analysis_result["anomaly_details_sample"] = sample_anomalies_df.to_dict(orient='records')
                else:
                    sec_analysis_result["anomaly_details_sample"] = [] # Empty list if no anomalies

            except Exception as e:
                logger.error(f"AI anomaly prediction error: {e}", exc_info=True)
                error_msg = f"Error during prediction: {e}"
                sec_analysis_result["status"] = error_msg
                sec_analysis_result["text_summary"] = f"Security analysis failed during prediction: {e}"
        elif sec_analysis_result["status"] not in ["Model not trained. Attempting on-the-fly training.", "Model temporarily trained on current session data."] and not sec_analysis_result["status"].startswith("Error training") :
             sec_analysis_result["status"] = "Model not trained and on-the-fly training failed or was not attempted."
             sec_analysis_result["text_summary"] = "Security model is not trained. Analysis could not be performed."
        
        ai_results["security_analysis"] = sec_analysis_result

        # 2. AI QoS Analysis
        qos_desc_dict = self.qos_ml_analyzer.get_description() # This should return a dict
        qos_analysis_result = {
            "description": qos_desc_dict,
            "text_summary": "QoS analysis not performed or encountered an issue.",
            "quality_score": 0.0,
            "anomalies_detected": 0,
            # "details_df": None, # The qos_analyzer now returns a summary dict, not the df directly here
            "status": "Not run"
        }
        try:
            # analyze_qos_features returns the augmented DataFrame
            qos_augmented_df = self.qos_ml_analyzer.analyze_qos_features(features_df.copy())
            # generate_summary takes this augmented DataFrame
            qos_summary_data = self.qos_ml_analyzer.generate_summary(qos_augmented_df)
            
            qos_analysis_result.update({
                "text_summary": qos_summary_data.get('text_summary', "No QoS summary provided."),
                "quality_score": float(qos_summary_data.get('quality_score', 0.0)),
                "anomalies_detected": int(qos_summary_data.get('anomalies_detected', 0)),
                # If you need a sample of qos_concerns for the UI, you could extract it from qos_augmented_df
                # For example: qos_concerns_sample = qos_augmented_df[qos_augmented_df['qos_concerns'] != 'None']['qos_concerns'].head().tolist()
                "status": "Completed"
            })
        except Exception as e:
            logger.error(f"AI QoS analysis error: {e}", exc_info=True)
            qos_analysis_result["status"] = f"Error: {e}"
            qos_analysis_result["text_summary"] = f"QoS analysis failed: {e}"
        ai_results["qos_analysis"] = qos_analysis_result

        # 3. AI Performance Analysis
        perf_desc_dict = self.performance_ml_analyzer.get_description() # This should return a dict
        perf_analysis_result = {
            "description": perf_desc_dict,
            "text_summary": "Performance analysis not performed or encountered an issue.",
            "quality_score": 0.0,
            "anomalies_detected": 0,
            # "details_df": None, # The performance_analyzer now returns a dict with summary and df
            "status": "Not run"
        }
        try:
            # analyze_performance_features now returns a dictionary including the summary and the df
            perf_output_dict = self.performance_ml_analyzer.analyze_performance_features(features_df.copy())
            
            perf_analysis_result.update({
                "text_summary": perf_output_dict.get('text_summary', "No Performance summary provided."),
                "quality_score": float(perf_output_dict.get('quality_score', 0.0)),
                "anomalies_detected": int(perf_output_dict.get('anomalies_detected', 0)),
                # If you need a sample for the UI, you could process perf_output_dict['details_df']
                # For example: perf_concerns_sample = perf_output_dict['details_df'][...some condition...].head().to_dict('records')
                "status": "Completed"
            })
        except Exception as e:
            logger.error(f"AI performance analysis error: {e}", exc_info=True)
            perf_analysis_result["status"] = f"Error: {e}"
            perf_analysis_result["text_summary"] = f"Performance analysis failed: {e}"
        ai_results["performance_analysis"] = perf_analysis_result
        
        logger.info("AI analysis on session data completed and results structured.")

        # Save detailed AI results to a dedicated JSON file
        try:
            project_root = Path(__file__).resolve().parent.parent.parent
            ai_reports_dir = project_root / "data" / "reports" / "AI_reports"
            ai_reports_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ai_report_filename = f"ai_analysis_report_{timestamp}.json"
            ai_report_filepath = ai_reports_dir / ai_report_filename
            
            with open(ai_report_filepath, 'w') as f:
                json.dump(ai_results, f, indent=4, default=str) # Use default=str for non-serializable objects like Path
            logger.info(f"Detailed AI analysis report saved to: {ai_report_filepath}")
            print(f"Detailed AI analysis report saved to: {ai_report_filepath}") # Also print to console

        except Exception as e:
            logger.error(f"Failed to save dedicated AI analysis report: {e}", exc_info=True)
            print(f"Error: Failed to save dedicated AI analysis report: {e}")


        if generate_report_after:
            logger.info("Triggering report generation after AI analysis.")
            self._finalize_run(ai_results=ai_results, cli_report_format=self.cli_report_format if hasattr(self, 'cli_report_format') else None)
        
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
            training_successful = self.ai_anomaly_detector.train_model(features_df_normal, self.ai_model_path, self.ai_scaler_path)
            if training_successful:
                logger.info("AI Anomaly Detector trained successfully.")
                print("AI Anomaly Detector trained successfully.")
                print(f"Model saved to {self.ai_model_path}")
                print(f"Scaler saved to {self.ai_scaler_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"AI model training/saving error: {e}", exc_info=True)
            print(f"Error during AI model training or saving: {e}")

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
