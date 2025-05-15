import logging
import time
from datetime import datetime

from src.analysis.statistics_collector import StatisticsCollector
from ..utils.config_manager import ConfigManager
from ..utils.alerter import Alerter
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, ARP, Dot11, Raw # Added Ether

from src.capture.frame_capture import FrameCapture
from src.analysis.protocol_analyzer import ProtocolAnalyzer
from src.analysis.ieee802_11_analyzer import IEEE802_11_Analyzer
from src.analysis.ieee802_3_analyzer import IEEE802_3_Analyzer # Import IEEE802_3_Analyzer
from src.analysis.flow_analyzer import FlowAnalyzer
from src.analysis.anomaly_detector import AnomalyDetector
from src.reporting.report_generator import ReportGenerator
from ..storage.database_handler import DatabaseHandler

logger = logging.getLogger(__name__)

class AnalysisEngine:
    def __init__(self):
        logger.info("Initializing AnalysisEngine...")
        self.config = ConfigManager # Direct access to ConfigManager class methods
        
        self.analyzers = []
        self._load_analyzers() # Dynamically load or register analyzers

        self.frame_capturer = FrameCapture(packet_processing_callback=self._process_packet_from_capture)
        self.stats_collector = StatisticsCollector(self.config)
        self.report_generator = ReportGenerator() # Uses ConfigManager internally
        self.db_handler = DatabaseHandler() # Uses ConfigManager internally
        self.alerter = Alerter(self.config)

        self.all_analyzed_data = [] # Stores results of all processed packets
        self.is_running = False

    def _load_analyzers(self):
        """Carga y configura los analizadores de paquetes."""
        self.analyzers = {
            "protocol": ProtocolAnalyzer(self.config), # Use self.config
            "wifi": IEEE802_11_Analyzer(self.config), # Use self.config
            "ethernet": IEEE802_3_Analyzer(self.config), # Use self.config
            "flow": FlowAnalyzer(self.config), # Use self.config
            "anomaly": AnomalyDetector(self.config) # Use self.config
        }
        # Log the names of the loaded analyzer classes for clarity
        loaded_analyzer_names = [analyzer.__class__.__name__ for analyzer in self.analyzers.values()]
        logger.info(f"Loaded {len(self.analyzers)} analyzers: {loaded_analyzer_names}")

    def _process_packet_from_capture(self, packet):
        """Callback function passed to FrameCapture to process each raw packet."""
        if not self.is_running: # Stop processing if engine run is complete
            return

        current_analysis = {
            'capture_timestamp': datetime.now().isoformat(), # Central timestamp
            'raw_packet_length': len(packet),
            # 'raw_packet_hex': packet.hexraw() # Optional, can be large
        }

        # Perform detailed analysis using the dedicated method
        try:
            detailed_analysis_results = self._determine_packet_type_and_analyze(packet)
            current_analysis.update(detailed_analysis_results)
        except Exception as e:
            logger.error(f"Critical error in _determine_packet_type_and_analyze for packet: {e}", exc_info=True)
            current_analysis['analysis_error'] = f"Core analysis failed: {e}"
            # Ensure essential keys exist for downstream processing even if analysis fails
            current_analysis.setdefault('protocol_details', {"error": "Core analysis failed due to exception"})
            current_analysis.setdefault('ethernet_details', {"error": "Core analysis failed due to exception"}) # if applicable
            current_analysis.setdefault('wifi_details', {"error": "Core analysis failed due to exception"}) # if applicable
            current_analysis.setdefault('flow_analysis', {"error": "Core analysis failed due to exception"})
            current_analysis.setdefault('anomaly_analysis', {"detected_anomalies": [], "error": "Core analysis failed due to exception"})
        
        # Generate a summary line
        # _determine_packet_type_and_analyze ensures 'protocol_details' exists.
        summary_details = current_analysis.get('protocol_details', {})
        
        # Robustly get details for summary, handling cases where summary_details might not be a dict (e.g., if analysis failed badly)
        src_ip = summary_details.get('src_ip', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        src_port = summary_details.get('src_port', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        dst_ip = summary_details.get('dst_ip', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        dst_port = summary_details.get('dst_port', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        protocol = summary_details.get('protocol', 'N/A') if isinstance(summary_details, dict) else 'N/A'
        
        summary_line = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} Proto: {protocol}"
        
        packet_summary_content = {'summary_line': summary_line}
        if isinstance(summary_details, dict): # only spread if it's a dict and not an error string/object
            packet_summary_content.update(summary_details)
        current_analysis['packet_summary'] = packet_summary_content

        # Update statistics
        self.stats_collector.process_packet_analysis(current_analysis)

        # Store for reporting
        self.all_analyzed_data.append(current_analysis)

        # Save to database if enabled
        if self.db_handler.is_enabled:
            self.db_handler.save_analysis(current_analysis)

        # Check for alerts from anomaly detector
        # _determine_packet_type_and_analyze ensures 'anomaly_analysis' exists.
        anomaly_info = current_analysis.get('anomaly_analysis', {})
        if isinstance(anomaly_info, dict) and anomaly_info.get('detected_anomalies'):
            for anomaly_item in anomaly_info['detected_anomalies']:
                if isinstance(anomaly_item, dict): # Ensure anomaly_item is a dict before .get
                    self.alerter.send_alert(anomaly_item.get('message', 'Unknown Anomaly'), 
                                            severity="WARNING", 
                                            details=anomaly_item)
                else:
                    logger.warning(f"Malformed anomaly data item: {anomaly_item}")

    def run_live_capture(self, interface=None, count=0, timeout=None, bpf_filter=None):
        logger.info(f"Starting live capture run: interface={interface}, count={count}, timeout={timeout}, filter='{bpf_filter}'")
        self.is_running = True
        self.stats_collector.reset()
        self.all_analyzed_data = []
        
        if interface == "auto" or interface is None:
            interface = self.config.get('capture.default_interface', None)
            if interface == "auto" or interface is None: # Scapy will try to pick one if None
                 logger.info("No specific interface provided, Scapy will attempt to choose one.")
                 interface = None # Pass None to Scapy
        
        self.frame_capturer.start_capture(interface, count, timeout, bpf_filter)
        # Capture is synchronous and calls _process_packet_from_capture for each packet.
        # When start_capture returns, capture is done or timed out.
        
        self.is_running = False # Mark processing as complete
        logger.info("Live capture run finished.")
        self._finalize_run()

    def run_from_pcap(self, pcap_file_path):
        logger.info(f"Starting PCAP file run: {pcap_file_path}")
        self.is_running = True
        self.stats_collector.reset()
        self.all_analyzed_data = []

        self.frame_capturer.read_pcap(pcap_file_path)
        # read_pcap now calls _process_packet_from_capture for each packet.

        self.is_running = False
        logger.info(f"PCAP file run finished for {pcap_file_path}.")
        self._finalize_run()

    def _finalize_run(self):
        """Common tasks after a capture/pcap run is complete."""
        logger.info("Finalizing run...")
        
        # Generate and print/save reports
        report_format = self.config.get('reporting.default_format', 'console')
        if report_format == 'console':
            self.report_generator.print_to_console(self.all_analyzed_data)
        else:
            self.report_generator.generate_report(self.all_analyzed_data, report_format)

        # Print statistics to console
        final_stats = self.stats_collector.get_statistics()
        logger.info("Final Statistics:")
        for key, value in final_stats.items():
            if isinstance(value, dict):
                logger.info(f"  {key}:")
                for sub_key, sub_value in value.items():
                    logger.info(f"    {sub_key}: {sub_value}")
            else:
                logger.info(f"  {key}: {value}")

        # Close database connection
        if self.db_handler:
            self.db_handler.close()
        
        logger.info("Run finalized.")

    def shutdown(self):
        """Gracefully shut down the engine."""
        logger.info("Shutting down AnalysisEngine...")
        if self.frame_capturer.async_sniffer and self.frame_capturer.async_sniffer.running: # If async was used
            self.frame_capturer.stop_async_capture()
        if self.db_handler:
            self.db_handler.close()
        logger.info("AnalysisEngine shut down.")

    def _determine_packet_type_and_analyze(self, packet):
        """
        Determina el tipo de paquete y lo pasa al analizador apropiado.
        Retorna un diccionario con los resultados del análisis de cada analizador relevante.
        """
        analysis_output = {}

        # Prioritize Ethernet analysis if it's an Ethernet frame
        if packet.haslayer(Ether):
            if "ethernet" in self.analyzers:
                try:
                    # Pass the whole packet to ethernet_analyzer
                    # It will return a dict like {'ethernet_details': {...}}
                    eth_analysis = self.analyzers["ethernet"].analyze_packet(packet, existing_analysis={})
                    analysis_output.update(eth_analysis)
                    
                    # If ethernet_details contains ip_layer_details, use that for protocol_details
                    # Otherwise, fallback to the main protocol analyzer for IP if Ether didn't find IP
                    if 'ethernet_details' in eth_analysis and 'ip_layer_details' in eth_analysis['ethernet_details']:
                        # The ProtocolAnalyzer's output is already structured as 'protocol_details'
                        # So we can directly use the nested ip_layer_details if the structure matches.
                        # Let's assume ip_layer_details from ethernet_analyzer is already the full protocol_details structure.
                        analysis_output['protocol_details'] = eth_analysis['ethernet_details']['ip_layer_details']
                    elif 'ethernet_details' in eth_analysis and 'arp_layer_details' in eth_analysis['ethernet_details']:
                         analysis_output['protocol_details'] = eth_analysis['ethernet_details']['arp_layer_details'] # Or handle ARP differently
                    elif packet.haslayer(IP) and "protocol" in self.analyzers: # Fallback if Ether didn't contain IP
                        proto_analysis = self.analyzers["protocol"].analyze_packet(packet, existing_analysis={})
                        analysis_output.update(proto_analysis)

                except Exception as e:
                    logger.error(f"Error during Ethernet analysis: {e}", exc_info=True)
                    analysis_output['ethernet_details'] = {"error": f"Ethernet analysis failed: {e}"}
            else:
                logger.warning("Ethernet analyzer not loaded, but Ethernet frame detected.")
        
        # If not Ethernet, or if Ethernet analyzer didn't handle IP, try general protocol analyzer for IP
        elif packet.haslayer(IP) and "protocol" in self.analyzers:
            try:
                # The ProtocolAnalyzer returns a dict like {'protocol_details': {...}}
                proto_analysis = self.analyzers["protocol"].analyze_packet(packet, existing_analysis={})
                analysis_output.update(proto_analysis)
            except Exception as e:
                logger.error(f"Error during IP Protocol analysis: {e}", exc_info=True)
                analysis_output['protocol_details'] = {"error": f"IP Protocol analysis failed: {e}"}

        # WiFi analysis (can be independent or complementary)
        if packet.haslayer(Dot11) and "wifi" in self.analyzers:
            try:
                # The IEEE802_11_Analyzer returns a dict like {'wifi_details': {...}}
                wifi_analysis = self.analyzers["wifi"].analyze_packet(packet, existing_analysis={})
                analysis_output.update(wifi_analysis)
            except Exception as e:
                logger.error(f"Error during WiFi analysis: {e}", exc_info=True)
                analysis_output['wifi_details'] = {"error": f"WiFi analysis failed: {e}"}
        else: # Ensure wifi_details error is present if not Dot11
             if 'wifi_details' not in analysis_output : # Avoid overwriting if already set by an error above
                analysis_output['wifi_details'] = {"error": "No es una trama 802.11"}


        # Flow analysis (can use details from previous analyses)
        if "flow" in self.analyzers:
            try:
                # FlowAnalyzer might need access to IP/port details, ensure they are passed if available
                # It returns a dict like {'flow_analysis': {...}}
                flow_input = analysis_output.get('protocol_details', {}) # Pass IP/L4 details to flow analyzer
                if flow_input: # Only run if there are some protocol details
                     flow_res = self.analyzers["flow"].analyze_packet(packet, existing_analysis=flow_input)
                     analysis_output['flow_analysis'] = flow_res.get('flow_details', {}) # Assuming it adds 'flow_details'
                else:
                    analysis_output['flow_analysis'] = {"info": "Skipped, no L3/L4 details for flow."}

            except Exception as e:
                logger.error(f"Error during Flow analysis: {e}", exc_info=True)
                analysis_output['flow_analysis'] = {"error": f"Flow analysis failed: {e}"}
        
        # Anomaly detection (can use details from previous analyses)
        if "anomaly" in self.analyzers and self.config.get('analysis.anomaly_detection.enabled', False):
            try:
                # AnomalyDetector might need access to various details
                # It returns a dict like {'anomaly_analysis': {...}}
                anomaly_input = analysis_output.get('protocol_details', {})
                if anomaly_input:
                    anomaly_res = self.analyzers["anomaly"].analyze_packet(packet, existing_analysis=anomaly_input)
                    analysis_output['anomaly_analysis'] = anomaly_res.get('anomaly_details', {})
                else:
                    analysis_output['anomaly_analysis'] = {"info": "Skipped, no L3/L4 details for anomaly detection."}

            except Exception as e:
                logger.error(f"Error during Anomaly detection: {e}", exc_info=True)
                analysis_output['anomaly_analysis'] = {"error": f"Anomaly detection failed: {e}"}
        else:
            analysis_output['anomaly_analysis'] = {"detected_anomalies": []} # Default if disabled or no input

        # Ensure 'protocol_details' exists, even if empty or error, for consistent report structure
        if 'protocol_details' not in analysis_output:
            analysis_output['protocol_details'] = {"info": "No L3/L4 protocol details extracted."}
            if packet.haslayer(IP): # If it was IP but no analyzer ran or errored
                 analysis_output['protocol_details']['error'] = "IP packet detected but no L3/L4 analysis performed."
            elif not packet.haslayer(Ether) and not packet.haslayer(Dot11): # Truly unknown
                 analysis_output['protocol_details']['error'] = "Packet is not Ethernet, WiFi, or IP."


        return analysis_output

    def _process_packet(self, packet):
        """Processa un único paquete, determinando su tipo y aplicando los análisis correspondientes."""
        if not self.is_running:
            logger.warning("AnalysisEngine is not running. Packet processing skipped.")
            return {"error": "Engine not running"}

        # Primero, intentamos determinar el tipo de paquete y realizar análisis preliminares
        analysis_results = self._determine_packet_type_and_analyze(packet)

        # Aquí podríamos agregar pasos adicionales de procesamiento si es necesario

        return analysis_results
