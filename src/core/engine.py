import logging
import time
from datetime import datetime
from ..utils.config_manager import ConfigManager
from ..utils.alerter import Alerter
from ..capture.frame_capture import FrameCapture
from ..analysis.statistics_collector import StatisticsCollector
from ..analysis.protocol_analyzer import ProtocolAnalyzer # Example analyzer
from ..analysis.ieee802_11_analyzer import IEEE802_11_Analyzer # Example analyzer
from ..analysis.flow_analyzer import FlowAnalyzer # Example analyzer
from ..analysis.anomaly_detector import AnomalyDetector # Example analyzer
from ..reporting.report_generator import ReportGenerator
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
        """Loads and instantiates analyzer classes."""
        # This could be made more dynamic, e.g., by discovering plugins
        # or reading from configuration.
        self.analyzers.append(ProtocolAnalyzer(self.config))
        self.analyzers.append(IEEE802_11_Analyzer(self.config)) # Assuming it's updated
        self.analyzers.append(FlowAnalyzer(self.config))
        self.analyzers.append(AnomalyDetector(self.config))
        logger.info(f"Loaded {len(self.analyzers)} analyzers: {[a.get_name() for a in self.analyzers]}")

    def _process_packet_from_capture(self, packet):
        """Callback function passed to FrameCapture to process each raw packet."""
        if not self.is_running: # Stop processing if engine run is complete
            return

        current_analysis = {
            'capture_timestamp': datetime.now().isoformat(), # Central timestamp
            'raw_packet_length': len(packet),
            # 'raw_packet_hex': packet.hexraw() # Optional, can be large
        }

        # Pass packet through all registered analyzers
        for analyzer in self.analyzers:
            try:
                # Each analyzer enriches the current_analysis dictionary
                analyzer.analyze_packet(packet, current_analysis)
            except Exception as e:
                logger.error(f"Error during analysis with {analyzer.get_name()}: {e}", exc_info=True)
                current_analysis.setdefault(f'{analyzer.get_name()}_error', str(e))
        
        # Generate a summary line (could be a dedicated step or part of an analyzer)
        # For now, let's assume ProtocolAnalyzer might add a summary
        summary_details = current_analysis.get('protocol_details', {})
        summary_line = f"{summary_details.get('src_ip','N/A')}:{summary_details.get('src_port','N/A')} -> " \
                       f"{summary_details.get('dst_ip','N/A')}:{summary_details.get('dst_port','N/A')} " \
                       f"Proto: {summary_details.get('protocol','N/A')}"
        current_analysis['packet_summary'] = {'summary_line': summary_line, **summary_details}


        # Update statistics
        self.stats_collector.process_packet_analysis(current_analysis)

        # Store for reporting
        self.all_analyzed_data.append(current_analysis)

        # Save to database if enabled
        if self.db_handler.is_enabled:
            self.db_handler.save_analysis(current_analysis)

        # Check for alerts from anomaly detector
        anomaly_info = current_analysis.get('anomaly_analysis', {})
        if anomaly_info.get('detected_anomalies'):
            for anomaly in anomaly_info['detected_anomalies']:
                self.alerter.send_alert(anomaly.get('message', 'Unknown Anomaly'), 
                                        severity="WARNING", 
                                        details=anomaly)


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
