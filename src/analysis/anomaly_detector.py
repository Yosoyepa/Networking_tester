import logging
from pcapkit import *
from .base_analyzer import BaseAnalyzer
from collections import Counter

logger = logging.getLogger(__name__)

class AnomalyDetector(BaseAnalyzer):
    """Detects anomalies based on configured rules."""
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.anomaly_rules = self.config_manager.get('analysis.anomaly_detection.rules', [])
        self.is_enabled = self.config_manager.get('analysis.anomaly_detection.enabled', False)
        self.packet_stats = Counter() # Example: count packets per source IP
        logger.debug(f"AnomalyDetector initialized. Enabled: {self.is_enabled}")

    def analyze_packet(self, packet, existing_analysis=None):
        """Analyzes packet for anomalies. Returns its own analysis part."""
        anomalies_found = []
        if not self.is_enabled:
            # Return the specific structure for anomaly analysis, even if empty
            return {'detected_anomalies': []}

        # Example: High traffic source detection
        # Ensure that 'IP' is imported or handled if not available globally
        # For now, assuming 'IP' layer check is appropriate here.
        # from scapy.all import IP # This might be needed at the top of the file if not already there
        try:
            if packet.haslayer('IP'): # A more robust check than just 'IP in packet'
                src_ip = packet['IP'].src
                self.packet_stats[src_ip] += 1

                for rule in self.anomaly_rules:
                    if rule.get('type') == 'high_traffic_source':
                        threshold = rule.get('threshold_packets', 1000)
                        if self.packet_stats[src_ip] > threshold:
                            message = rule.get('alert_message', "High traffic from {source_ip}").format(source_ip=src_ip)
                            anomalies_found.append({"rule_type": rule['type'], "message": message, "source_ip": src_ip, "count": self.packet_stats[src_ip]})
                            logger.warning(f"Anomaly detected: {message}")
        except AttributeError:
            logger.debug("Packet does not have IP layer for anomaly detection, or 'IP' layer not recognized.")
            # This can happen for non-IP packets like ARP, or if Scapy's IP layer isn't named 'IP'
            # or if packet is malformed.

        # Add more rule evaluations here

        # Return only the anomaly-specific results
        return {'detected_anomalies': anomalies_found}

    def get_current_stats(self): # For potential periodic checks by an engine
        return self.packet_stats