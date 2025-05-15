import logging
import time
from scapy.all import IP, TCP, UDP, ICMP # Added Scapy imports
from .base_analyzer import BaseAnalyzer
from collections import defaultdict

logger = logging.getLogger(__name__)

class FlowAnalyzer(BaseAnalyzer):
    """
    Analyzes packet flows to derive performance metrics like RTT, jitter (conceptual).
    NOTE: True RTT and jitter calculation is complex and requires tracking TCP sequence numbers,
    acknowledgments, and timestamps accurately across a flow. This is a simplified placeholder.
    """
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.flows = defaultdict(lambda: {"timestamps": [], "packet_count": 0})
        self.rtt_threshold = self.config_manager.get('analysis.performance_metrics.rtt_threshold_ms', 100)
        logger.debug("FlowAnalyzer initialized.")

    def _get_flow_key(self, packet):
        packet_summary_for_log = packet.summary() if hasattr(packet, 'summary') else 'Packet summary N/A'
        logger.debug(f"FlowAnalyzer._get_flow_key: Analyzing packet: {packet_summary_for_log}")

        if packet.haslayer(IP):
            logger.debug("FlowAnalyzer._get_flow_key: IP layer found.")
            ip_layer = packet[IP]
            proto = ip_layer.proto
            # Canonical key: sort IP addresses to treat (src,dst) and (dst,src) as the same flow direction for some metrics
            # However, for RTT and other directional metrics, raw order might be needed.
            # For now, using sorted for general flow identification.
            src_ip, dst_ip = sorted((ip_layer.src, ip_layer.dst))

            if packet.haslayer(TCP):
                logger.debug("FlowAnalyzer._get_flow_key: TCP layer found.")
                tcp_layer = packet[TCP]
                # Sort ports for canonical key
                src_port, dst_port = sorted((tcp_layer.sport, tcp_layer.dport))
                return (src_ip, dst_ip, proto, src_port, dst_port)
            elif packet.haslayer(UDP):
                logger.debug("FlowAnalyzer._get_flow_key: UDP layer found.")
                udp_layer = packet[UDP]
                # Sort ports for canonical key
                src_port, dst_port = sorted((udp_layer.sport, udp_layer.dport))
                return (src_ip, dst_ip, proto, src_port, dst_port)
            # For ICMP or other IP protocols that don't have ports in the same way
            logger.debug(f"FlowAnalyzer._get_flow_key: Non-TCP/UDP IP packet (proto: {proto}). Keying by IP and protocol.")
            return (src_ip, dst_ip, proto)
        else:
            logger.debug("FlowAnalyzer._get_flow_key: IP layer NOT found.")
            return None

    def analyze_packet(self, packet, existing_analysis=None):
        """
        Processes a packet as part of a flow.
        Returns a dictionary of flow metrics for the current packet, safe for JSON.
        The existing_analysis argument is the current state of analysis_output from the engine.
        """
        packet_summary_for_log = packet.summary() if hasattr(packet, 'summary') else 'Packet summary N/A'
        logger.debug(f"FlowAnalyzer.analyze_packet received: {packet_summary_for_log}")

        flow_key = self._get_flow_key(packet)
        logger.debug(f"FlowAnalyzer.analyze_packet flow_key: {flow_key}")
        
        current_packet_flow_metrics = {}

        if flow_key:
            # Store essential, JSON-safe data for internal flow tracking
            packet_time = packet.time if hasattr(packet, 'time') else time.time()
            self.flows[flow_key]["timestamps"].append(packet_time)
            self.flows[flow_key]["packet_count"] = self.flows[flow_key].get("packet_count", 0) + 1
            
            # For the output related to *this specific packet*
            current_packet_flow_metrics['flow_packet_count_so_far'] = self.flows[flow_key]["packet_count"]
            current_packet_flow_metrics['flow_identifier'] = str(flow_key) # Ensure flow_key is JSON serializable

            # Placeholder for more advanced metrics
            # if len(self.flows[flow_key]["timestamps"]) > 1:
            #     inter_packet_gap = packet_time - self.flows[flow_key]["timestamps"][-2]
            #     current_packet_flow_metrics['inter_packet_gap_ms'] = inter_packet_gap * 1000
        
        # Enhanced logging before returning
        logger.debug(f"FlowAnalyzer.analyze_packet PRE-RETURN metrics for packet {packet_summary_for_log}: {current_packet_flow_metrics}")
        return current_packet_flow_metrics

    def get_flow_summary(self):
        """Returns a summary of all tracked flows. This is called at the end of a run."""
        summary = {}
        for key, data in self.flows.items():
            summary[str(key)] = {
                "total_packets_in_flow": data.get("packet_count", 0),
                # Add more derived metrics here, e.g., duration, avg_inter_packet_gap
                "first_packet_time": min(data["timestamps"]) if data["timestamps"] else None,
                "last_packet_time": max(data["timestamps"]) if data["timestamps"] else None,
            }
        return summary
    
    def reset(self):
        """Resets the internal state of the flow analyzer for a new run."""
        self.flows = defaultdict(lambda: {"timestamps": [], "packet_count": 0})
        logger.info("FlowAnalyzer reset.")