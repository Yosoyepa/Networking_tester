import logging
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class StatisticsCollector:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.reset()
        logger.debug("StatisticsCollector initialized.")

    def reset(self):
        self.total_packets = 0
        self.protocol_counts = Counter() # TCP, UDP, ICMP, etc.
        self.ip_source_counts = Counter()
        self.ip_destination_counts = Counter()
        self.port_source_counts = Counter()
        self.port_destination_counts = Counter()
        self.packet_type_counts = Counter() # WiFi, Ethernet, Other
        self.start_time = None
        self.end_time = None
        self.errors = 0
        # Add more specific stats as needed

    def process_packet_analysis(self, analysis_data):
        """
        Updates statistics based on the analyzed packet data.
        analysis_data is the rich dictionary from the analysis engine.
        """
        # Ensure timestamps are datetime objects
        raw_timestamp_from_data = analysis_data.get('capture_timestamp')
        
        current_dt_timestamp = None
        if isinstance(raw_timestamp_from_data, str):
            try:
                current_dt_timestamp = datetime.fromisoformat(raw_timestamp_from_data)
            except ValueError:
                logger.warning(f"Malformed ISO timestamp string '{raw_timestamp_from_data}' in analysis_data. Using current time.")
                current_dt_timestamp = datetime.now()
        elif isinstance(raw_timestamp_from_data, datetime):
            current_dt_timestamp = raw_timestamp_from_data
        else: # None or other unexpected type
            if raw_timestamp_from_data is not None: # Log if it was some other type
                 logger.warning(f"Unexpected type for 'capture_timestamp': {type(raw_timestamp_from_data)}. Using current time.")
            current_dt_timestamp = datetime.now() # Fallback to current time

        if self.start_time is None:
            self.start_time = current_dt_timestamp # Now self.start_time is a datetime object
        
        # Always update end_time with the current packet's timestamp (or current time if not available)
        self.end_time = current_dt_timestamp # Now self.end_time is a datetime object

        self.total_packets += 1
        
        # Track packet type (Ethernet, WiFi, Other)
        packet_summary = analysis_data.get('packet_summary', {})
        packet_type = packet_summary.get('packet_type', 'Unknown')
        self.packet_type_counts[packet_type] += 1
        
        protocol_details = analysis_data.get('protocol_details', {})
        if protocol_details:
            protocol_name = protocol_details.get('protocol', 'OTHER')
            self.protocol_counts[protocol_name] += 1
            
            src_ip = protocol_details.get('src_ip')
            dst_ip = protocol_details.get('dst_ip')
            if src_ip: self.ip_source_counts[src_ip] += 1
            if dst_ip: self.ip_destination_counts[dst_ip] += 1

            src_port = protocol_details.get('src_port')
            dst_port = protocol_details.get('dst_port')
            if src_port: self.port_source_counts[src_port] +=1
            if dst_port: self.port_destination_counts[dst_port] +=1
        
        # Check for errors if analyzers add an error field
        if analysis_data.get('error') or protocol_details.get('error'):
            self.errors += 1

    def get_statistics(self):
        duration_seconds = 0
        if self.start_time and self.end_time:
            # self.start_time and self.end_time are now guaranteed to be datetime objects (or None)
            # So, direct assignment is safe.
            st = self.start_time
            et = self.end_time
            duration = et - st
            duration_seconds = duration.total_seconds()

        packets_per_second = 0
        if duration_seconds > 0 and self.total_packets > 0:
            packets_per_second = round(self.total_packets / duration_seconds, 2)

        return {
            "total_packets": self.total_packets,
            "start_time": self.start_time.isoformat() if self.start_time else None, # This will now work
            "end_time": self.end_time.isoformat() if self.end_time else None,       # This will now work
            "duration_seconds": duration_seconds,
            "packets_per_second": packets_per_second,
            "protocol_distribution": dict(self.protocol_counts),
            "packet_type_distribution": dict(self.packet_type_counts),
            "top_source_ips": dict(self.ip_source_counts.most_common(5)),
            "top_destination_ips": dict(self.ip_destination_counts.most_common(5)),
            "top_source_ports": dict(self.port_source_counts.most_common(5)),
            "top_destination_ports": dict(self.port_destination_counts.most_common(5)),
            "error_count": self.errors,
        }