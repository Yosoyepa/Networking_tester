"""
Performance Analyzer using ML for AI Monitoring.

Analyzes network packet features to assess performance aspects like speed.
NOTE: True speed/throughput analysis requires aggregation over time,
      which is a more advanced feature to be added.
      Initially, this focuses on packet-level characteristics relevant to performance.
"""
import pandas as pd
import logging
# from sklearn.preprocessing import StandardScaler
# Future: from sklearn.linear_model import LinearRegression # For predicting throughput based on features

logger = logging.getLogger(__name__)

class PerformanceMLAnalyzer:
    """
    Analyzes performance-related features from packet data.
    """
    def __init__(self, config_manager=None):
        self.config_manager = config_manager
        logger.info("PerformanceMLAnalyzer initialized.")
        # In the future, load/initialize ML models here

    def analyze_performance_features(self, features_df: pd.DataFrame) -> dict:
        """
        Analyzes performance-related features.
        Currently, this is a placeholder for more advanced analysis.
        It can add interpretations based on packet sizes or protocol types.

        Args:
            features_df (pd.DataFrame): DataFrame with extracted features,
                                        must include 'frame_length', 'ip_protocol'.

        Returns:
            dict: Results dictionary with summary, quality_value, and details
        """
        if features_df.empty:
            logger.warning("Performance analysis input is empty.")
            return {
                "summary": "No data to analyze",
                "quality_value": 0.0,
                "details": []
            }

        results_df = features_df.copy()

        # Basic performance indicators based on packet size
        if 'frame_length' in results_df.columns:
            conditions = [
                (results_df['frame_length'] < 100),
                (results_df['frame_length'] >= 100) & (results_df['frame_length'] < 1000),
                (results_df['frame_length'] >= 1000)
            ]
            categories = ['Small Packet', 'Medium Packet', 'Large Packet']
            results_df['packet_size_category'] = pd.Series(
                pd.NA, dtype=pd.StringDtype()
            ).fillna(pd.NA) # Initialize with NA
            
            # Using loc for assignment:
            results_df.loc[conditions[0], 'packet_size_category'] = categories[0]
            results_df.loc[conditions[1], 'packet_size_category'] = categories[1]
            results_df.loc[conditions[2], 'packet_size_category'] = categories[2]
            results_df['packet_size_category'] = results_df['packet_size_category'].fillna('Unknown Size')

        # Potential performance implications of protocols
        if 'ip_protocol' in results_df.columns:
            # Example: TCP (6) often for bulk, UDP (17) for real-time/small
            # This is a very rough heuristic.
            protocol_perf_notes = []
            for proto in results_df['ip_protocol']:
                if proto == 6: # TCP
                    protocol_perf_notes.append("TCP (reliable, potential overhead)")
                elif proto == 17: # UDP
                    protocol_perf_notes.append("UDP (fast, unreliable, good for streaming/VoIP)")
                elif proto == 1: # ICMP
                    protocol_perf_notes.append("ICMP (control/error, not data intensive)")
                else:
                    protocol_perf_notes.append("Other protocol")
            results_df['protocol_performance_note'] = protocol_perf_notes
        else:
            results_df['protocol_performance_note'] = 'N/A (No IP Protocol feature)'

        # Placeholder for throughput/latency estimation (requires flow analysis)
        results_df['estimated_throughput_impact'] = "Low (per-packet analysis only)"
        results_df['estimated_latency_impact'] = "Unknown (per-packet analysis only)"

        logger.info(f"Performed basic performance feature analysis on {len(results_df)} samples.")
        
        # Generate result summary and performance score
        packet_size_counts = results_df['packet_size_category'].value_counts().to_dict() if 'packet_size_category' in results_df else {}
        protocol_counts = results_df['protocol_performance_note'].value_counts().to_dict() if 'protocol_performance_note' in results_df else {}
        
        # Calculate a basic quality score - this is just a placeholder
        # In a real implementation, this would be based on meaningful metrics
        quality_value = 75.0  # Default moderate score
        
        # Format a descriptive summary
        summary = f"Analyzed {len(results_df)} packets: "
        summary += ", ".join([f"{count} {size}" for size, count in packet_size_counts.items()])
        summary += ". Protocol distribution: "
        summary += ", ".join([f"{count} {proto}" for proto, count in protocol_counts.items()])
        
        # Create details list for report
        details = []
        for size, count in packet_size_counts.items():
            details.append(f"{count} packets categorized as '{size}'")
        for proto, count in protocol_counts.items():
            details.append(f"{count} packets with {proto}")
        
        # Add packet size distribution insight
        if 'packet_size_category' in results_df:
            small_pct = (results_df['packet_size_category'] == 'Small Packet').mean() * 100
            large_pct = (results_df['packet_size_category'] == 'Large Packet').mean() * 100
            if large_pct > 50:
                details.append(f"High proportion of large packets ({large_pct:.1f}%) may indicate bulk data transfer")
            if small_pct > 50:
                details.append(f"High proportion of small packets ({small_pct:.1f}%) may indicate interactive traffic or control messages")
        
        return {
            "summary": summary,
            "quality_value": quality_value,
            "details": details,
            "dataframe": results_df  # Include the dataframe for engine.py to use if needed
        }

    def get_description(self) -> dict:
        """
        Returns a description of the performance analysis procedure.
        """
        return {
            "name": "Performance Feature Analyzer",
            "procedure": "This module provides initial insights into network performance by analyzing per-packet features. "
                         "It categorizes packets by size (Small, Medium, Large) and notes general performance characteristics "
                         "of common protocols (TCP, UDP, ICMP). True performance metrics like throughput (speed) and latency "
                         "require analysis of packet sequences over time (flow analysis), which is planned for future versions. "
                         "Current analysis is heuristic.",
            "features_used": "'frame_length', 'ip_protocol'.",
            "output": "Augmented data with packet size categories and general protocol performance notes. Placeholders for future throughput/latency impact estimations.",
            "quality_value": 0.0,  # Adding a numeric quality value for consistency with other analyzers
            "quality_values_description": "Packet Size Category (e.g., 'Small Packet', 'Large Packet'), Protocol Performance Note (e.g., 'TCP (reliable, potential overhead)'). Actual speed values (Mbps/Gbps) are not yet calculated at this stage."
        }

# Example Usage (for testing)
if __name__ == '__main__':
    data = {
        'frame_length': [60, 700, 1480, 200],
        'ip_protocol': [6, 17, 6, 1] # TCP, UDP, TCP, ICMP
    }
    sample_df = pd.DataFrame(data)
    
    perf_analyzer = PerformanceMLAnalyzer()
    print(perf_analyzer.get_description())
    
    results = perf_analyzer.analyze_performance_features(sample_df)
    print("\nPerformance Analysis Results:")
    print(f"Summary: {results['summary']}")
    print(f"Quality Value: {results['quality_value']}")
    print("Details:")
    for detail in results['details']:
        print(f"  - {detail}")
    print("\nData Sample:")
    print(results['dataframe'][['frame_length', 'ip_protocol', 'packet_size_category', 'protocol_performance_note']].head())

