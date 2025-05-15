"""
Performance Analyzer using ML for AI Monitoring.

Analyzes network packet features to assess performance aspects like speed.
NOTE: True speed/throughput analysis requires aggregation over time,
      which is a more advanced feature to be added.
      Initially, this focuses on packet-level characteristics relevant to performance.
"""
import pandas as pd
import logging

logger = logging.getLogger(__name__)

class PerformanceMLAnalyzer:
    """
    Analyzes performance-related features from packet data.
    """
    def __init__(self, config_manager=None):
        self.config_manager = config_manager
        logger.info("PerformanceMLAnalyzer initialized.")
    
    def analyze_performance_features(self, features_df):
        """
        Analyzes performance-related features.
        Currently, this is a placeholder for more advanced analysis.
        
        Args:
            features_df (pd.DataFrame): DataFrame with extracted features
            
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
        
        # Add simple categorizations based on frame length if available
        if 'frame_length' in results_df.columns:
            conditions = [
                (results_df['frame_length'] < 100),
                (results_df['frame_length'] >= 100) & (results_df['frame_length'] < 1000),
                (results_df['frame_length'] >= 1000)
            ]
            categories = ['Small Packet', 'Medium Packet', 'Large Packet']
            
            # Using a safer approach for categorization
            results_df['packet_size_category'] = 'Unknown Size'
            for i, condition in enumerate(conditions):
                results_df.loc[condition, 'packet_size_category'] = categories[i]
        
        # Add protocol analysis if available
        if 'ip_protocol' in results_df.columns:
            protocol_notes = []
            for proto in results_df['ip_protocol']:
                if proto == 6:  # TCP
                    protocol_notes.append("TCP (reliable, potential overhead)")
                elif proto == 17:  # UDP
                    protocol_notes.append("UDP (fast, unreliable)")
                elif proto == 1:  # ICMP
                    protocol_notes.append("ICMP (control/error)")
                else:
                    protocol_notes.append("Other protocol")
            results_df['protocol_performance_note'] = protocol_notes
        else:
            results_df['protocol_performance_note'] = 'Protocol information not available'
            
        # Basic statistics for the report
        packet_count = len(results_df)
        size_distribution = {}
        protocol_distribution = {}
        
        if 'packet_size_category' in results_df.columns:
            size_distribution = results_df['packet_size_category'].value_counts().to_dict()
            
        if 'protocol_performance_note' in results_df.columns:
            protocol_distribution = results_df['protocol_performance_note'].value_counts().to_dict()
            
        # Generate summary
        summary_parts = [f"Analyzed {packet_count} packets"]
        if size_distribution:
            summary_parts.append(", ".join(f"{count} {size}" for size, count in size_distribution.items()))
        if protocol_distribution:
            summary_parts.append("Protocol distribution: " + 
                               ", ".join(f"{count} {proto}" for proto, count in protocol_distribution.items()))
            
        summary = ". ".join(summary_parts)
        
        # Generate details
        details = []
        for size, count in size_distribution.items():
            details.append(f"{count} packets categorized as '{size}'")
        for proto, count in protocol_distribution.items():
            details.append(f"{count} packets with {proto}")
            
        return {
            "summary": summary,
            "quality_value": 75.0,  # Arbitrary quality score
            "details": details,
            "dataframe": results_df  # Include the dataframe for reference
        }
    
    def get_description(self):
        """Returns a description of the analyzer"""
        return {
            "name": "Performance Feature Analyzer",
            "procedure": "This module provides initial insights into network performance by analyzing per-packet features. "
                         "It categorizes packets by size and analyzes protocol distribution.",
            "features_used": "'frame_length', 'ip_protocol'.",
            "output": "Packet size categories and protocol performance notes.",
            "quality_value": 0.0,
            "quality_values_description": "Packet Size Category and Protocol Performance Note."
        }
