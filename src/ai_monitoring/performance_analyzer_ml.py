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
from src.utils.config_manager import ConfigManager # Ensure ConfigManager is imported

logger = logging.getLogger(__name__)

class PerformanceMLAnalyzer:
    """
    Analyzes performance-related features from packet data.
    """
    def __init__(self, config_manager=None): # config_manager instance is still accepted
        self.config_manager = config_manager # And stored, in case other methods need it
        self.performance_rules = {}
        try:
            # Use the static get method from ConfigManager class
            # Corrected path: 'ai_monitoring.performance_rules'
            loaded_rules = ConfigManager.get('ai_monitoring.performance_rules', {})
            if isinstance(loaded_rules, dict):
                self.performance_rules = loaded_rules
                logger.info(f"Loaded performance rules: {self.performance_rules}")
            else:
                logger.warning(f"Performance rules loaded are not a dict: {loaded_rules}. Using empty default.")
                self.performance_rules = {}
        except Exception as e:
            logger.error(f"Error loading performance rules using ConfigManager.get: {e}")
            self.performance_rules = {} # Ensure it's a dict on error

        # Define default fallbacks for essential rules
        default_packet_sizes = {'small_threshold': 100, 'medium_threshold': 1000}
        self.performance_rules['packet_size_categories'] = self.performance_rules.get('packet_size_categories', default_packet_sizes)
        self.performance_rules['packet_size_categories']['small_threshold'] = self.performance_rules['packet_size_categories'].get('small_threshold', default_packet_sizes['small_threshold'])
        self.performance_rules['packet_size_categories']['medium_threshold'] = self.performance_rules['packet_size_categories'].get('medium_threshold', default_packet_sizes['medium_threshold'])
        
        default_protocol_insights = {'enabled': True}
        self.performance_rules['protocol_insights'] = self.performance_rules.get('protocol_insights', default_protocol_insights)
        self.performance_rules['protocol_insights']['enabled'] = self.performance_rules['protocol_insights'].get('enabled', default_protocol_insights['enabled'])

        default_small_packet_concern = {'enabled': True, 'threshold_percentage': 60, 'minimum_sample_size': 50}
        self.performance_rules['small_packet_percentage_concern'] = self.performance_rules.get('small_packet_percentage_concern', default_small_packet_concern)
        for key, val in default_small_packet_concern.items():
            self.performance_rules['small_packet_percentage_concern'][key] = self.performance_rules['small_packet_percentage_concern'].get(key, val)

        logger.info("PerformanceMLAnalyzer initialized.")

    def analyze_performance_features(self, features_df: pd.DataFrame) -> dict:
        """
        Analyzes performance-related features using configurable rules.

        Args:
            features_df (pd.DataFrame): DataFrame with extracted features.

        Returns:
            dict: A dictionary containing:
                  'text_summary' (str): A human-readable summary string.
                  'quality_score' (float): A numeric score (0-100) representing overall performance assessment.
                  'anomalies_detected' (int): Count of detected performance concerns/anomalies.
                  'details_df' (pd.DataFrame): The input DataFrame augmented with analysis columns.
        """
        if features_df.empty:
            logger.warning("Performance analysis input is empty.")
            return {
                "text_summary": "No performance data to analyze.",
                "quality_score": 0.0,
                "anomalies_detected": 0,
                "details_df": pd.DataFrame() # Return empty DataFrame
            }

        results_df = features_df.copy()
        total_samples = len(results_df)
        concerns_found = [] # List to store descriptions of concerns
        anomalies_count = 0

        # Packet Size Categorization (configurable)
        if 'frame_length' in results_df.columns:
            size_config = self.performance_rules.get('packet_size_categories', {})
            small_thresh = size_config.get('small_threshold', 100)
            medium_thresh = size_config.get('medium_threshold', 1000)

            conditions = [
                (results_df['frame_length'] <= small_thresh),
                (results_df['frame_length'] > small_thresh) & (results_df['frame_length'] <= medium_thresh),
                (results_df['frame_length'] > medium_thresh)
            ]
            categories = ['Small Packet', 'Medium Packet', 'Large Packet']
            results_df['packet_size_category'] = pd.NA
            results_df['packet_size_category'] = pd.Series(dtype=pd.StringDtype()) # Initialize with StringDtype

            for cond, cat in zip(conditions, categories):
                results_df.loc[cond, 'packet_size_category'] = cat
            results_df['packet_size_category'] = results_df['packet_size_category'].fillna('Unknown Size')
        else:
            results_df['packet_size_category'] = 'N/A (No frame_length feature)'

        # Protocol Performance Notes (configurable)
        if self.performance_rules.get('protocol_insights', {}).get('enabled', False) and \
           'ip_protocol' in results_df.columns:
            protocol_notes = []
            for proto in results_df['ip_protocol']:
                if proto == 6: protocol_notes.append("TCP (reliable, connection-oriented)")
                elif proto == 17: protocol_notes.append("UDP (fast, connectionless)")
                elif proto == 1: protocol_notes.append("ICMP (control/error messaging)")
                else: protocol_notes.append(f"Other protocol ({proto})")
            results_df['protocol_performance_note'] = protocol_notes
        else:
            results_df['protocol_performance_note'] = 'N/A (Protocol insights disabled or no ip_protocol feature)'

        # Placeholder for future flow-based metrics
        results_df['estimated_throughput_impact'] = "Low (per-packet analysis only)"
        results_df['estimated_latency_impact'] = "Unknown (per-packet analysis only)"

        # Small Packet Percentage Concern (configurable)
        small_packet_concern_rule = self.performance_rules.get('small_packet_percentage_concern', {})
        if small_packet_concern_rule.get('enabled', False) and \
           'packet_size_category' in results_df.columns and \
           total_samples >= small_packet_concern_rule.get('minimum_sample_size', 50):
            
            small_packet_count = (results_df['packet_size_category'] == 'Small Packet').sum()
            small_packet_percentage = (small_packet_count / total_samples) * 100
            threshold_pct = small_packet_concern_rule.get('threshold_percentage', 60)

            if small_packet_percentage > threshold_pct:
                concern_desc = f"High percentage of small packets ({small_packet_percentage:.1f}%) detected. This might indicate predominantly interactive/control traffic, or potentially fragmentation or keep-alive messages. Threshold: >{threshold_pct}%."
                concerns_found.append(concern_desc)
                anomalies_count += small_packet_count # Count all small packets as part of this anomaly type
                # Add a column to mark these specific packets if needed, or just use the summary.

        logger.info(f"Performed performance feature analysis on {total_samples} samples.")

        # Generate Summary and Quality Score
        summary_parts = [f"Performance Analysis ({total_samples} samples):"]
        if 'packet_size_category' in results_df.columns and not results_df['packet_size_category'].str.startswith('N/A').all():
            packet_size_counts = results_df['packet_size_category'].value_counts()
            summary_parts.append("Packet Size Distribution:")
            for size, count in packet_size_counts.items():
                percentage = (count / total_samples) * 100
                summary_parts.append(f"  - {size}: {count} ({percentage:.1f}%)")
        
        if 'protocol_performance_note' in results_df.columns and not results_df['protocol_performance_note'].str.startswith('N/A').all():
            protocol_counts = results_df['protocol_performance_note'].value_counts()
            summary_parts.append("Protocol Notes:")
            for proto_note, count in protocol_counts.items():
                percentage = (count / total_samples) * 100
                summary_parts.append(f"  - {proto_note}: {count} ({percentage:.1f}%)")

        if concerns_found:
            summary_parts.append("Performance Concerns:")
            summary_parts.extend([f"  - {concern}" for concern in concerns_found])
        else:
            summary_parts.append("No specific performance concerns identified based on current heuristics.")

        text_summary = "\n".join(summary_parts)

        # Basic quality score - placeholder, needs refinement
        quality_score = 100.0
        if anomalies_count > 0 and total_samples > 0:
            # Penalize based on the proportion of packets involved in any anomaly
            # This is a rough measure; specific anomalies might have different weights
            penalty_factor = (anomalies_count / total_samples)
            quality_score = max(0, 100.0 - (penalty_factor * 50)) # Max 50 point penalty for this model

        return {
            "text_summary": text_summary,
            "quality_score": round(quality_score, 2),
            "anomalies_detected": anomalies_count, # Sum of packets part of any anomaly
            "details_df": results_df
        }

    def get_description(self) -> dict:
        """
        Returns a description of the performance analysis procedure.
        """
        return {
            "name": "Performance Feature Analyzer",
            "procedure": "This module provides insights into network performance by analyzing per-packet features using configurable rules from settings.yaml. "
                         "It categorizes packets by size (Small, Medium, Large) based on 'performance_rules.packet_size_categories'. "
                         "It notes general performance characteristics of common protocols (TCP, UDP, ICMP) if 'performance_rules.protocol_insights.enabled' is true. "
                         "A configurable rule ('performance_rules.small_packet_percentage_concern') can flag a high percentage of small packets. "
                         "True performance metrics like throughput and latency require flow analysis (planned for future versions).",
            "features_used": "'frame_length', 'ip_protocol'.",
            "output_columns": "Augmented data with 'packet_size_category', 'protocol_performance_note', 'estimated_throughput_impact', 'estimated_latency_impact'.",
            "summary_output": "Provides a text summary of packet size distribution, protocol notes, and any detected performance concerns. Includes a numeric quality score (0-100) and a count of anomaly instances.",
            "quality_metrics": "The quality score is influenced by the proportion of packets associated with identified performance concerns (e.g., high percentage of small packets). "
                               "Metrics include packet size categorization and protocol characteristics."
        }

# Example Usage (for testing)
if __name__ == '__main__':
    data = {
        'frame_length': [60, 700, 1480, 200],
        'ip_protocol': [6, 17, 6, 1] # TCP, UDP, TCP, ICMP
    }
    sample_df = pd.DataFrame(data)
    
    # Mock ConfigManager for testing
    class MockConfigManager:
        def __init__(self, rules=None):
            self.rules = rules
            if self.rules is None:
                self.rules = { # Default mock rules, mimicking settings.yaml structure
                    'packet_size_categories': {'small_threshold': 100, 'medium_threshold': 1000},
                    'protocol_insights': {'enabled': True},
                    'small_packet_percentage_concern': {'enabled': True, 'threshold_percentage': 60, 'minimum_sample_size': 2}
                }

        def get_setting(self, key, default=None):
            if key == 'ai_monitoring_settings.performance_rules':
                return self.rules
            return default

    print("--- Test with Default Performance Rules ---")
    perf_analyzer_default = PerformanceMLAnalyzer(config_manager=MockConfigManager())
    description = perf_analyzer_default.get_description()
    print("Analyzer Description:")
    for key, value in description.items():
        print(f"  {key}: {value}")

    results_default = perf_analyzer_default.analyze_performance_features(sample_df.copy())
    print("\nPerformance Analysis Results (Default Rules):")
    print(f"Text Summary:\n{results_default['text_summary']}")
    print(f"Quality Score: {results_default['quality_score']}")
    print(f"Anomalies Detected: {results_default['anomalies_detected']}")
    # print("\nDetails DataFrame Sample:")
    # print(results_default['details_df'][['frame_length', 'ip_protocol', 'packet_size_category', 'protocol_performance_note']].head())

    print("\n--- Test with Small Packet Concern Triggered ---")
    many_small_packets_data = {
        'frame_length': [60, 70, 80, 90, 50, 1500], # 5 out of 6 are small
        'ip_protocol': [6, 17, 6, 1, 6, 17]
    }
    small_df = pd.DataFrame(many_small_packets_data)
    results_small_concern = perf_analyzer_default.analyze_performance_features(small_df.copy())
    print(f"Text Summary:\n{results_small_concern['text_summary']}")
    print(f"Quality Score: {results_small_concern['quality_score']}")
    print(f"Anomalies Detected: {results_small_concern['anomalies_detected']}")

    print("\n--- Test with Small Packet Concern Disabled ---")
    disabled_concern_rules = {
        'packet_size_categories': {'small_threshold': 100, 'medium_threshold': 1000},
        'protocol_insights': {'enabled': True},
        'small_packet_percentage_concern': {'enabled': False, 'threshold_percentage': 60, 'minimum_sample_size': 2}
    }
    perf_analyzer_disabled = PerformanceMLAnalyzer(config_manager=MockConfigManager(rules=disabled_concern_rules))
    results_disabled_concern = perf_analyzer_disabled.analyze_performance_features(small_df.copy()) # Use same small_df
    print(f"Text Summary:\n{results_disabled_concern['text_summary']}")
    print(f"Quality Score: {results_disabled_concern['quality_score']}")
    print(f"Anomalies Detected: {results_disabled_concern['anomalies_detected']}")

    print("\n--- Test with Empty DataFrame ---")
    empty_df = pd.DataFrame(columns=sample_df.columns)
    results_empty = perf_analyzer_default.analyze_performance_features(empty_df)
    print(f"Text Summary:\n{results_empty['text_summary']}")
    print(f"Quality Score: {results_empty['quality_score']}")
    print(f"Anomalies Detected: {results_empty['anomalies_detected']}")

    print("\n--- Test with No Config Manager (Defaults) ---")
    perf_analyzer_no_config = PerformanceMLAnalyzer(config_manager=None)
    results_no_config = perf_analyzer_no_config.analyze_performance_features(sample_df.copy())
    print(f"Text Summary:\n{results_no_config['text_summary']}")
    print(f"Quality Score: {results_no_config['quality_score']}")
    print(f"Anomalies Detected: {results_no_config['anomalies_detected']}")

