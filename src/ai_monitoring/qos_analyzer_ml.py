"""
QoS Analyzer using ML for AI Monitoring.

Analyzes network packet features to assess Quality of Service aspects.
"""
import pandas as pd
import logging
# from sklearn.cluster import KMeans # Example: for clustering traffic types
# from sklearn.preprocessing import StandardScaler
from src.utils.config_manager import ConfigManager # Ensure ConfigManager is imported

logger = logging.getLogger(__name__)

class QoSMLAnalyzer:
    """
    Analyzes QoS related features from packet data.
    Initially, this might be rule-based or simple statistical,
    with hooks for more advanced ML models later.
    """
    # Based on https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos_dfs/configuration/15-mt/qos-dfs-15-mt-book/qos-dfs-dscp-values.html
    DSCP_COMMON_MAPPINGS = {
        0:  {'name': 'Best Effort (BE) / CS0', 'description': 'Default traffic.'},
        8:  {'name': 'CS1 (Scavenger)', 'description': 'Lower-priority data (e.g., bulk data).'},
        10: {'name': 'AF11', 'description': 'Assured Forwarding - Class 1, Low Drop'},
        12: {'name': 'AF12', 'description': 'Assured Forwarding - Class 1, Medium Drop'},
        14: {'name': 'AF13', 'description': 'Assured Forwarding - Class 1, High Drop'},
        16: {'name': 'CS2', 'description': 'OAM (Operations, Administration, and Maintenance).'},
        18: {'name': 'AF21', 'description': 'Assured Forwarding - Class 2, Low Drop (e.g., Transactional Data)'},
        20: {'name': 'AF22', 'description': 'Assured Forwarding - Class 2, Medium Drop'},
        22: {'name': 'AF23', 'description': 'Assured Forwarding - Class 2, High Drop'},
        24: {'name': 'CS3', 'description': 'Broadcast Video / Streaming Video.'},
        26: {'name': 'AF31', 'description': 'Assured Forwarding - Class 3, Low Drop (e.g., Voice/Video Conferencing)'},
        28: {'name': 'AF32', 'description': 'Assured Forwarding - Class 3, Medium Drop'},
        30: {'name': 'AF33', 'description': 'Assured Forwarding - Class 3, High Drop'},
        32: {'name': 'CS4', 'description': 'Real-time Interactive / Control Traffic.'},
        34: {'name': 'AF41', 'description': 'Assured Forwarding - Class 4, Low Drop (e.g., Interactive Multimedia)'},
        36: {'name': 'AF42', 'description': 'Assured Forwarding - Class 4, Medium Drop'},
        38: {'name': 'AF43', 'description': 'Assured Forwarding - Class 4, High Drop'},
        40: {'name': 'CS5', 'description': 'Signaling / Network Control.'},
        46: {'name': 'Expedited Forwarding (EF)', 'description': 'High priority, low-latency, low-jitter (e.g., VoIP).'},
        48: {'name': 'CS6 (Network Control)', 'description': 'Network Control (e.g., routing protocols).'},
        56: {'name': 'CS7 (Network Control)', 'description': 'Network Control (highest priority).'}
    }
    
    # Wi-Fi User Priorities (UP) to Access Categories (AC) mapping
    # Based on IEEE 802.11 standards (e.g., 802.11e/WMM)
    WIFI_UP_TO_AC = {
        0: {'ac': 'BE', 'name': 'Best Effort (AC_BE)', 'description': 'Background traffic, lowest priority.'},
        1: {'ac': 'BK', 'name': 'Background (AC_BK)', 'description': 'Bulk data, low priority.'}, # Often 0,1 map to BE/BK
        2: {'ac': 'BK', 'name': 'Background (AC_BK)', 'description': 'Spare, often maps to Background.'},
        3: {'ac': 'BE', 'name': 'Best Effort (AC_BE)', 'description': 'Excellent effort, normal data.'}, # Often 2,3 map to BE
        4: {'ac': 'VI', 'name': 'Video (AC_VI)', 'description': 'Video streaming, controlled latency.'},
        5: {'ac': 'VI', 'name': 'Video (AC_VI)', 'description': 'Video, higher priority video.'},
        6: {'ac': 'VO', 'name': 'Voice (AC_VO)', 'description': 'Voice over IP, interactive voice.'},
        7: {'ac': 'VO', 'name': 'Voice (AC_VO)', 'description': 'Highest priority voice, network control over Wi-Fi.'}
    }


    def __init__(self, config_manager=None): # config_manager instance is still accepted
        self.config_manager = config_manager # And stored, in case other methods need it
        self.qos_rules = {}
        try:
            # Use the static get method from ConfigManager class
            # Corrected path: 'ai_monitoring.qos_rules'
            loaded_rules = ConfigManager.get('ai_monitoring.qos_rules', {})
            if isinstance(loaded_rules, dict):
                self.qos_rules = loaded_rules
                logger.info(f"Loaded QoS rules: {self.qos_rules}")
            else:
                logger.warning(f"QoS rules loaded are not a dict: {loaded_rules}. Using empty default.")
                self.qos_rules = {}
        except Exception as e:
            logger.error(f"Error loading QoS rules using ConfigManager.get: {e}")
            self.qos_rules = {} # Ensure it's a dict on error
        
        # Define default fallbacks if rules are not found/valid
        # This ensures ef_small_packet_concern always has a default structure if not loaded
        default_ef_concern = {
            'enabled': True,
            'dscp_threshold': 46, # EF
            'frame_length_threshold': 100
        }
        if not self.qos_rules or 'ef_small_packet_concern' not in self.qos_rules:
            logger.info("Using default 'ef_small_packet_concern' rules.")
            self.qos_rules['ef_small_packet_concern'] = default_ef_concern
        else:
            # Ensure all keys exist in the loaded rule, falling back to defaults if necessary
            loaded_ef_concern = self.qos_rules['ef_small_packet_concern']
            if not isinstance(loaded_ef_concern, dict):
                logger.warning("'ef_small_packet_concern' rule is not a dict. Reverting to default.")
                self.qos_rules['ef_small_packet_concern'] = default_ef_concern
            else:
                self.qos_rules['ef_small_packet_concern']['enabled'] = loaded_ef_concern.get('enabled', default_ef_concern['enabled'])
                self.qos_rules['ef_small_packet_concern']['dscp_threshold'] = loaded_ef_concern.get('dscp_threshold', default_ef_concern['dscp_threshold'])
                self.qos_rules['ef_small_packet_concern']['frame_length_threshold'] = loaded_ef_concern.get('frame_length_threshold', default_ef_concern['frame_length_threshold'])

        logger.info("QoSMLAnalyzer initialized.")
        # In the future, load/initialize ML models here

    def analyze_qos_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyzes QoS related features and adds QoS assessment to the DataFrame.

        Args:
            features_df (pd.DataFrame): DataFrame with extracted features,
                                        must include 'dscp' and 'wifi_tid'.

        Returns:
            pd.DataFrame: The input DataFrame augmented with QoS analysis columns
                          (e.g., 'dscp_meaning', 'wifi_ac_name', 'qos_concerns').
        """
        if features_df.empty:
            logger.warning("QoS analysis input is empty.")
            # Return a new empty DataFrame with expected columns if possible, or just a copy
            # For simplicity, returning a copy. Consider defining expected output columns for empty DFs.
            return features_df.copy()

        results_df = features_df.copy()

        # DSCP Analysis
        if 'dscp' in results_df.columns:
            results_df['dscp_meaning'] = results_df['dscp'].apply(
                lambda x: self.DSCP_COMMON_MAPPINGS.get(x, {}).get('name', 'Unknown/Unassigned')
            )
            results_df['dscp_description'] = results_df['dscp'].apply(
                lambda x: self.DSCP_COMMON_MAPPINGS.get(x, {}).get('description', 'No specific description.')
            )
        else:
            results_df['dscp_meaning'] = 'N/A (No DSCP feature)'
            results_df['dscp_description'] = 'N/A'

        # Wi-Fi TID/UP to Access Category Analysis
        if 'wifi_tid' in results_df.columns and 'is_wifi' in results_df.columns:
            results_df['wifi_ac_name'] = results_df.apply(
                lambda row: self.WIFI_UP_TO_AC.get(row['wifi_tid'], {}).get('name', 'Unknown UP') if row['is_wifi'] else 'N/A (Not WiFi)', axis=1
            )
            results_df['wifi_ac_description'] = results_df.apply(
                lambda row: self.WIFI_UP_TO_AC.get(row['wifi_tid'], {}).get('description', 'No specific description.') if row['is_wifi'] else 'N/A', axis=1
            )
        else:
            results_df['wifi_ac_name'] = 'N/A (No WiFi TID/is_wifi feature)'
            results_df['wifi_ac_description'] = 'N/A'
            
        # Initialize qos_concerns column
        results_df['qos_concerns'] = "None" # Default to string "None"

        # Configurable heuristic: EF small packet concern
        # Ensure qos_rules and ef_small_packet_concern exist from __init__
        ef_concern_rule = self.qos_rules.get('ef_small_packet_concern', {})
        
        if (ef_concern_rule.get('enabled', False) and
            'dscp' in results_df.columns and 
            'frame_length' in results_df.columns):
            
            dscp_thresh = ef_concern_rule.get('dscp_threshold', 46)
            frame_len_thresh = ef_concern_rule.get('frame_length_threshold', 100)
            
            concern_mask = (results_df['dscp'] >= dscp_thresh) & (results_df['frame_length'] < frame_len_thresh)
            results_df.loc[concern_mask, 'qos_concerns'] = f"High priority (DSCP >= {dscp_thresh}) for small packet (< {frame_len_thresh} bytes)"

        logger.info(f"Performed QoS analysis on {len(results_df)} samples.")
        return results_df

    def generate_summary(self, analyzed_df: pd.DataFrame) -> dict:
        """
        Generates a summary of QoS analysis results.

        Args:
            analyzed_df (pd.DataFrame): DataFrame after QoS analysis.

        Returns:
            dict: A dictionary containing:
                  'text_summary' (str): A human-readable summary string.
                  'quality_score' (float): A numeric score (0-100) representing overall QoS health.
                  'anomalies_detected' (int): Count of detected anomalies/concerns.
        """
        if analyzed_df.empty or 'qos_concerns' not in analyzed_df.columns:
            return {
                "text_summary": "No QoS data to summarize or 'qos_concerns' column missing.",
                "quality_score": 0.0, # Default score for no data
                "anomalies_detected": 0
            }

        concerns_summary_lines = []
        total_samples = len(analyzed_df)
        if total_samples == 0: # Should be caught by analyzed_df.empty but good for robustness
             return {
                "text_summary": "No QoS data (0 samples) to summarize.",
                "quality_score": 0.0,
                "anomalies_detected": 0
            }

        anomalies_detected = 0
        
        # EF small packet concern summary
        ef_concern_rule = self.qos_rules.get('ef_small_packet_concern', {})
        if ef_concern_rule.get('enabled', False): # Only summarize if rule was enabled
            dscp_thresh = ef_concern_rule.get('dscp_threshold', 46)
            frame_len_thresh = ef_concern_rule.get('frame_length_threshold', 100)
            ef_small_packet_label = f"High priority (DSCP >= {dscp_thresh}) for small packet (< {frame_len_thresh} bytes)"
            ef_small_packet_count = len(analyzed_df[analyzed_df['qos_concerns'] == ef_small_packet_label])
            
            if ef_small_packet_count > 0:
                percentage = (ef_small_packet_count / total_samples) * 100
                concerns_summary_lines.append(f"- '{ef_small_packet_label}': {ef_small_packet_count} instances ({percentage:.2f}% of samples).")
                anomalies_detected += ef_small_packet_count
        
        # Add more concern summaries here if other rules are implemented

        # Overall summary string
        if not concerns_summary_lines:
            summary_str = f"QoS Analysis: No specific concerns detected in {total_samples} analyzed samples. All traffic appears to conform to basic QoS checks performed."
        else:
            summary_str = f"QoS Analysis ({total_samples} samples):\n" + "\n".join(concerns_summary_lines)
            summary_str += f"\nTotal QoS anomalies/concerns: {anomalies_detected}."
        
        # Placeholder for quality score logic
        quality_score = 100.0
        if anomalies_detected > 0 and total_samples > 0:
            # Simple penalty: reduce score by percentage of anomalous packets, scaled
            # Max penalty of 75 for this simple model. Max 100% anomalous packets -> score 25.
            penalty_factor = (anomalies_detected / total_samples)
            quality_score = max(0, 100.0 - (penalty_factor * 75))

        return {
            "text_summary": summary_str.strip(),
            "quality_score": round(quality_score, 2),
            "anomalies_detected": anomalies_detected # This is a sum of counts, not distinct types of anomalies
        }

    def get_description(self) -> dict:
        """
        Returns a description of the QoS analysis procedure.
        """
        return {
            "name": "QoS Feature Analyzer",
            "procedure": "This module analyzes Differentiated Services Code Point (DSCP) values from IP headers "
                         "and Wi-Fi User Priority (UP) / TID values from 802.11 QoS Control fields. "
                         "It maps these values to their standard meanings (e.g., Best Effort, Expedited Forwarding, Voice Access Category). "
                         "It uses configurable rules (from settings.yaml under 'ai_monitoring_settings.qos_rules') to identify potential QoS concerns, "
                         "such as high-priority markings on very small packets. The primary configurable rule is 'ef_small_packet_concern'.",
            "features_used": "'dscp' (from IP ToS field), 'wifi_tid' (from 802.11 QoS Control), 'is_wifi', 'frame_length'.",
            "output_columns": "Augmented data with 'dscp_meaning', 'dscp_description', 'wifi_ac_name', 'wifi_ac_description', and 'qos_concerns'.",
            "summary_output": "Provides a text summary of detected concerns (including counts and percentages), a numeric quality score (0-100), and a total count of anomaly instances.",
            "quality_metrics": "The quality score is derived from the percentage of packets exhibiting configured QoS concerns. "
                               "Specific metrics include interpretations of DSCP and Wi-Fi UP/TID values, and identification of packets matching concern criteria."
        }

# Example Usage (for testing)
if __name__ == '__main__':
    data = {
        'frame_length': [64, 512, 1500, 70, 1200],
        'dscp': [0, 46, 10, 56, 0], # BE, EF, AF11, CS7, BE
        'is_wifi': [0, 0, 0, 1, 1],
        'wifi_tid': [0, 0, 0, 7, 4] # N/A, N/A, N/A, Voice, Video
    }
    sample_df = pd.DataFrame(data)
    
    # Mock ConfigManager for testing
    class MockConfigManager:
        def __init__(self, rules=None):
            self.rules = rules
            if self.rules is None:
                self.rules = {
                    'ef_small_packet_concern': {
                        'enabled': True,
                        'dscp_threshold': 46,
                        'frame_length_threshold': 100 
                    }
                }

        def get_setting(self, key, default=None):
            if key == 'ai_monitoring_settings.qos_rules':
                return self.rules
            return default

    print("--- Test with Default EF Small Packet Concern (Enabled) ---")
    qos_analyzer_default = QoSMLAnalyzer(config_manager=MockConfigManager()) 
    description = qos_analyzer_default.get_description()
    print("Analyzer Description:")
    for key, value in description.items():
        print(f"  {key}: {value}")
    
    results_default = qos_analyzer_default.analyze_qos_features(sample_df.copy())
    print("\nQoS Analysis Results (DataFrame - Default Rule):")
    print(results_default[['frame_length', 'dscp', 'dscp_meaning', 'qos_concerns']])
    summary_default = qos_analyzer_default.generate_summary(results_default)
    print("\nQoS Analysis Summary (Default Rule):")
    print(f"  Text: {summary_default['text_summary']}")
    print(f"  Quality Score: {summary_default['quality_score']}")
    print(f"  Anomalies Detected: {summary_default['anomalies_detected']}")

    # Test with rule disabled
    print("\n--- Test with EF Small Packet Concern Disabled ---")
    disabled_rules = {
        'ef_small_packet_concern': {
            'enabled': False, 
            'dscp_threshold': 46,
            'frame_length_threshold': 100 
        }
    }
    qos_analyzer_disabled = QoSMLAnalyzer(config_manager=MockConfigManager(rules=disabled_rules))
    results_disabled = qos_analyzer_disabled.analyze_qos_features(sample_df.copy())
    print("\nQoS Analysis Results (DataFrame - Disabled Rule):")
    print(results_disabled[['frame_length', 'dscp', 'dscp_meaning', 'qos_concerns']])
    summary_disabled = qos_analyzer_disabled.generate_summary(results_disabled)
    print("\nQoS Analysis Summary (Disabled Rule):")
    print(f"  Text: {summary_disabled['text_summary']}")
    print(f"  Quality Score: {summary_disabled['quality_score']}")
    print(f"  Anomalies Detected: {summary_disabled['anomalies_detected']}")

    # Test with no config manager (fallback to defaults)
    print("\n--- Test with No Config Manager (Defaults) ---")
    qos_analyzer_no_config = QoSMLAnalyzer(config_manager=None)
    results_no_config = qos_analyzer_no_config.analyze_qos_features(sample_df.copy())
    print("\nQoS Analysis Results (DataFrame - No Config):")
    print(results_no_config[['frame_length', 'dscp', 'dscp_meaning', 'qos_concerns']])
    summary_no_config = qos_analyzer_no_config.generate_summary(results_no_config)
    print("\nQoS Analysis Summary (No Config):")
    print(f"  Text: {summary_no_config['text_summary']}")
    print(f"  Quality Score: {summary_no_config['quality_score']}")
    print(f"  Anomalies Detected: {summary_no_config['anomalies_detected']}")

    # Test with empty dataframe
    print("\n--- Test with Empty DataFrame ---")
    empty_df = pd.DataFrame(columns=sample_df.columns)
    results_empty = qos_analyzer_default.analyze_qos_features(empty_df) # Use any initialized analyzer
    print("\nQoS Analysis Results (DataFrame - Empty):")
    print(results_empty)
    summary_empty = qos_analyzer_default.generate_summary(results_empty)
    print("\nQoS Analysis Summary (Empty):")
    print(f"  Text: {summary_empty['text_summary']}")
    print(f"  Quality Score: {summary_empty['quality_score']}")
    print(f"  Anomalies Detected: {summary_empty['anomalies_detected']}")

    # Test with custom thresholds
    print("\n--- Test with Custom EF Small Packet Concern Thresholds ---")
    custom_rules = {
        'ef_small_packet_concern': {
            'enabled': True, 
            'dscp_threshold': 40, # Custom DSCP threshold
            'frame_length_threshold': 80 # Custom frame length threshold
        }
    }
    qos_analyzer_custom = QoSMLAnalyzer(config_manager=MockConfigManager(rules=custom_rules))
    # Create data that would trigger custom rule but not default
    custom_data = {
        'frame_length': [70, 90], 
        'dscp': [42, 46], # DSCP 42 > 40, DSCP 46 > 40
        'is_wifi': [0,0],
        'wifi_tid': [0,0]
    }
    custom_sample_df = pd.DataFrame(custom_data)
    results_custom = qos_analyzer_custom.analyze_qos_features(custom_sample_df)
    print("\nQoS Analysis Results (DataFrame - Custom Rule):")
    print(results_custom[['frame_length', 'dscp', 'dscp_meaning', 'qos_concerns']])
    summary_custom = qos_analyzer_custom.generate_summary(results_custom)
    print("\nQoS Analysis Summary (Custom Rule):")
    print(f"  Text: {summary_custom['text_summary']}")
    print(f"  Quality Score: {summary_custom['quality_score']}")
    print(f"  Anomalies Detected: {summary_custom['anomalies_detected']}")
