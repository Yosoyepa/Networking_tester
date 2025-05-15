"""
QoS Analyzer using ML for AI Monitoring.

Analyzes network packet features to assess Quality of Service aspects.
"""
import pandas as pd
import logging
# from sklearn.cluster import KMeans # Example: for clustering traffic types
# from sklearn.preprocessing import StandardScaler

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


    def __init__(self, config_manager=None):
        self.config_manager = config_manager
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
            return features_df

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
            
        # Placeholder for more advanced QoS concerns detection (e.g., based on ML or heuristics)
        results_df['qos_concerns'] = "None detected (basic analysis)"
        
        # Example heuristic: High DSCP for very small packets (potential misconfiguration or unusual traffic)
        if 'dscp' in results_df.columns and 'frame_length' in results_df.columns:
            results_df.loc[(results_df['dscp'] >= 46) & (results_df['frame_length'] < 100), 'qos_concerns'] = "High priority (EF) for small packet"

        logger.info(f"Performed QoS analysis on {len(results_df)} samples.")
        return results_df

    def get_description(self) -> dict:
        """
        Returns a description of the QoS analysis procedure.
        """
        return {
            "name": "QoS Feature Analyzer",
            "procedure": "This module analyzes Differentiated Services Code Point (DSCP) values from IP headers "
                         "and Wi-Fi User Priority (UP) / TID values from 802.11 QoS Control fields. "
                         "It maps these values to their standard meanings (e.g., Best Effort, Expedited Forwarding, Voice Access Category). "
                         "Currently, it uses a rule-based approach for interpretation. Future versions may include ML models "
                         "to detect QoS anomalies or classify traffic based on QoS patterns.",
            "features_used": "'dscp' (from IP ToS field), 'wifi_tid' (from 802.11 QoS Control), 'is_wifi', 'frame_length'.",
            "output": "Augmented data with interpretations of DSCP and Wi-Fi UP/TID values, and potential QoS concerns.",
            "quality_values": "DSCP Name (e.g., 'Best Effort', 'EF'), Wi-Fi Access Category (e.g., 'Voice', 'Video'), "
                              "and descriptive text about the QoS marking and potential concerns."
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
    
    qos_analyzer = QoSMLAnalyzer()
    print(qos_analyzer.get_description())
    
    results = qos_analyzer.analyze_qos_features(sample_df)
    print("\nQoS Analysis Results:")
    print(results[['frame_length', 'dscp', 'dscp_meaning', 'dscp_description', 'is_wifi', 'wifi_tid', 'wifi_ac_name', 'wifi_ac_description', 'qos_concerns']])
