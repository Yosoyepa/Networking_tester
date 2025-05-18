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
import argparse # Added
import os # Added
import json # Added
import mlflow # Added

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
            loaded_rules = ConfigManager.get('ai_monitoring.qos_rules.performance_rules', {})
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
            # Ensure the column is initialized correctly to avoid dtype issues with pd.NA or mixed types if some conditions aren't met.
            results_df['packet_size_category'] = pd.Series(index=results_df.index, dtype=pd.StringDtype())


            for i, cond_series in enumerate(conditions):
                results_df.loc[cond_series, 'packet_size_category'] = categories[i]
            
            # Fill any remaining NaNs, though with StringDtype and proper assignment, this might not be strictly necessary
            # if all packets fall into one of the categories. However, it's a good fallback.
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
            
            # Ensure 'packet_size_category' is not all N/A before proceeding
            if not results_df['packet_size_category'].str.startswith('N/A').all():
                small_packet_count = (results_df['packet_size_category'] == 'Small Packet').sum()
                small_packet_percentage = (small_packet_count / total_samples) * 100
                threshold_pct = small_packet_concern_rule.get('threshold_percentage', 60)

                if small_packet_percentage > threshold_pct:
                    concern_desc = f"High percentage of small packets ({small_packet_percentage:.1f}%) detected. This might indicate predominantly interactive/control traffic, or potentially fragmentation or keep-alive messages. Threshold: >{threshold_pct}%."
                    concerns_found.append(concern_desc)
                    anomalies_count += small_packet_count # Count all small packets as part of this anomaly type
            else:
                logger.info("Small packet concern check skipped as 'packet_size_category' is N/A.")


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

def main():
	parser = argparse.ArgumentParser(description="Performance Analyzer ML Script")
	parser.add_argument("--features-input-path", type=str, required=True, help="Path to the input CSV file with features.")
	parser.add_argument("--output-dir", type=str, required=True, help="Directory to save analysis results (JSON summary, CSV details).")
	parser.add_argument("--mlflow-active-run-id", type=str, required=False, help="Active MLflow Run ID for nested logging.")
	args = parser.parse_args()

	logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	logger.info(f"Starting performance analysis with input: {args.features_input_path}")

	os.makedirs(args.output_dir, exist_ok=True)

	try:
		features_df = pd.read_csv(args.features_input_path)
	except FileNotFoundError:
		logger.error(f"Input features file not found: {args.features_input_path}")
		raise
	except Exception as e:
		logger.error(f"Error loading features CSV {args.features_input_path}: {e}")
		raise

	analyzer = PerformanceMLAnalyzer() # Uses ConfigManager internally
	analysis_results = analyzer.analyze_performance_features(features_df)

	summary_data = {
		"text_summary": analysis_results["text_summary"],
		"quality_score": analysis_results["quality_score"],
		"anomalies_detected": analysis_results["anomalies_detected"],
		"performance_rules_used": analyzer.performance_rules # Log the rules used
	}
	summary_output_path = os.path.join(args.output_dir, "performance_analysis_summary.json")
	details_output_path = os.path.join(args.output_dir, "performance_analysis_details.csv")

	with open(summary_output_path, 'w') as f:
		json.dump(summary_data, f, indent=4)
	logger.info(f"Performance analysis summary saved to: {summary_output_path}")

	analysis_results["details_df"].to_csv(details_output_path, index=False)
	logger.info(f"Performance analysis details saved to: {details_output_path}")

	# MLflow Logging
	if args.mlflow_active_run_id:
		with mlflow.start_run(run_id=args.mlflow_active_run_id, run_name="PerformanceAnalysisStep", nested=True):
			logger.info(f"Logging to MLflow nested run under parent ID: {args.mlflow_active_run_id}")
			mlflow.log_param("performance_features_input_path", args.features_input_path)
			mlflow.log_param("performance_output_dir", args.output_dir)
			
			# Log performance rules as parameters
			for category, rules in analyzer.performance_rules.items():
				if isinstance(rules, dict):
					for key, value in rules.items():
						mlflow.log_param(f"rule_{category}_{key}", value)
				else:
					mlflow.log_param(f"rule_{category}", rules)
			
			mlflow.log_metric("performance_quality_score", analysis_results["quality_score"])
			mlflow.log_metric("performance_anomalies_detected", analysis_results["anomalies_detected"])
			
			mlflow.log_artifact(summary_output_path, artifact_path="performance_analysis_results")
			mlflow.log_artifact(details_output_path, artifact_path="performance_analysis_results")
			logger.info("Logged parameters, metrics, and artifacts to MLflow.")
	else:
		# Fallback for standalone run (optional, could also just skip MLflow if no run_id)
		with mlflow.start_run(run_name="PerformanceAnalysisStandalone"):
			logger.info("No active MLflow run ID provided, starting a new standalone MLflow run.")
			mlflow.log_param("performance_features_input_path", args.features_input_path)
			mlflow.log_param("performance_output_dir", args.output_dir)
			
			# Log performance rules as parameters
			for category, rules in analyzer.performance_rules.items():
				if isinstance(rules, dict):
					for key, value in rules.items():
						mlflow.log_param(f"rule_{category}_{key}", value)
				else:
					mlflow.log_param(f"rule_{category}", rules)
			
			mlflow.log_metric("performance_quality_score", analysis_results["quality_score"])
			mlflow.log_metric("performance_anomalies_detected", analysis_results["anomalies_detected"])
			
			mlflow.log_artifact(summary_output_path, artifact_path="performance_analysis_results")
			mlflow.log_artifact(details_output_path, artifact_path="performance_analysis_results")


if __name__ == '__main__':
	# Setup project root for src imports if run directly
	current_dir = os.path.dirname(os.path.abspath(__file__))
	project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
	import sys
	if project_root not in sys.path:
		sys.path.insert(0, project_root)
	
	# Re-import ConfigManager if path was just added, to ensure it's found
	# This is a bit of a hack for direct execution; normally PYTHONPATH handles this.
	try:
		from src.utils.config_manager import ConfigManager
	except ImportError:
		print("Failed to re-import ConfigManager. Ensure PYTHONPATH is set or script is run via orchestrator.")
		# Depending on strictness, might exit here if ConfigManager is critical and not found.

	main()

