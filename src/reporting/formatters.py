import json
import csv
import io
import logging
import pprint # Added for pretty printing AI results

logger = logging.getLogger(__name__)

class BaseFormatter:
    def format(self, data_list, stats=None, ai_results=None): # Added stats and ai_results
        raise NotImplementedError

class JSONFormatter(BaseFormatter):
    def format(self, data_list, stats=None, ai_results=None): # Added stats and ai_results
        """Formats a list of analysis dictionaries, stats, and AI results into a JSON string."""
        cleaned_packet_analysis_data = []
        for item in data_list:
            # Remove non-serializable raw Scapy packet object before JSON dump
            cleaned_item = {k: v for k, v in item.items() if k != 'original_packet'}
            cleaned_packet_analysis_data.append(cleaned_item)
        

        report_content = {
            "statistics": stats if stats is not None else {},
            "packet_analysis_data": cleaned_packet_analysis_data, # Use cleaned data
            "ai_analysis_results": ai_results if ai_results is not None else {}
        }
        
        try:
            return json.dumps(report_content, indent=4, default=str) # default=str for datetime etc.
        except TypeError as e:
            logger.error(f"Error formatting data to JSON: {e}")
            return json.dumps({"error": "JSON formatting failed", "details": str(e)})

class CSVFormatter(BaseFormatter):
    def format(self, data_list, stats=None, ai_results=None): # Added stats and ai_results, but CSV will ignore them for now
        """Formats a list of analysis dictionaries into a CSV string.
        Currently, stats and ai_results are ignored by this formatter.
        """
        if not data_list:
            return ""
        
        output = io.StringIO()
        headers = []
        sample_data = {}

        for item in data_list:
            if isinstance(item, dict) and 'packet_summary' in item and isinstance(item['packet_summary'], dict):
                sample_data = item['packet_summary']
                headers = list(sample_data.keys())
                break
        
        if not headers and data_list and isinstance(data_list[0], dict): # Fallback
            # Ensure 'packet_summary' is not accidentally taken as headers if it's a dict itself
            if 'packet_summary' in data_list[0] and isinstance(data_list[0]['packet_summary'], dict):
                headers = list(data_list[0]['packet_summary'].keys())
            else:
                headers = list(data_list[0].keys())
            sample_data = data_list[0]

        if not headers:
            logger.warning("CSVFormatter: Could not determine headers from data.")
            return "Error: Could not determine CSV headers."

        writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        for item_data_full in data_list:
            # Extract the relevant part for CSV or flatten
            data_to_write = item_data_full.get('packet_summary', item_data_full if isinstance(item_data_full, dict) else {})
            # Ensure all values are simple types for CSV
            processed_row = {}
            if isinstance(data_to_write, dict):
                for key, value in data_to_write.items():
                    if isinstance(value, (list, dict)):
                        processed_row[key] = json.dumps(value) # Serialize complex types to JSON string
                    else:
                        processed_row[key] = value
                writer.writerow(processed_row)
            else:
                logger.debug(f"Skipping non-dict item for CSV: {data_to_write}")
        return output.getvalue()

class ConsoleFormatter(BaseFormatter):
    def format(self, data_list, stats=None, ai_results=None): # Added stats and ai_results
        """Formats analysis data, stats, and AI results for console output."""
        lines = ["=== Network Analysis Report ==="]

        if stats:
            lines.append("\\n=== Overall Statistics ===")
            for key, value in stats.items():
                if isinstance(value, dict):
                    lines.append(f"  {key}:")
                    for sub_key, sub_value in value.items():
                        lines.append(f"    {sub_key}: {sub_value}")
                else:
                    lines.append(f"  {key}: {value}")
            lines.append("=" * 30)

        lines.append("\\n=== Packet Analysis Details ===")
        if not data_list:
            lines.append("No packet data to display.")
        else:
            for i, item in enumerate(data_list):
                lines.append(f"--- Packet {i+1} ---")
                summary = item.get('packet_summary', item)
                if isinstance(summary, dict):
                    for key, value in summary.items():
                        lines.append(f"  {key}: {value}")
                else:
                    lines.append(str(summary))
                # Optionally, include other parts of 'item' if needed, e.g., anomaly_analysis
                anomaly_info = item.get('anomaly_analysis')
                if anomaly_info and anomaly_info.get('detected_anomalies'):
                    lines.append(f"  Rule-Based Anomalies: {len(anomaly_info['detected_anomalies'])}")
                    for anom in anomaly_info['detected_anomalies']:
                        lines.append(f"    - {anom.get('message', 'Unknown anomaly')}")

                lines.append("-" * 20)
        lines.append("=" * 30)

        if ai_results:
            lines.append("\\n=== AI Analysis Results ===")
            if isinstance(ai_results, dict) and "error" in ai_results:
                lines.append(f"AI Analysis Error: {ai_results['error']}")
            elif isinstance(ai_results, dict):
                # Use pprint for a structured view of the AI results
                ai_pretty_printer = pprint.PrettyPrinter(indent=2, width=100)
                for analysis_type, results_data in ai_results.items():
                    lines.append(f"\\n--- {analysis_type.replace('_', ' ').title()} ---")
                    if isinstance(results_data, dict):
                        # lines.append(ai_pretty_printer.pformat(results_data))
                        # Custom formatting for better readability than pure pprint
                        lines.append(f"  Description: {results_data.get('description', 'N/A')}")
                        lines.append(f"  Status: {results_data.get('status', 'N/A')}")
                        if "model_name" in results_data: # For security analysis
                            lines.append(f"  Model: {results_data.get('model_name', 'N/A')}")
                        if "packets_analyzed" in results_data: # For security analysis
                             lines.append(f"  Packets Analyzed by AI: {results_data.get('packets_analyzed', 0)}")
                             lines.append(f"  Potential Anomalies by AI: {results_data.get('anomalies_detected', 0)}")
                        if "summary" in results_data: # For QoS/Performance
                            lines.append(f"  Summary: {results_data.get('summary', 'N/A')}")
                        
                        lines.append(f"  Quality Value: {results_data.get('quality_value', 0.0):.2f}%")

                        details_sample = results_data.get('anomaly_details_sample') or results_data.get('details_sample')
                        if details_sample:
                            lines.append(f"  Details Sample (up to 5):")
                            if isinstance(details_sample, list):
                                for i, detail in enumerate(details_sample):
                                    if i < 5: # Ensure we only print up to 5
                                        lines.append(f"    - {ai_pretty_printer.pformat(detail)}")
                            elif isinstance(details_sample, str): # e.g. if it's a pre-formatted string
                                lines.append(f"    {details_sample}")
                    else:
                        lines.append(f"  {str(results_data)}") # Fallback for unexpected format
            else:
                lines.append("AI analysis results are not in the expected dictionary format.")
            lines.append("=" * 30)
        
        lines.append("\\n=== End of Report ===")
        return "\\n".join(lines)