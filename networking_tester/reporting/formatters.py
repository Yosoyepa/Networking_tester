import json
import csv
import io
import logging

logger = logging.getLogger(__name__)

class BaseFormatter:
    def format(self, data):
        raise NotImplementedError

class JSONFormatter(BaseFormatter):
    def format(self, data_list):
        """Formats a list of analysis dictionaries into a JSON string."""
        try:
            return json.dumps(data_list, indent=4, default=str) # default=str for datetime etc.
        except TypeError as e:
            logger.error(f"Error formatting data to JSON: {e}")
            return json.dumps([{"error": "JSON formatting failed", "details": str(e)}])

class CSVFormatter(BaseFormatter):
    def format(self, data_list):
        """Formats a list of analysis dictionaries into a CSV string."""
        if not data_list:
            return ""
        
        output = io.StringIO()
        # Attempt to get headers from the first item, assuming flat dicts for simplicity
        # More complex data might need specific handling or flattening
        # For now, let's assume 'packet_summary' is a primary dict in each item
        headers = []
        sample_data = {}

        for item in data_list:
            if isinstance(item, dict) and 'packet_summary' in item and isinstance(item['packet_summary'], dict):
                sample_data = item['packet_summary']
                headers = list(sample_data.keys())
                break
        
        if not headers and data_list and isinstance(data_list[0], dict): # Fallback
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
            if isinstance(data_to_write, dict):
                 writer.writerow(data_to_write)
            else:
                logger.debug(f"Skipping non-dict item for CSV: {data_to_write}")
        return output.getvalue()

class ConsoleFormatter(BaseFormatter):
    def format(self, data_list):
        """Formats a list of analysis dictionaries for console output."""
        lines = []
        for i, item in enumerate(data_list):
            lines.append(f"--- Packet {i+1} ---")
            # Prefer a summary if available
            summary = item.get('packet_summary', item)
            if isinstance(summary, dict):
                for key, value in summary.items():
                    lines.append(f"  {key}: {value}")
            else:
                lines.append(str(summary))
            lines.append("-" * 20)
        return "\n".join(lines)