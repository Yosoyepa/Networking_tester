import logging
from pathlib import Path
from datetime import datetime
from .formatters import JSONFormatter, CSVFormatter, ConsoleFormatter
from ..utils.config_manager import ConfigManager

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.formatters = {
            "json": JSONFormatter(),
            "csv": CSVFormatter(),
            "console": ConsoleFormatter(),
        }
        self.output_dir_str = ConfigManager.get('reporting.output_directory', 'reports')
        self.filename_template = ConfigManager.get('reporting.report_filename_template', "capture_report_{timestamp}.{format}")
        
        project_root = Path(__file__).resolve().parent.parent.parent
        self.output_dir = project_root / self.output_dir_str
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, analyzed_data_list, report_format=None, stats=None, ai_results=None):
        """
        Generates a report from the list of analyzed packet data, stats, and AI results.

        Args:
            analyzed_data_list (list): A list of dictionaries, where each dict is an analysis result for a packet.
            report_format (str, optional): The desired format ('json', 'csv', 'console'). 
                                           Defaults to config or 'console'.
            stats (dict, optional): Overall statistics dictionary.
            ai_results (dict, optional): Dictionary containing AI analysis results.

        Returns:
            str: The formatted report string.
        """
        if report_format is None:
            report_format = ConfigManager.get('reporting.default_format', 'console')

        formatter = self.formatters.get(report_format.lower())
        if not formatter:
            logger.error(f"Unsupported report format: {report_format}. Using console.")
            formatter = self.formatters["console"]
            report_format = "console" # Ensure filename uses correct format

        # Pass stats and ai_results to the formatter
        formatted_string = formatter.format(analyzed_data_list, stats=stats, ai_results=ai_results)

        if report_format != "console":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Modify filename if AI results are present to distinguish the report
            base_filename_part = "capture_report"
            if ai_results and not ai_results.get("error"):
                base_filename_part = "ai_analysis_report"
            
            filename = self.filename_template.replace("capture_report", base_filename_part)\
                                            .format(timestamp=timestamp, format=report_format)
            
            filepath = self.output_dir / filename
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(formatted_string)
                logger.info(f"Report generated and saved to {filepath}")
            except IOError as e:
                logger.error(f"Failed to write report to {filepath}: {e}")
        
        return formatted_string

    def print_to_console(self, analyzed_data_list, stats=None, ai_results=None):
        """Prints a console-formatted report directly, including stats and AI results."""
        console_formatter = self.formatters["console"]
        # Pass stats and ai_results to the console formatter
        print(console_formatter.format(analyzed_data_list, stats=stats, ai_results=ai_results))
