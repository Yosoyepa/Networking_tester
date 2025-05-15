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

    def generate_report(self, analyzed_data_list, report_format=None):
        """
        Generates a report from the list of analyzed packet data.

        Args:
            analyzed_data_list (list): A list of dictionaries, where each dict is an analysis result for a packet.
            report_format (str, optional): The desired format ('json', 'csv', 'console'). 
                                           Defaults to config or 'console'.

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

        formatted_string = formatter.format(analyzed_data_list)

        if report_format != "console":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.filename_template.format(timestamp=timestamp, format=report_format)
            filepath = self.output_dir / filename
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(formatted_string)
                logger.info(f"Report generated and saved to {filepath}")
            except IOError as e:
                logger.error(f"Failed to write report to {filepath}: {e}")
        
        return formatted_string

    def print_to_console(self, analyzed_data_list):
        """Prints a console-formatted report directly."""
        console_formatter = self.formatters["console"]
        print(console_formatter.format(analyzed_data_list))
