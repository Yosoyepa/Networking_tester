import logging
import sys

DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_LOG_LEVEL = logging.INFO

def setup_logging(log_level=DEFAULT_LOG_LEVEL, log_format=DEFAULT_LOG_FORMAT, log_file=None):
    """
    Configures basic logging for the application.

    Args:
        log_level: The logging level (e.g., logging.INFO, logging.DEBUG).
        log_format: The format string for log messages.
        log_file: Optional path to a file where logs should be written.
    """
    logging.basicConfig(level=log_level, format=log_format, stream=sys.stdout)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)

    # Example: Silence overly verbose loggers from libraries if needed
    # logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    # logging.getLogger('pika').setLevel(logging.WARNING)

    logging.info(f"Logging configured with level: {logging.getLevelName(log_level)}")

if __name__ == '__main__':
    # Example of using the logger setup
    setup_logging(log_level=logging.DEBUG)
    logging.debug("This is a debug message.")
    logging.info("This is an info message.")
    logging.warning("This is a warning message.")
    logging.error("This is an error message.")
