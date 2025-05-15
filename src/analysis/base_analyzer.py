from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

class BaseAnalyzer(ABC):
    """Abstract base class for all packet analyzers."""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.name = self.__class__.__name__
        logger.debug(f"Analyzer '{self.name}' initialized.")

    @abstractmethod
    def analyze_packet(self, packet, existing_analysis=None):
        """
        Analyzes a single packet and returns a dictionary with analysis results.
        
        Args:
            packet: The Scapy packet object to analyze.
            existing_analysis (dict, optional): Analysis results from previous analyzers.
                                                Analyzers can enrich this dictionary.

        Returns:
            dict: A dictionary containing the analysis results for this analyzer.
                  It's recommended to namespace results, e.g., {'protocol_info': {...}}.
        """
        pass

    def get_name(self):
        return self.name