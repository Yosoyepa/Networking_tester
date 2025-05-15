import yaml
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages loading and accessing configuration from a YAML file."""
    _config = None
    _config_path = None

    @classmethod
    def load_config(cls, config_path="config/settings.yaml"):
        """
        Loads the configuration from the specified YAML file.
        The path should be relative to the project root.
        """
        project_root = Path(__file__).resolve().parent.parent.parent
        full_config_path = project_root / config_path
        cls._config_path = full_config_path
        try:
            with open(full_config_path, 'r', encoding='utf-8') as f:
                cls._config = yaml.safe_load(f)
            logger.info(f"Configuration loaded successfully from {full_config_path}")
        except FileNotFoundError:
            logger.error(f"Configuration file not found at {full_config_path}. Using default or empty config.")
            cls._config = {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration from {full_config_path}: {e}")
            cls._config = {}
        return cls._config

    @classmethod
    def get(cls, key, default=None):
        """
        Retrieves a configuration value using a dot-separated key.
        Example: ConfigManager.get('logging.level')
        """
        if cls._config is None:
            cls.load_config() # Attempt to load if not already loaded

        keys = key.split('.')
        value = cls._config
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else: # pragma: no cover
                    logger.warning(f"Config key part '{k}' not found or parent is not a dict for key '{key}'.")
                    return default
            return value
        except (KeyError, TypeError): # pragma: no cover
            logger.debug(f"Configuration key '{key}' not found. Returning default: {default}")
            return default

    @classmethod
    def get_config_path(cls):
        """Returns the path of the loaded configuration file."""
        return cls._config_path

# Load configuration when the module is imported for easy access
ConfigManager.load_config()

if __name__ == '__main__':
    # Example Usage:
    print(f"Log Level: {ConfigManager.get('logging.level', 'INFO')}")
    print(f"Default Interface: {ConfigManager.get('capture.default_interface')}")
    print(f"Known Port 80: {ConfigManager.get('analysis.known_ports.80')}")
    print(f"Non-existent key: {ConfigManager.get('foo.bar.baz', 'default_value')}")
    print(f"Config file path: {ConfigManager.get_config_path()}")