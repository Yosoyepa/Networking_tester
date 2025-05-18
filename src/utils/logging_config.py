#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para configuración de logging en networking_tester."""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from .config_manager import ConfigManager # Import ConfigManager

def setup_logging(): # Removed parameters, will get from config
    """
    Configura el logging para la aplicación based on settings.yaml:
    - Log a archivo con rotación.
    - Log a consola (opcional).
    """
    log_level_str = ConfigManager.get('logging.level', 'INFO')
    console_logging = ConfigManager.get('logging.console_logging', True)
    log_format_str = ConfigManager.get('logging.format', "%(asctime)s [%(levelname)-7s] [%(name)-20s] [%(funcName)s:%(lineno)d] %(message)s")
    log_file_path_str = ConfigManager.get('logging.file', 'logs/networking_tester.log')

    numeric_log_level = getattr(logging, str(log_level_str).upper(), logging.INFO)

    project_root = Path(__file__).resolve().parent.parent.parent
    log_file_full_path = project_root / log_file_path_str
    log_file_full_path.parent.mkdir(parents=True, exist_ok=True)

    log_formatter = logging.Formatter(log_format_str, datefmt="%Y-%m-%d %H:%M:%S")
    # Simpler formatter for console
    console_log_formatter = logging.Formatter("%(message)s")
    
    # Configurar el logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_log_level)
    
    # Remover handlers existentes para evitar duplicados en caso de múltiples llamadas
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Handler para el archivo de log con rotación
    file_handler = RotatingFileHandler(
        log_file_full_path, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(numeric_log_level)
    root_logger.addHandler(file_handler)
    
    # Handler para la consola (stdout)
    if console_logging:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_log_formatter) # Use the simpler formatter for console
        # Set console level based on config, or a specific level for less verbosity if desired
        console_log_level_str = ConfigManager.get('logging.console_level', log_level_str) # Default to main log level
        numeric_console_log_level = getattr(logging, str(console_log_level_str).upper(), numeric_log_level)
        console_handler.setLevel(numeric_console_log_level)
        root_logger.addHandler(console_handler)
    
    # Silenciar loggers muy verbosos
    logging.getLogger("scapy").setLevel(logging.WARNING)
    
    # Crear y retornar un logger específico para networking_tester
    logger = logging.getLogger('networking_tester') # Main application logger
    logger.info(f"Logging configurado. Nivel: {log_level_str.upper()}. Archivo: {log_file_full_path}")

    return logger

# Logger para este módulo
logger = logging.getLogger(__name__)
logger.debug(f'Módulo {__name__} cargado.')
