#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para configuración de logging en networking_tester."""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

def setup_logging(log_level_str="INFO", console_logging=True):
    """
    Configura el logging para la aplicación:
    - Log a archivo con rotación.
    - Log a consola (opcional).
    """
    # Convertir string de nivel de log a valor numérico de logging
    numeric_log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    
    # Crear el directorio de logs si no existe
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "networking_tester.log"
    
    # Formato del log
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] [%(name)-20s] [%(funcName)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Configurar el logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_log_level)
    
    # Remover handlers existentes para evitar duplicados en caso de múltiples llamadas
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Handler para el archivo de log con rotación
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(numeric_log_level)
    root_logger.addHandler(file_handler)
    
    # Handler para la consola (stdout)
    if console_logging:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_formatter)
        console_handler.setLevel(numeric_log_level)
        root_logger.addHandler(console_handler)
    
    # Silenciar loggers muy verbosos
    logging.getLogger("scapy").setLevel(logging.WARNING)
    
    # Crear y retornar un logger específico para networking_tester
    logger = logging.getLogger('networking_tester')
    logger.info(f"Logging configurado. Nivel: {log_level_str.upper()}. Archivo: {log_file}")
    
    return logger

# Logger para este módulo
logger = logging.getLogger(__name__)
logger.debug(f'Módulo {__name__} cargado.')
