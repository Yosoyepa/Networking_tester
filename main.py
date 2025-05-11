#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

import argparse
from networking_tester.capture import frame_capturer
from networking_tester.analysis import frame_parser # O los analizadores específicos
from networking_tester.ai_monitoring import anomaly_detector # Ejemplo
from networking_tester.utils import logging_config
import logging

logger = logging_config.setup_logging()

def run_capture_and_analyze(interface, count, pcap_file=None):
    logger.info(f'Iniciando captura en {interface} por {count} paquetes.')
    # Aquí iría la lógica para llamar a frame_capturer
    # y luego pasar los paquetes a los módulos de análisis y IA.
    # Ejemplo:
    # capturer = frame_capturer.FrameCapturer(interface=interface, count=count)
    # packets = capturer.start_capture_and_get_packets()
    # if pcap_file and packets:
    #     capturer.save_to_pcap(packets, pcap_file)
    #     logger.info(f'Captura guardada en {pcap_file}')

    # for packet in packets:
    #     analysis_result = frame_parser.parse_packet(packet) # Suponiendo una función genérica
    #     logger.debug(f'Análisis: {analysis_result}')
    #     # Pasar a IA si es necesario
    #     # ai_features = ai_monitoring.feature_extractor.extract(packet)
    #     # ai_prediction = ai_monitoring.anomaly_detector.predict(ai_features)
    logger.info('Proceso de captura y análisis (simulado) completado.')

def main():
    parser = argparse.ArgumentParser(description='Herramienta networking_tester para análisis de redes.')
    parser.add_argument('-i', '--interface', type=str, required=False, help='Interfaz de red para capturar (ej: eth0, wlan0).')
    parser.add_argument('-c', '--count', type=int, default=10, help='Número de paquetes a capturar.')
    parser.add_argument('-r', '--read', type=str, help='Leer paquetes desde un archivo PCAP en lugar de capturar en vivo.')
    parser.add_argument('-w', '--write', type=str, help='Guardar los paquetes capturados en un archivo PCAP.')
    parser.add_argument('--ai-monitor', action='store_true', help='Activar monitoreo con IA (funcionalidad a desarrollar).')
    # Añadir más argumentos según las funcionalidades (Punto 5 y 6)

    args = parser.parse_args()

    logger.info(f'Iniciando {project_name} con argumentos: {args}')

    if args.read:
        logger.info(f'Leyendo paquetes desde: {args.read}')
        # Lógica para leer y procesar desde PCAP
    elif args.interface:
        run_capture_and_analyze(args.interface, args.count, args.write)
    else:
        logger.warning('No se especificó una interfaz para captura en vivo ni un archivo PCAP para leer.')
        parser.print_help()

    if args.ai_monitor:
        logger.info('Monitoreo con IA activado (simulación).')
        # Lógica para el monitoreo con IA

    logger.info(f'networking_tester finalizado.')

if __name__ == '__main__':
    main()
