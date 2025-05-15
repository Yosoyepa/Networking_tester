#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para frame_parser dentro de networking_tester."""

import logging
from .ieee802_3_analyzer import IEEE802_3_Analyzer
from .ieee802_11_analyzer import IEEE802_11_Analyzer
from .protocol_analyzer import ProtocolAnalyzer
from scapy.all import Ether, Dot11

logger = logging.getLogger(__name__)

class FrameParser:
    """Clase para analizar tramas de red de diferentes tipos."""
    
    def __init__(self):
        """Inicializar con los analizadores apropiados."""
        self.ethernet_analyzer = IEEE802_3_Analyzer()
        self.wifi_analyzer = IEEE802_11_Analyzer()
        self.protocol_analyzer = ProtocolAnalyzer()
        logger.debug('Analizador de tramas inicializado')
    
    def parse_packet(self, packet):
        """
        Analiza un paquete de red y determina su tipo y características.
        
        Args:
            packet: Paquete capturado (objeto scapy)
            
        Returns:
            dict: Diccionario con la información del análisis
        """
        # Determinar el tipo de paquete/trama
        if packet.haslayer(Ether):
            # Es una trama Ethernet
            analysis = self.ethernet_analyzer.analyze_frame(packet)
            
            # Si contiene una capa IP, analizar también protocolo
            if 'IP' in packet:
                protocol_analysis = self.protocol_analyzer.analyze_packet(packet)
                # Añadir información del protocolo al análisis Ethernet
                if 'error' not in protocol_analysis:
                    analysis.update(protocol_analysis)
            
            return analysis
            
        elif packet.haslayer(Dot11):
            # Es una trama WiFi (802.11)
            return self.wifi_analyzer.analyze_frame(packet)
            
        else:
            # Intentar analizar como un paquete IP
            protocol_analysis = self.protocol_analyzer.analyze_packet(packet)
            if 'error' not in protocol_analysis:
                return protocol_analysis
                
            # Si no se reconoce, devolver error genérico
            return {"error": "Tipo de paquete desconocido"}

logger.debug(f'Módulo {__name__} cargado.')
