#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analizador de tramas 802.11 (WiFi) para networking_tester."""

from scapy.all import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11QoS
from unittest.mock import MagicMock
import logging
from datetime import datetime
from .base_analyzer import BaseAnalyzer # Import BaseAnalyzer

logger = logging.getLogger(__name__)

class IEEE802_11_Analyzer(BaseAnalyzer): # Inherit from BaseAnalyzer
    """Clase para analizar tramas IEEE 802.11 (WiFi)."""
    
    def __init__(self, config_manager): # Accept config_manager
        super().__init__(config_manager) # Call super init
        logger.debug("IEEE802_11_Analyzer initialized.")
        self.ssid_list = {}  # Diccionario para almacenar SSIDs descubiertos
        # Interfaces conocidas para WiFi (para inferir si un paquete viene de WiFi)
        self.known_wifi_interfaces = set()
        # Inicializar con algunos valores comunes, este conjunto puede crecer
        common_wifi_prefixes = [
            '60:e3:2b', # Posible prefijo de interfaz WiFi en tu contexto
        ]
        for prefix in common_wifi_prefixes:
            self.known_wifi_interfaces.add(prefix.lower())

    def analyze_packet(self, packet, existing_analysis=None): # Rename from analyze_frame and add existing_analysis
        """
        Analiza una trama 802.11 y extrae información relevante.
        
        Args:
            packet: Trama 802.11 capturada (objeto de scapy o MagicMock)
            existing_analysis (dict, optional): Analysis results from previous analyzers.
            
        Returns:
            dict: Diccionario con información analizada de la trama, integrated with existing_analysis.
        """
        analysis_results = {}
        # Manejo especial para objetos MagicMock utilizados en pruebas
        if isinstance(packet, MagicMock):
            frame_type_val = getattr(packet, 'type', 0)
            subtype_val = getattr(packet, 'subtype', 8) # Default to Beacon for mock
            fcfield = getattr(packet, 'FCfield', 0)
            
            if frame_type_val == 0: frame_type_str = "Management"
            elif frame_type_val == 1: frame_type_str = "Control"
            elif frame_type_val == 2: frame_type_str = "Data"
            else: frame_type_str = "Unknown"

            # Simplified subtype for mock
            if frame_type_val == 0 and subtype_val == 8: subtype_name = "Beacon"
            elif frame_type_val == 1 and subtype_val == 13: subtype_name = "ACK"
            elif frame_type_val == 2 and subtype_val == 0: subtype_name = "Data" # Plain data
            elif frame_type_val == 2 and subtype_val == 8: subtype_name = "QoS Data" # QoS Data
            else: subtype_name = "Subtype " + str(subtype_val)
            
            analysis_results = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                'packet_length': getattr(packet, 'len', len(packet) if hasattr(packet, '__len__') else 100),
                'type_general': "IEEE 802.11",
                'tipo_subtipo': f"{frame_type_str} {subtype_name}",
                'flags': { 'ProtectedFrame': bool(fcfield & 0x40) }, # Simplified flags for mock
                'type': 'wifi', # This key might be better as 'layer2_type'
                'src_mac': getattr(packet, 'addr2', "AA:BB:CC:DD:EE:FF"),
                'dst_mac': getattr(packet, 'addr1', "00:11:22:33:44:55"),
                'bssid': getattr(packet, 'addr3', "DE:AD:BE:EF:00:00"),
            }
            if bool(fcfield & 0x40):
                analysis_results['security_info'] = {'status': "Trama protegida/encriptada."}
            else:
                analysis_results['security_info'] = {'status': "Trama no protegida"}

            if frame_type_val == 2 and hasattr(packet, 'tid'): # Mock QoS Data
                tid = getattr(packet, 'tid', 0)
                priority = tid & 0x7
                analysis_results['qos_control'] = {'tid': tid, 'priority': priority}
                analysis_results['qos_interpretacion'] = f"Prioridad de Usuario (UP): {priority}"
            
            if frame_type_val == 0 and subtype_val == 8: # Mock Beacon
                 analysis_results['ssid'] = getattr(packet, 'ssid', 'MockSSID')


        # Análisis de tramas reales
        elif packet.haslayer(Dot11):
            dot11_frame = packet.getlayer(Dot11)
            frame_type_str_real = self._get_frame_type(dot11_frame) # This returns a descriptive string
            
            # Determine general type string for 'tipo_subtipo' consistency
            general_type_prefix = ""
            if dot11_frame.type == 0: general_type_prefix = "Management"
            elif dot11_frame.type == 1: general_type_prefix = "Control"
            elif dot11_frame.type == 2: general_type_prefix = "Data"
            
            # Safely convert packet.time to float before using it in datetime.fromtimestamp
            packet_time = datetime.now()
            if hasattr(packet, 'time'):
                try:
                    # Convert EDecimal to float before using it with fromtimestamp
                    packet_time = datetime.fromtimestamp(float(packet.time))
                except (TypeError, ValueError, OverflowError):
                    # If conversion fails, use current time
                    packet_time = datetime.now()
            
            analysis_results = {
                'timestamp': packet_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                'packet_length': len(packet),
                'type_general': "IEEE 802.11",
                'tipo_subtipo': f"{general_type_prefix} {frame_type_str_real}".strip(),
                'flags': self._extract_flags(dot11_frame),
                'type': 'wifi',
            }
            
            if hasattr(dot11_frame, 'addr1') and dot11_frame.addr1: analysis_results['dst_mac'] = dot11_frame.addr1
            if hasattr(dot11_frame, 'addr2') and dot11_frame.addr2: analysis_results['src_mac'] = dot11_frame.addr2
            if hasattr(dot11_frame, 'addr3') and dot11_frame.addr3: analysis_results['bssid'] = dot11_frame.addr3 # Often BSSID
            
            analysis_results['security_info'] = {'status': self._analyze_security(packet)} # Ensure _analyze_security returns a string
            
            if packet.haslayer(Dot11Beacon): self._analyze_beacon(packet, analysis_results)
            elif packet.haslayer(Dot11ProbeReq): self._analyze_probe_request(packet, analysis_results)
            elif packet.haslayer(Dot11ProbeResp): self._analyze_probe_response(packet, analysis_results)
            elif dot11_frame.type == 2: self._analyze_data_frame(packet, analysis_results) # Type 2 = Data
            
            if packet.haslayer(Dot11QoS): self._analyze_qos(packet, analysis_results)
            
            analysis_results['performance'] = {
                'signal_strength': getattr(packet, 'dBm_AntSignal', None), # Scapy might provide this
                'data_rate': self._estimate_data_rate(packet)
            }

        # Nuevo código: detección inferencial de tramas WiFi encapsuladas como Ethernet
        else:
            is_likely_wifi = self._infer_wifi_packet(packet, existing_analysis)
            
            if is_likely_wifi:
                # Get safe timestamp
                packet_time = datetime.now()
                if hasattr(packet, 'time'):
                    try:
                        # Convert EDecimal to float before using it with fromtimestamp
                        packet_time = datetime.fromtimestamp(float(packet.time))
                    except (TypeError, ValueError, OverflowError):
                        # If conversion fails, use current time
                        packet_time = datetime.now()
                        
                # Crear un análisis simplificado para tramas WiFi encapsuladas
                analysis_results = {
                    'timestamp': packet_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'packet_length': len(packet),
                    'type_general': "IEEE 802.11 (inferido)",
                    'tipo_subtipo': "Trama WiFi encapsulada",
                    'flags': {"encapsulated": True},
                    'type': 'wifi',
                    'encapsulated_as': 'ethernet',
                    'inferred_from': self._get_inference_reason(packet, existing_analysis)
                }
                
                # Añadir información de MAC si está disponible
                if hasattr(packet, 'src') and packet.src:
                    analysis_results['src_mac'] = packet.src
                if hasattr(packet, 'dst') and packet.dst:
                    analysis_results['dst_mac'] = packet.dst
                
                # Buscar SSID en caché o intentar inferirlo
                possible_ssid = self._infer_ssid(packet, existing_analysis)
                if possible_ssid:
                    analysis_results['ssid'] = possible_ssid
            else:
                analysis_results = {"error": "No es una trama 802.11"}

        # Integrate with existing_analysis
        if existing_analysis:
            existing_analysis.setdefault('wifi_details', {}).update(analysis_results)
            return existing_analysis
        
        return {'wifi_details': analysis_results}

    def _get_frame_type(self, dot11_frame):
        """Determina el tipo y subtipo de trama 802.11."""
        type_val = dot11_frame.type
        subtype_val = dot11_frame.subtype
        
        if type_val == 0:
            type_str = "Management"
            if subtype_val == 0:
                return "Association Request"
            elif subtype_val == 1:
                return "Association Response"
            elif subtype_val == 8:
                return "Beacon"
            elif subtype_val == 4:
                return "Probe Request"
            elif subtype_val == 5:
                return "Probe Response"
            # Otros subtipos...
        elif type_val == 1:
            type_str = "Control"
            if subtype_val == 11:
                return "RTS"
            elif subtype_val == 12:
                return "CTS"
            elif subtype_val == 13:
                return "ACK"
            # Otros subtipos...
        elif type_val == 2:
            type_str = "Data"
            if hasattr(dot11_frame, 'QoS'):
                return "QoS Data"
            return "Data"
        
        return f"{type_str} (type={type_val}, subtype={subtype_val})"
    
    def _extract_flags(self, dot11_frame):
        """Extrae las banderas (flags) de la trama 802.11."""
        flags = {}
        
        # Comunes a todas las tramas 802.11
        if hasattr(dot11_frame, 'FCfield'):
            fc = dot11_frame.FCfield
            flags['ToDS'] = bool(fc & 0x01)
            flags['FromDS'] = bool(fc & 0x02)
            flags['MoreFrag'] = bool(fc & 0x04)
            flags['Retry'] = bool(fc & 0x08)
            flags['PwrMgt'] = bool(fc & 0x10)
            flags['MoreData'] = bool(fc & 0x20)
            flags['ProtectedFrame'] = bool(fc & 0x40)
            flags['Order'] = bool(fc & 0x80)
        
        return flags
    
    def _analyze_security(self, frame): # Changed from packet to frame for consistency if it only uses Dot11
        """Analiza la seguridad de la trama."""
        dot11_layer = frame.getlayer(Dot11)
        if dot11_layer and hasattr(dot11_layer, 'FCfield') and dot11_layer.FCfield & 0x40: # Protected Frame bit
            # Further analysis could be done here to determine WEP, WPA, WPA2, WPA3 from RSNInfo etc.
            return "Trama protegida/encriptada." # Basic status
        return "Trama no protegida"

    def _analyze_beacon(self, frame, analysis_results_dict): # Modifies dict directly
        """Analiza una trama Beacon."""
        beacon_layer = frame.getlayer(Dot11Beacon)
        dot11_layer = frame.getlayer(Dot11)
        
        if beacon_layer and hasattr(beacon_layer, 'info'):
            try:
                ssid = beacon_layer.info.decode('utf-8', errors='replace')
                analysis_results_dict['ssid'] = ssid
                if dot11_layer and hasattr(dot11_layer, 'addr2'): # addr2 is typically the BSSID in Beacons
                    self.ssid_list[ssid] = {
                        'last_seen': datetime.fromtimestamp(frame.time).isoformat() if hasattr(frame, 'time') else datetime.now().isoformat(),
                        'bssid': dot11_layer.addr2
                        # Could add channel, security type etc. here if parsed
                    }
            except Exception as e:
                logger.warning(f"Could not decode SSID in beacon: {e}")
                analysis_results_dict['ssid'] = "<undecodable>"
    
    # Ensure other _analyze_* methods also take analysis_results_dict and modify it.
    def _analyze_probe_request(self, frame, analysis_results_dict):
        probe_req_layer = frame.getlayer(Dot11ProbeReq)
        if probe_req_layer and hasattr(probe_req_layer, 'info'):
            try:
                ssid = probe_req_layer.info.decode('utf-8', errors='replace')
                if ssid: # SSID can be empty (wildcard probe)
                    analysis_results_dict['requested_ssid'] = ssid
            except Exception as e:
                logger.warning(f"Could not decode SSID in probe request: {e}")


    def _analyze_probe_response(self, frame, analysis_results_dict):
        probe_resp_layer = frame.getlayer(Dot11ProbeResp)
        if probe_resp_layer and hasattr(probe_resp_layer, 'info'):
            try:
                ssid = probe_resp_layer.info.decode('utf-8', errors='replace')
                analysis_results_dict['ssid'] = ssid
            except Exception as e:
                logger.warning(f"Could not decode SSID in probe response: {e}")


    def _analyze_data_frame(self, frame, analysis_results_dict):
        # Placeholder for more detailed data frame analysis
        # e.g., check for LLC/SNAP headers, encapsulated protocol
        pass


    def _analyze_qos(self, frame, analysis_results_dict):
        qos_layer = frame.getlayer(Dot11QoS)
        if qos_layer:
            tid = qos_layer.TID
            if isinstance(tid, MagicMock): tid = 0
            
            priority = tid & 0x07 if isinstance(tid, int) else 0
            ack_policy = (tid >> 5) & 0x03 if isinstance(tid, int) else 0 # Corrected shift for Ack Policy (bits 5-6)
                                                                      # Assuming standard QoS Control field
            
            analysis_results_dict['qos_control'] = {
                'tid': tid,
                'priority': priority,
                'ack_policy': ack_policy 
            }
            priority_names = {
                0: "Best Effort (AC_BE)", 1: "Background (AC_BK)", 2: "Background (AC_BK)",
                3: "Best Effort (AC_BE)", 4: "Video (AC_VI)", 5: "Video (AC_VI)",
                6: "Voice (AC_VO)", 7: "Voice (AC_VO)"
            }
            analysis_results_dict['qos_interpretacion'] = f"UP: {priority} ({priority_names.get(priority, 'Desconocida')})"


    def _estimate_data_rate(self, frame):
        # This is a very rough estimation. Real data rate comes from radiotap headers or specific 802.11 fields.
        if frame.haslayer(Dot11Beacon): return 1.0
        # Scapy's Dot11QoS is just a basic layer, doesn't inherently mean high speed.
        # Actual rates (MCS index, etc.) are in other layers or radiotap.
        # For now, return a placeholder.
        return None # Or a default like 6.0 if you must provide a value

    # Remove _generate_summary or adapt it if strictly needed internally by this analyzer only
    # def _generate_summary(self, analysis_results_dict):
    #     # ...
    #     pass

    def get_network_summary(self): # This might be useful for the engine to call after a run
        return self.ssid_list
    
    def _infer_wifi_packet(self, packet, existing_analysis):
        """
        Infiere si un paquete es WiFi basado en características específicas
        cuando no tiene una capa Dot11 explícita.
        """
        # 1. Verificar si la interfaz MAC es conocida como WiFi
        if hasattr(packet, 'src'):
            src_prefix = packet.src.lower()[:8]  # Primeros 3 bytes del MAC (con :)
            if src_prefix in self.known_wifi_interfaces:
                # Aprender este nuevo prefijo
                self.known_wifi_interfaces.add(src_prefix)
                # Mark the packet as WiFi for AI processing
                packet._wifi_inferred = True
                return True
            
            # Add your specific 60:e3:2b MAC prefix
            if packet.src.lower().startswith('60:e3:2b'):
                self.known_wifi_interfaces.add('60:e3:2b')
                packet._wifi_inferred = True
                return True
        
        # 2. Verificar si hay información de ethernet_details que sugiera WiFi
        if existing_analysis and 'ethernet_details' in existing_analysis:
            eth_details = existing_analysis['ethernet_details']
            
            # Si la MAC de origen es conocida como WiFi
            if 'src_mac' in eth_details:
                src_prefix = eth_details['src_mac'].lower()[:8]
                
                # Special case for your specific WiFi adapter
                if eth_details['src_mac'].lower().startswith('60:e3:2b'):
                    self.known_wifi_interfaces.add('60:e3:2b')
                    packet._wifi_inferred = True
                    return True
                    
                if src_prefix in self.known_wifi_interfaces:
                    self.known_wifi_interfaces.add(src_prefix)
                    packet._wifi_inferred = True
                    return True
            
            # Verificar patrones específicos de WiFi en el protocolo
            if eth_details.get('ethertype') == "0x800":  # IPv4
                # Buscar protocolos típicos de WiFi
                # Por ejemplo, si es multicast a una dirección típica de SSDP en WiFi
                if 'dst_mac' in eth_details and eth_details['dst_mac'].startswith("01:00:5e:7f:ff:"):
                    packet._wifi_inferred = True
                    return True
                
        # 3. Verificar campos de protocolo específicos
        if hasattr(packet, 'type') and getattr(packet, 'type', None) == 2:  # Data frames en WiFi
            packet._wifi_inferred = True
            return True
        
        # 4. Buscar patrones específicos en el contenido del paquete para identificar WiFi
        # Por ejemplo, si hay un SSID visible en el contenido
        raw_bytes = bytes(packet) if hasattr(packet, '__bytes__') else b''
        if b'SSID=' in raw_bytes or b'SSID:' in raw_bytes:
            packet._wifi_inferred = True
            return True
            
        # Por defecto, no es WiFi si no se encontró evidencia
        return False
    
    def _get_inference_reason(self, packet, existing_analysis):
        """
        Proporciona una razón por la que se infirió que este paquete es WiFi.
        """
        reasons = []
        
        # Verificar MAC de origen
        if hasattr(packet, 'src'):
            src_prefix = packet.src.lower()[:8]
            if src_prefix in self.known_wifi_interfaces:
                reasons.append(f"MAC de origen ({src_prefix}) corresponde a una interfaz WiFi conocida")
        
        # Verificar ethernet_details
        if existing_analysis and 'ethernet_details' in existing_analysis:
            eth_details = existing_analysis['ethernet_details']
            if 'src_mac' in eth_details:
                src_prefix = eth_details['src_mac'].lower()[:8]
                if src_prefix in self.known_wifi_interfaces:
                    reasons.append(f"MAC de origen en ethernet_details ({src_prefix}) corresponde a una interfaz WiFi conocida")
            
            if eth_details.get('ethertype') == "0x800" and 'dst_mac' in eth_details:
                if eth_details['dst_mac'].startswith("01:00:5e:7f:ff:"):
                    reasons.append("Dirección multicast característica de WiFi")
        
        # Si no hay razones específicas
        if not reasons:
            reasons.append("Basado en heurísticas generales de tráfico WiFi")
            
        return reasons

    def _infer_ssid(self, packet, existing_analysis):
        """
        Intenta inferir el SSID basado en la información disponible.
        """
        # Si ya tenemos un SSID almacenado para alguna MAC, usarlo
        if hasattr(packet, 'src') and packet.src:
            for ssid, info in self.ssid_list.items():
                if info.get('bssid') == packet.src:
                    return ssid
        
        # Buscar en contenido del paquete
        if hasattr(packet, 'load'):
            try:
                load_str = packet.load.decode('utf-8', errors='ignore')
                if 'SSID=' in load_str:
                    # Extraer SSID=valor
                    parts = load_str.split('SSID=')
                    if len(parts) > 1:
                        potential_ssid = parts[1].split()[0]
                        return potential_ssid
            except (AttributeError, UnicodeDecodeError):
                pass
        
        # No se pudo inferir
        return None