# networking_tester/networking_tester/analysis/ieee802_3_analyzer.py
# Script de Python
# Desarrollado para networking_tester

from scapy.all import Ether

class IEEE802_3_Analyzer:
    def analyze_frame(self, frame):
        """
        Analiza una trama IEEE 802.3 (Ethernet).
        Args:
            frame (scapy.layers.l2.Ether): Trama Ethernet capturada por Scapy.
        Returns:
            dict: Un diccionario con los campos analizados.
        """
        if not frame.haslayer(Ether):
            return {"error": "No es una trama Ethernet"}

        analysis = {
            "tipo": "IEEE 802.3 (Ethernet)",
            "direccion_destino": frame[Ether].dst,
            "direccion_origen": frame[Ether].src,
            "tipo_ethernet": hex(frame[Ether].type) # EtherType (ej: 0x0800 para IPv4)
        }
        # Aquí puedes añadir más detalles, como análisis de VLAN tags si existen
        # if frame.haslayer(Dot1Q):
        #     analysis["vlan_id"] = frame[Dot1Q].vlan
        #     analysis["vlan_priority"] = frame[Dot1Q].prio

        # Puedes seguir analizando capas superiores (IP, TCP, UDP, etc.)
        # if frame.haslayer(IP):
        #     analysis["ip_origen"] = frame[IP].src
        #     analysis["ip_destino"] = frame[IP].dst

        return analysis