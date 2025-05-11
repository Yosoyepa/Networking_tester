# networking_tester/networking_tester/analysis/ieee802_11_analyzer.py
# Script de Python
# Desarrollado para networking_tester

from scapy.all import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11DataFrame, Dot11QoSDataFrame
# También podrías necesitar Dot11AssoReq, Dot11AssoResp, Dot11Auth, etc.

class IEEE802_11_Analyzer:
    def analyze_frame(self, frame):
        """
        Analiza una trama IEEE 802.11 (WLAN).
        Args:
            frame (scapy.layers.dot11.Dot11): Trama 802.11 capturada por Scapy.
        Returns:
            dict: Un diccionario con los campos analizados.
        """
        if not frame.haslayer(Dot11):
            return {"error": "No es una trama IEEE 802.11"}

        dot11_layer = frame[Dot11]
        analysis = {
            "tipo_general": "IEEE 802.11",
            "tipo_subtipo": self._get_dot11_type_subtype_str(dot11_layer.type, dot11_layer.subtype),
            "direccion_receptor_ra": dot11_layer.addr1, # Receiver Address
            "direccion_transmisor_ta": dot11_layer.addr2, # Transmitter Address
            "direccion_destino_da": dot11_layer.addr3,   # Destination Address (varía según ToDS/FromDS)
            # "direccion_origen_sa": dot11_layer.addr4, # Source Address (solo en WDS)
            "duracion_id": dot11_layer.ID,
            "control_fragmento_secuencia": dot11_layer.SC,
        }

        # Campos de flags (ToDS, FromDS, MoreFrag, Retry, PwrMgt, MoreData, WEP, Order)
        analysis["flags"] = {
            "ToDS": dot11_layer.FCfield.to_ds,
            "FromDS": dot11_layer.FCfield.from_ds,
            "MoreFrag": dot11_layer.FCfield.more_frag,
            "Retry": dot11_layer.FCfield.retry,
            "PwrMgt": dot11_layer.FCfield.pw_mgt,
            "MoreData": dot11_layer.FCfield.more_data,
            "ProtectedFrame": dot11_layer.FCfield.protected, # Anteriormente WEP
            "Order": dot11_layer.FCfield.order
        }

        # Tramas de Gestión (Management Frames)
        if dot11_layer.type == 0: # Management
            if dot11_layer.haslayer(Dot11Beacon):
                beacon_frame = dot11_layer[Dot11Beacon]
                analysis["ssid"] = beacon_frame.info.decode(errors='ignore')
                analysis["timestamp"] = beacon_frame.timestamp
                analysis["beacon_interval"] = beacon_frame.beacon_interval
                # ... y muchos más campos de beacon (capabilities, supported rates, etc.)
            elif dot11_layer.haslayer(Dot11ProbeReq):
                probe_req_frame = dot11_layer[Dot11ProbeReq]
                analysis["requested_ssid"] = probe_req_frame.info.decode(errors='ignore')
            # ... Añadir análisis para otras tramas de gestión (ProbeResp, Auth, AssoReq/Resp, etc.)

        # Tramas de Control (Control Frames)
        elif dot11_layer.type == 1: # Control
            # Ej: RTS (subtype 11), CTS (subtype 12), ACK (subtype 13)
            # analysis["control_info"] = "Detalles específicos del tipo de trama de control"
            pass # Añadir lógica para tramas de control

        # Tramas de Datos (Data Frames)
        elif dot11_layer.type == 2: # Data
            analysis["es_trama_datos"] = True
            if dot11_layer.haslayer(Dot11DataFrame): # Simple Data frame
                pass
            if dot11_layer.haslayer(Dot11QoSDataFrame): # QoS Data frame
                qos_layer = frame[Dot11QoSDataFrame] # O frame[Dot11QoS]
                analysis["qos_control"] = {
                    "tid": qos_layer.TID,
                    "priority": qos_layer.UP, # User Priority (0-7)
                    "ack_policy": qos_layer.Ack_Policy,
                    # ... otros campos de QoS
                }

        # Punto 5.2: Evaluar campos de seguridad y calidad de servicio
        # Seguridad:
        # El campo "ProtectedFrame" (anteriormente WEP) indica si la trama está encriptada.
        # Para WPA/WPA2/WPA3, la encriptación se maneja en la carga útil de la trama de datos.
        # Se pueden buscar elementos de información específicos (IEs) en tramas de gestión
        # como Beacons o Probe Responses para identificar los mecanismos de seguridad (RSN IE).
        if analysis["flags"]["ProtectedFrame"]:
            analysis["seguridad_info"] = "Trama protegida/encriptada."
            # Un análisis más profundo requeriría desencriptar o parsear IEs específicos.
        else:
            analysis["seguridad_info"] = "Trama no protegida (o protección no indicada a este nivel)."

        # Calidad de Servicio (QoS):
        # Ya se extrajo en `analysis["qos_control"]` si es una trama QoS.
        # El significado de los valores (ej. TID, UP) depende del estándar 802.11e.
        # UP (User Priority) mapea a Clases de Acceso (AC_VO, AC_VI, AC_BE, AC_BK).
        if "qos_control" in analysis:
            analysis["qos_interpretacion"] = f"Trama de datos con QoS. Prioridad de Usuario (UP): {analysis['qos_control']['priority']}"
        else:
            analysis["qos_interpretacion"] = "No es una trama de datos con QoS explícita o QoS no analizada."

        return analysis

    def _get_dot11_type_subtype_str(self, type_val, subtype_val):
        types = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
        subtypes_mgmt = {
            0: "Association Request", 1: "Association Response", 2: "Reassociation Request",
            3: "Reassociation Response", 4: "Probe Request", 5: "Probe Response",
            8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication",
            12: "Deauthentication", 13: "Action"
            # ... otros subtipos de gestión
        }
        subtypes_ctrl = {
            # 8: "Block Ack Request", 9: "Block Ack", # Varían con HT/VHT
            10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End", 15: "CF-End + CF-Ack"
            # ... otros subtipos de control
        }
        subtypes_data = {
            0: "Data", 1: "Data + CF-Ack", 2: "Data + CF-Poll", 3: "Data + CF-Ack + CF-Poll",
            4: "Null (no data)", 5: "CF-Ack (no data)", 6: "CF-Poll (no data)",
            7: "CF-Ack + CF-Poll (no data)",
            8: "QoS Data", 9: "QoS Data + CF-Ack", 10: "QoS Data + CF-Poll",
            11: "QoS Data + CF-Ack + CF-Poll", 12: "QoS Null (no data)",
            14: "QoS CF-Poll (no data)", 15: "QoS CF-Ack + CF-Poll (no data)"
        }

        type_str = types.get(type_val, f"Desconocido ({type_val})")
        subtype_str = ""

        if type_val == 0: # Management
            subtype_str = subtypes_mgmt.get(subtype_val, f"Subtipo Mgmt Desconocido ({subtype_val})")
        elif type_val == 1: # Control
            subtype_str = subtypes_ctrl.get(subtype_val, f"Subtipo Ctrl Desconocido ({subtype_val})")
        elif type_val == 2: # Data
            subtype_str = subtypes_data.get(subtype_val, f"Subtipo Data Desconocido ({subtype_val})")
        
        return f"{type_str} - {subtype_str}"


# En main.py o un script de ejecución:
# from networking_tester.capture.frame_capturer import FrameCapturer
# from networking_tester.analysis.ieee802_3_analyzer import IEEE802_3_Analyzer
# from networking_tester.analysis.ieee802_11_analyzer import IEEE802_11_Analyzer
# from scapy.all import Ether, Dot11, rdpcap # Para leer de archivo

# def process_packet(packet):
#   if packet.haslayer(Ether):
#       analyzer_802_3 = IEEE802_3_Analyzer()
#       analysis = analyzer_802_3.analyze_frame(packet)
#       print("Análisis IEEE 802.3:", analysis)
#   elif packet.haslayer(Dot11):
#       analyzer_802_11 = IEEE802_11_Analyzer()
#       analysis = analyzer_802_11.analyze_frame(packet)
#       print("Análisis IEEE 802.11:", analysis)
#   else:
#       print("Paquete de tipo no soportado para análisis detallado:", packet.summary())

# # Para capturar en vivo:
# # capturer = FrameCapturer(interface="YOUR_WIFI_INTERFACE_IN_MONITOR_MODE", count=20)
# # capturer.start_capture(packet_handler_callback=process_packet)

# # Para leer de un archivo .pcap (primero necesitarás uno)
# # packets_from_file = rdpcap("data/captures/mi_captura.pcap") # Asegúrate que exista
# # for pkt in packets_from_file:
# #     process_packet(pkt)