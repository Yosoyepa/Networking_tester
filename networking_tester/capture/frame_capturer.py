# networking_tester/networking_tester/capture/frame_capturer.py
# Script de Python
# Desarrollado para networking_tester

from scapy.all import sniff, wrpcap
import os

class FrameCapturer:
    def __init__(self, interface=None, capture_filter=None, count=0, timeout=None):
        """
        Inicializa el capturador de tramas.
        Args:
            interface (str, optional): Interfaz de red para capturar.
                                       Si es None, Scapy intentará elegir una.
            capture_filter (str, optional): Filtro BPF para la captura (ej. "tcp port 80").
            count (int, optional): Número de paquetes a capturar. 0 para infinito.
            timeout (int, optional): Tiempo en segundos para detener la captura.
        """
        self.interface = interface
        self.capture_filter = capture_filter
        self.count = count
        self.timeout = timeout
        self.packets = None

    def start_capture(self, packet_handler_callback=None):
        """
        Inicia la captura de paquetes.
        Args:
            packet_handler_callback (function, optional): Función a llamar por cada paquete capturado.
                                                          Debe aceptar un argumento (el paquete).
        """
        print(f"Iniciando captura en la interfaz: {self.interface or 'auto-seleccionada'}")
        print(f"Filtro: {self.capture_filter or 'ninguno'}")
        print(f"Cantidad de paquetes a capturar: {'infinito' if self.count == 0 else self.count}")

        # Si no se provee un callback, usamos uno simple para almacenar los paquetes
        if packet_handler_callback is None:
            self.packets = sniff(
                iface=self.interface,
                filter=self.capture_filter,
                count=self.count,
                timeout=self.timeout
            )
        else:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=packet_handler_callback, # Llama a esta función por cada paquete
                count=self.count,
                timeout=self.timeout
            )
        print("Captura finalizada.")

    def get_captured_packets(self):
        """Retorna los paquetes capturados si no se usó callback."""
        return self.packets

    def save_to_pcap(self, filename="capture.pcap"):
        """
        Guarda los paquetes capturados en un archivo PCAP.
        Args:
            filename (str): Nombre del archivo PCAP.
        """
        if self.packets:
            path = os.path.join("data", "captures", filename) # Asumiendo que se ejecuta desde la raíz del proyecto
            wrpcap(path, self.packets)
            print(f"Paquetes guardados en: {path}")
        else:
            print("No hay paquetes capturados para guardar (o se usó un callback externo).")

    def start_capture_and_get_packets(self):
        """
        Captura paquetes y retorna la lista de paquetes capturados.
        Returns:
            list: Lista de paquetes capturados.
        """
        self.start_capture()
        return self.get_captured_packets()

# Ejemplo de uso (se movería a main.py o un script específico)
if __name__ == '__main__':
    # Esto es solo para demostración aquí, idealmente se llama desde main.py
    import os # Necesario si se ejecuta directamente y se quiere guardar
    if not os.path.exists(os.path.join("data", "captures")):
        os.makedirs(os.path.join("data", "captures"))

    def simple_packet_printer(packet):
        print(f"Paquete capturado: {packet.summary()}")

    # capturer = FrameCapturer(interface="eth0", count=10) # Especifica tu interfaz
    # capturer.start_capture(packet_handler_callback=simple_packet_printer)

    capturer_store = FrameCapturer(interface="Wi-Fi", count=5, timeout=10) # o el nombre de tu interfaz Wi-Fi
    capturer_store.start_capture()
    captured = capturer_store.get_captured_packets()
    if captured:
        captured.summary()
        capturer_store.save_to_pcap("mi_captura.pcap")