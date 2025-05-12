# Arquitectura del Proyecto: networking_tester

## 1. Introducción

`networking_tester` es una herramienta diseñada para la captura y análisis de tráfico de red. Permite a los usuarios capturar paquetes en vivo desde una interfaz de red o leerlos desde archivos PCAP, y luego analizar estos paquetes para extraer información relevante sobre protocolos, seguridad y rendimiento.

## 2. Componentes Principales

El proyecto está estructurado en varios módulos principales, cada uno con responsabilidades específicas:

### 2.1. `networking_tester` (Paquete Principal)

Contiene la lógica central de la aplicación y los sub-módulos.

*   **`__main__.py` (o script de entrada principal):**
    *   Responsable de manejar los argumentos de la línea de comandos (CLI).
    *   Orquesta el flujo de la aplicación: inicia la captura, invoca el análisis y presenta los resultados.
*   **`__init__.py`:** Inicializador del paquete.

### 2.2. `capture` (Módulo de Captura)

Responsable de la adquisición de tramas de red.

*   **`frame_capture.py`:**
    *   Clase `FrameCapture`:
        *   Encapsula la lógica para capturar paquetes en vivo utilizando `scapy.sniff` y `scapy.AsyncSniffer`.
        *   Permite leer paquetes desde archivos PCAP (`scapy.rdpcap`).
        *   Permite escribir paquetes capturados a archivos PCAP (`scapy.wrpcap`).
        *   Maneja filtros de captura (BPF).
        *   Realiza un conteo básico de paquetes por protocolo (TCP, UDP, ICMP) durante la captura.
        *   Invoca un callback (`_packet_callback`) por cada paquete capturado, que puede delegar a módulos de análisis.

### 2.3. `analysis` (Módulo de Análisis)

Contiene las clases y la lógica para analizar los paquetes capturados.

*   **`protocol_analyzer.py`:**
    *   Clase `ProtocolAnalyzer`:
        *   Analiza paquetes IP para extraer información detallada de protocolos de capa de transporte como TCP, UDP e ICMP.
        *   Identifica puertos conocidos y servicios asociados.
        *   Extrae información de cabeceras (IP, TCP, UDP, ICMP), flags TCP, TTL, etc.
        *   Proporciona información básica de QoS (DSCP/TOS).
        *   Genera un resumen legible del paquete.
*   **`ieee802_11_analyzer.py`:**
    *   Clase `IEEE802_11_Analyzer`:
        *   Especializada en el análisis de tramas IEEE 802.11 (WiFi).
        *   Extrae información específica de cabeceras WiFi, como tipo de trama, subtipo, direcciones MAC, SSID, información de QoS (WMM/802.11e), y detalles de seguridad (WEP, WPA/WPA2/WPA3).
*   **(Potencial) `security_analyzer.py`:**
    *   Podría centralizar la lógica de análisis de seguridad, como detección de patrones sospechosos, análisis de cifrado, etc. Actualmente, parte de esta lógica está distribuida.

### 2.4. `utils` (Módulo de Utilidades)

Proporciona funcionalidades de soporte utilizadas en todo el proyecto.

*   **`logging_config.py`:**
    *   Función `setup_logging`: Configura el sistema de logging centralizado para la aplicación, permitiendo la escritura de logs a consola y archivo.
*   **(Potencial) `config_manager.py`:**
    *   Podría manejar la carga y gestión de configuraciones de la aplicación (ej. desde un archivo YAML o JSON).

### 2.5. `tests` (Directorio de Pruebas)

Contiene los tests unitarios para asegurar la correctitud y fiabilidad de los módulos.

*   `test_frame_analysis.py`: Pruebas para los módulos de análisis de protocolos.
*   `test_frame_capture.py`: Pruebas para el módulo de captura de tramas.
*   Utiliza `unittest` y `unittest.mock`.

### 2.6. `logs` (Directorio de Logs)

Directorio donde se almacenan los archivos de log generados por la aplicación.

### 2.7. `docs` (Directorio de Documentación)

Contiene la documentación del proyecto, incluyendo este archivo de arquitectura.

## 3. Flujo de Datos General

1.  **Inicio:** El usuario ejecuta la aplicación a través de la CLI, especificando opciones como la interfaz de captura, el número de paquetes, un archivo PCAP de entrada/salida, o filtros.
2.  **Configuración:** Se inicializa el logging.
3.  **Captura:**
    *   Si es captura en vivo, `FrameCapture` inicia `scapy.sniff` en la interfaz especificada.
    *   Si es lectura de archivo, `FrameCapture` utiliza `scapy.rdpcap`.
4.  **Procesamiento por Paquete:**
    *   Para cada paquete capturado/leído, `FrameCapture._packet_callback` es invocado.
    *   Este callback puede pasar el paquete a una instancia de `ProtocolAnalyzer` y/o `IEEE802_11_Analyzer` (dependiendo del tipo de paquete y la configuración).
5.  **Análisis:**
    *   Los analizadores procesan el paquete, extraen la información relevante y la estructuran (generalmente en diccionarios).
6.  **Resultados:**
    *   La información analizada se agrega a una lista de resultados.
    *   Se pueden generar estadísticas de la captura.
    *   Los resultados y/o estadísticas se muestran al usuario en la consola o se guardan en un archivo (si se especifica).
7.  **Finalización:** Se liberan recursos y la aplicación termina.

## 4. Dependencias Clave

*   **Scapy:** Biblioteca fundamental para la manipulación, captura y análisis de paquetes.
*   **Python Standard Library:** `os`, `sys`, `unittest`, `logging`, `datetime`, `tempfile`, `argparse`.

## 5. Posibles Mejoras y Consideraciones Futuras

*   **Gestión de Configuración Avanzada:** Implementar un sistema de configuración más robusto (ej. archivos YAML/JSON) para parámetros como puertos conocidos, umbrales de alerta, formatos de salida, etc., en lugar de tenerlos codificados.
*   **Extensibilidad de Analizadores:** Diseñar un sistema que permita añadir fácilmente nuevos analizadores de protocolos o de seguridad (ej. mediante un patrón de registro o plugins).
*   **Módulo de Reportes Dedicado:** Crear un módulo específico para formatear y generar reportes en diversos formatos (CSV, JSON, HTML, PDF).
*   **Interfaz Gráfica de Usuario (GUI) o Web UI:** Para una mayor usabilidad, especialmente para usuarios no técnicos.
*   **Análisis de Rendimiento de Red:** Expandir las métricas de rendimiento más allá de las básicas (ej. cálculo de RTT, jitter, pérdida de paquetes si se analizan flujos).
*   **Detección de Anomalías y Alertas:** Implementar lógica para detectar patrones de tráfico anómalos o amenazas de seguridad y generar alertas.
*   **Persistencia de Resultados:** Opción para guardar los resultados detallados del análisis en una base de datos o un formato estructurado para consultas posteriores.
*   **Mejorar la Modularidad:**
    *   Separar más claramente las responsabilidades de `FrameCapture` (pura captura) de las estadísticas básicas, que podrían moverse a un módulo de estadísticas o ser calculadas post-captura por los analizadores.
    *   Considerar un módulo `core` o `engine` que orqueste la interacción entre captura, análisis y presentación de resultados, en lugar de que `FrameCapture` tenga demasiada lógica de coordinación.
*   **Documentación API:** Generar documentación automática de la API del código (ej. con Sphinx).
*   **Empaquetado y Distribución:** Mejorar el empaquetado para facilitar la instalación (ej. `pyproject.toml` y `build`).

Este documento proporciona una visión general de la arquitectura actual y posibles direcciones para el futuro desarrollo de `networking_tester`.
