# Arquitectura del Proyecto: networking_tester

## 1. Introducción

`networking_tester` es una herramienta diseñada para la captura y análisis de tráfico de red. Permite a los usuarios capturar paquetes en vivo desde una interfaz de red o leerlos desde archivos PCAP. Posteriormente, analiza estos paquetes para extraer información relevante sobre protocolos, generar estadísticas, detectar anomalías (opcionalmente con IA) y generar reportes.

## 2. Componentes Principales

El proyecto está estructurado en varios módulos y directorios principales:

### 2.1. Directorio Raíz (`networking_tester/`)

*   **`main.py`**: Punto de entrada principal de la aplicación. Maneja los argumentos de la línea de comandos (CLI), inicializa el `AnalysisEngine` y orquesta el flujo general.
*   **`README.md`**: Documentación principal del proyecto.
*   **`.gitignore`**: Especifica los archivos y directorios ignorados por Git.
*   **`requirements.txt`**: Lista las dependencias del proyecto.
*   **`setup.py`**: Script para la configuración del proyecto y generación de la estructura inicial (no es un setup de distribución estándar de paquete Python).

### 2.2. Paquete Principal (`networking_tester/networking_tester/`)

Contiene la lógica central de la aplicación y los sub-módulos.

*   **`__init__.py`**: Inicializador del paquete.

#### 2.2.1. `core` (Módulo Core)

*   **`engine.py`**:
    *   Clase `AnalysisEngine`: Componente central que orquesta todo el proceso.
        *   Inicializa y gestiona los demás componentes (captura, analizadores, almacenamiento, reportes).
        *   Maneja la configuración a través del `ConfigManager`.
        *   Proporciona métodos para ejecutar capturas en vivo (`run_live_capture`) o procesar archivos PCAP (`run_pcap_analysis`).
        *   Coordina el paso de paquetes desde el capturador a los analizadores y al colector de estadísticas.
        *   Gestiona la finalización del análisis y la generación de reportes.

#### 2.2.2. `capture` (Módulo de Captura)

Responsable de la adquisición de tramas de red.

*   **`frame_capture.py`**:
    *   Clase `FrameCapture`:
        *   Encapsula la lógica para capturar paquetes en vivo utilizando `scapy.sniff` (síncrono) y `scapy.AsyncSniffer` (asíncrono).
        *   Permite leer paquetes desde archivos PCAP (`scapy.rdpcap`).
        *   Permite escribir paquetes a archivos PCAP (`scapy.wrpcap`).
        *   Maneja filtros de captura (BPF).
        *   Utiliza un callback proporcionado por el `AnalysisEngine` para procesar cada paquete capturado/leído.

#### 2.2.3. `analysis` (Módulo de Análisis)

Contiene las clases y la lógica para analizar los paquetes capturados.

*   **`protocol_analyzer.py`**:
    *   Clase `ProtocolAnalyzer`:
        *   Analiza paquetes para extraer información detallada de protocolos de capa de red (IP) y transporte (TCP, UDP, ICMP).
        *   Identifica puertos conocidos y servicios asociados.
        *   Extrae información de cabeceras, flags TCP, TTL, etc.
        *   Proporciona información básica de QoS (DSCP/TOS).
*   **`ieee802_3_analyzer.py`**:
    *   Clase `IEEE802_3_Analyzer`: Especializada en el análisis de tramas Ethernet (IEEE 802.3), extrayendo direcciones MAC, EtherType, etc.
*   **`ieee802_11_analyzer.py`**:
    *   Clase `IEEE802_11_Analyzer`:
        *   Especializada en el análisis de tramas IEEE 802.11 (WiFi).
        *   Extrae información específica de cabeceras WiFi (tipo, subtipo, direcciones MAC, SSID, QoS, seguridad).
*   **`flow_analyzer.py`**:
    *   Clase `FlowAnalyzer`: Analiza flujos de red (secuencias de paquetes relacionados) para calcular métricas como duración, volumen de datos, y potencialmente identificar características de comunicación.
*   **`statistics_collector.py`**:
    *   Clase `StatisticsCollector`: Recopila y calcula estadísticas agregadas durante la sesión de análisis, como conteo total de paquetes, conteo por protocolo, marcas de tiempo de inicio/fin, duración, y tasas de datos.

#### 2.2.4. `ai_monitoring` (Módulo de Monitoreo con IA)

Contiene componentes para funcionalidades de análisis basadas en Inteligencia Artificial.

*   **`anomaly_detector.py`**:
    *   Clase `AnomalyDetector`: Implementa la lógica para detectar anomalías en el tráfico de red, potencialmente utilizando modelos de Machine Learning pre-entrenados.
*   **`qos_analyzer_ai.py`**: (Conceptual) Podría analizar la Calidad de Servicio (QoS) utilizando técnicas de IA.
*   **`feature_extractor.py`**: (Conceptual) Responsable de extraer características relevantes de los paquetes o flujos para alimentar los modelos de IA.

#### 2.2.5. `utils` (Módulo de Utilidades)

Proporciona funcionalidades de soporte utilizadas en todo el proyecto.

*   **`logging_config.py`**:
    *   Función `setup_logging`: Configura el sistema de logging centralizado para la aplicación.
*   **`config_manager.py`**:
    *   Clase `ConfigManager`: Maneja la carga y el acceso a las configuraciones de la aplicación desde `config/settings.yaml`.
*   **`helpers.py`**: Contiene funciones de ayuda diversas y utilidades generales.

#### 2.2.6. `storage` (Módulo de Almacenamiento)

Gestiona la persistencia de los datos y resultados del análisis.

*   **`database_handler.py`**:
    *   Clase `DatabaseHandler`: Proporciona una interfaz para interactuar con una base de datos (ej. SQLite) para almacenar y recuperar resultados de análisis detallados o estadísticas. Su uso puede ser opcional según la configuración.

#### 2.2.7. `reporting` (Módulo de Reportes)

Responsable de generar reportes de los resultados del análisis.

*   **`report_generator.py`**:
    *   Clase `ReportGenerator`: Toma los datos procesados y las estadísticas para generar reportes en diferentes formatos (ej. JSON, consola, CSV).

### 2.3. `config` (Directorio de Configuración)

*   **`settings.yaml`**: Archivo de configuración principal de la aplicación, donde se definen parámetros como niveles de logging, interfaz de red por defecto, rutas a modelos de IA, configuración de la base de datos, etc.

### 2.4. `data` (Directorio de Datos)

Almacena datos utilizados o generados por la aplicación.

*   **`captures/`**: Para guardar capturas de red en formato PCAP.
*   **`models/`**: Para almacenar modelos de IA entrenados (ej. `.joblib`, `.onnx`).
*   **`reports/`**: Directorio por defecto para guardar los reportes generados.

### 2.5. `tests` (Directorio de Pruebas)

Contiene los tests unitarios y de integración para asegurar la correctitud y fiabilidad de los módulos.

*   `__init__.py`: Inicializador del paquete de pruebas.
*   `test_frame_capture.py`: Pruebas para el módulo de captura.
*   `test_frame_analysis.py`: Pruebas para los módulos de análisis (incluyendo analizadores específicos y colector de estadísticas).
*   `test_ai_monitoring.py`: Pruebas para los componentes de IA.
*   (Potencialmente otros archivos de prueba para `core`, `utils`, `storage`, `reporting`).
*   Utiliza `unittest` y `unittest.mock`.

### 2.6. `scripts` (Directorio de Scripts)

Contiene scripts auxiliares para desarrollo, mantenimiento, etc. (ej. el propio `setup.py` podría considerarse parte de esto en espíritu, aunque esté en la raíz).

### 2.7. `logs` (Directorio de Logs)

Directorio por defecto donde se almacenan los archivos de log generados por la aplicación, si la configuración de logging así lo especifica.

### 2.8. `docs` (Directorio de Documentación)

Contiene la documentación del proyecto.

*   `arquitectura.md`: Este archivo.
*   `manual_usuario.md`: Guía para el usuario final.

## 3. Flujo de Datos General

1.  **Inicio (`main.py`):**
    *   El usuario ejecuta la aplicación a través de la CLI.
    *   Se parsean los argumentos de la línea de comandos.
2.  **Configuración:**
    *   `ConfigManager` carga la configuración desde `settings.yaml`.
    *   `setup_logging` configura el sistema de logging basado en la configuración.
3.  **Inicialización del Motor:**
    *   Se crea una instancia de `AnalysisEngine`.
    *   El motor inicializa sus componentes: `FrameCapture`, analizadores (cargados dinámicamente o predefinidos), `StatisticsCollector`, `ReportGenerator`, y opcionalmente `DatabaseHandler`.
4.  **Ejecución del Análisis:**
    *   Si se especifica un archivo PCAP (`--read`), el `AnalysisEngine` llama a `run_pcap_analysis`.
        *   `FrameCapture.read_pcap()` lee los paquetes.
    *   Si se especifica una interfaz para captura en vivo (`--interface`), el `AnalysisEngine` llama a `run_live_capture`.
        *   `FrameCapture.start_capture()` (o `start_async_capture()`) inicia la captura en la interfaz.
    *   En ambos casos, `FrameCapture` utiliza el callback `AnalysisEngine._process_packet_callback` para cada paquete.
5.  **Procesamiento por Paquete (`AnalysisEngine._process_packet_callback`):**
    *   Se obtiene la marca de tiempo de captura.
    *   El paquete se pasa a cada analizador registrado (`ProtocolAnalyzer`, `IEEE802_3_Analyzer`, `IEEE802_11_Analyzer`, `FlowAnalyzer`, `AnomalyDetector`, etc.).
    *   Cada analizador procesa el paquete y devuelve un diccionario con los resultados de su análisis específico.
    *   Los resultados de todos los analizadores se fusionan en un único diccionario de `analysis_data` para ese paquete.
    *   `StatisticsCollector.process_packet_analysis()` actualiza las estadísticas generales con `analysis_data`.
    *   Opcionalmente, `analysis_data` (o un subconjunto) se envía al `DatabaseHandler` para persistencia.
    *   Los `analysis_data` se almacenan en memoria en el `AnalysisEngine` para el reporte final.
6.  **Finalización de la Captura/Lectura:**
    *   La captura se detiene (por conteo, timeout, Ctrl+C) o se llega al final del archivo PCAP.
7.  **Finalización del Análisis (`AnalysisEngine._finalize_run`):**
    *   Se obtienen las estadísticas finales del `StatisticsCollector`.
    *   `ReportGenerator.generate_report()` crea el reporte final utilizando los `analysis_data` acumulados y las estadísticas. El formato del reporte (consola, JSON, CSV) se basa en la configuración o argumentos CLI.
    *   El reporte se muestra o guarda.
8.  **Cierre (`AnalysisEngine.shutdown`):**
    *   Se liberan recursos (ej. cerrar conexión a la base de datos).
    *   La aplicación termina.

## 4. Dependencias Clave

*   **Scapy (>=2.5.0):** Biblioteca fundamental para la captura, manipulación y disección de paquetes.
*   **PyYAML:** Para leer archivos de configuración `.yaml`.
*   **Python Standard Library:** `logging`, `argparse`, `datetime`, `os`, `sys`, `unittest`, `json`, `csv`, `sqlite3` (opcional, para `DatabaseHandler`).
*   **(Opcional para IA)** `numpy`, `pandas`, `scikit-learn`, `tensorflow`/`torch`, `onnxruntime`.

## 5. Posibles Mejoras y Consideraciones Futuras

*   **Extensibilidad de Analizadores:** Mejorar el sistema para añadir fácilmente nuevos analizadores (ej. mediante un patrón de registro o plugins más formal).
*   **Interfaz Gráfica de Usuario (GUI) o Web UI:** Para una mayor usabilidad.
*   **Análisis de Rendimiento de Red Avanzado:** Expandir las métricas de rendimiento (ej. cálculo de RTT, jitter, pérdida de paquetes a partir del análisis de flujos).
*   **Mejorar la Modularidad:** Continuar refinando la separación de responsabilidades entre módulos.
*   **Documentación API:** Generar documentación automática de la API del código (ej. con Sphinx).
*   **Empaquetado y Distribución:** Mejorar el empaquetado para facilitar la instalación (ej. `pyproject.toml` y `build`).
*   **Pruebas de Integración y Rendimiento:** Añadir más pruebas de integración y pruebas de rendimiento para la captura y análisis bajo carga.
*   **Visualización de Datos:** Integrar herramientas o bibliotecas para la visualización de las estadísticas y resultados del análisis.

Este documento proporciona una visión general de la arquitectura actual y posibles direcciones para el futuro desarrollo de `networking_tester`.
