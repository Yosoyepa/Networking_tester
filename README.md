# Networking Tester

## 1. Descripción

**Networking Tester** es una herramienta de línea de comandos (CLI) diseñada para la captura, análisis y monitoreo de tráfico de red en entornos LAN/WLAN. Permite a los usuarios capturar paquetes en vivo desde interfaces de red o leerlos desde archivos PCAP. Posteriormente, analiza estos paquetes para extraer información relevante sobre protocolos, generar estadísticas detalladas, detectar anomalías (con capacidades opcionales de IA) y generar reportes en diversos formatos.

Este proyecto tiene como objetivo proporcionar una plataforma flexible y extensible para profesionales de redes, investigadores de seguridad y entusiastas que necesiten inspeccionar y comprender el comportamiento de la red.

## 2. Características Principales

*   **Captura de Paquetes:**
    *   Captura en vivo desde interfaces de red (Ethernet, WiFi).
    *   Lectura de paquetes desde archivos PCAP.
    *   Soporte para filtros de captura BPF.
    *   Modos de captura síncrono y asíncrono.
*   **Análisis Detallado:**
    *   Análisis de tramas Ethernet (IEEE 802.3).
    *   Análisis de tramas WiFi (IEEE 802.11), incluyendo detalles de cabeceras, SSID, QoS.
    *   Análisis de protocolos de red (IP) y transporte (TCP, UDP, ICMP).
    *   Identificación de puertos conocidos y servicios.
    *   Análisis de flujos de red.
    *   Extracción de información QoS (DSCP/TOS).
*   **Estadísticas y Reportes:**
    *   Recopilación de estadísticas agregadas (conteo de paquetes, por protocolo, duración, tasas).
    *   Generación de reportes en múltiples formatos: JSON, CSV y consola.
*   **Monitoreo con IA (Opcional/En Desarrollo):**
    *   Detección de anomalías en el tráfico de red.
    *   Capacidad para cargar y utilizar modelos de Machine Learning pre-entrenados.
*   **Configuración Flexible:**
    *   Gestión centralizada de la configuración a través de un archivo `settings.yaml`.
*   **Almacenamiento (Opcional):**
    *   Soporte para guardar resultados de análisis en una base de datos SQLite.
*   **Logging Detallado:**
    *   Sistema de logging configurable para facilitar la depuración y el seguimiento.

## 3. Estructura del Proyecto

El proyecto sigue una estructura modular para facilitar el desarrollo y mantenimiento:

*   **`networking_tester/`**: Directorio raíz del proyecto.
    *   **`main.py`**: Punto de entrada de la aplicación CLI.
    *   **`networking_tester/`**: Paquete principal con la lógica central.
        *   `core/`: Motor de análisis y orquestación.
        *   `capture/`: Módulo de captura de tramas.
        *   `analysis/`: Módulos analizadores de protocolos y estadísticas.
        *   `ai_monitoring/`: Componentes para funcionalidades de IA.
        *   `utils/`: Utilidades (configuración, logging).
        *   `storage/`: Manejo de base de datos.
        *   `reporting/`: Generación de reportes.
    *   `config/`: Archivos de configuración (ej. `settings.yaml`).
    *   `data/`: Datos utilizados o generados (capturas, modelos de IA, reportes).
    *   `docs/`: Documentación del proyecto (arquitectura, manual de usuario).
    *   `logs/`: Archivos de log.
    *   `tests/`: Pruebas unitarias y de integración.
*   **`requirements.txt`**: Dependencias del proyecto.
*   **`setup.py`**: Script de configuración inicial del proyecto.

(Consulta `docs/arquitectura.md` para una descripción detallada de la arquitectura).

## 4. Prerrequisitos

*   Python 3.8 o superior.
*   `pip` (manejador de paquetes de Python).
*   Dependencias listadas en `requirements.txt` (principalmente Scapy, PyYAML).
*   Para la captura en vivo, pueden ser necesarios privilegios de administrador (root/sudo).

## 5. Instalación

```bash
# 1. Clona el repositorio (si es necesario)
# git clone <URL_DEL_REPOSITORIO>
# cd networking_tester

# 2. Crea un entorno virtual (recomendado)
python -m venv venv

# 3. Activa el entorno virtual
# En Windows:
# venv\Scripts\activate
# En macOS/Linux:
# source venv/bin/activate

# 4. Instala las dependencias
pip install -r requirements.txt
```

## 6. Configuración

La configuración principal de `networking_tester` se gestiona a través del archivo `config/settings.yaml`. Puedes modificar este archivo para ajustar:

*   Niveles de logging y rutas de archivos de log.
*   Interfaz de red por defecto.
*   Puertos conocidos para análisis.
*   Formato de reporte por defecto y directorio de salida.
*   Habilitación y configuración de la base de datos.
*   Parámetros para la detección de anomalías (si está habilitada).

Consulta el archivo `config/settings.yaml` y `docs/manual_usuario.md` para más detalles.

## 7. Uso

Ejecuta la herramienta desde la línea de comandos usando `main.py`.

**Obtener ayuda sobre los comandos:**
```bash
python main.py --help
```

**Argumentos Principales:**

*   `-i, --interface INTERFACE`: Interfaz de red para captura en vivo (ej. `eth0`, `Wi-Fi`, `auto`).
*   `-c, --count COUNT`: Número de paquetes a capturar (0 para ilimitado).
*   `-t, --timeout TIMEOUT`: Detener captura después de N segundos.
*   `-r, --read PCAP_FILE`: Leer paquetes desde un archivo PCAP.
*   `-w, --write PCAP_FILE`: Guardar paquetes capturados a un archivo PCAP.
*   `-f, --filter FILTER`: Filtro BPF para la captura (ej. `'tcp port 80'`).
*   `--report-format {console,json,csv}`: Formato del reporte de salida.

**Ejemplos:**

1.  **Capturar 100 paquetes desde la interfaz por defecto y generar un reporte JSON:**
    ```bash
    python main.py -c 100 --report-format json
    ```

2.  **Capturar tráfico en `eth0` durante 60s, filtrando TCP, reporte en consola:**
    ```bash
    python main.py -i eth0 -t 60 -f "tcp" --report-format console
    ```

3.  **Leer desde `capture.pcap` y generar reporte CSV:**
    ```bash
    python main.py -r data/captures/capture.pcap --report-format csv
    ```

(Consulta `docs/manual_usuario.md` para más ejemplos y detalles).

## 8. Salida y Reportes

*   Los reportes se guardan por defecto en el directorio `reports/`.
*   Formatos disponibles: `json`, `csv`, `console`.
*   Los archivos de log se guardan en `logs/` (según configuración).

## 9. Desarrollo y Pruebas

*   El proyecto utiliza `unittest` para las pruebas.
*   Las pruebas se encuentran en el directorio `tests/`.
*   Ejecutar pruebas (ejemplo, desde el directorio raíz):
    ```bash
    python -m unittest discover tests
    ```

## 10. Posibles Mejoras Futuras

*   Interfaz Gráfica de Usuario (GUI) o Web UI.
*   Análisis de rendimiento de red más avanzado (RTT, jitter, pérdida).
*   Mejoras en la extensibilidad de los analizadores.
*   Visualización de datos y estadísticas.

(Consulta `docs/arquitectura.md` para más detalles sobre la visión a futuro).

## 11. Contribuciones

Las contribuciones son bienvenidas. Por favor, sigue las guías de estilo y envía Pull Requests al repositorio del proyecto (si aplica).

## 12. Licencia

MIT License

Copyright (c) 2025 Juan C Andrade Unigarro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
