# Manual de Usuario: networking_tester

## 1. Introducción

Bienvenido a `networking_tester`, una herramienta de línea de comandos diseñada para la captura y análisis de tráfico de red. Con `networking_tester`, puedes capturar paquetes en vivo desde una interfaz de red, leer paquetes desde archivos PCAP, analizar estos paquetes para extraer información detallada sobre protocolos, generar estadísticas de red y obtener reportes en varios formatos.

Este manual te guiará a través de la instalación, configuración y uso de `networking_tester`.

## 2. Instalación

### 2.1. Prerrequisitos

*   **Python:** Versión 3.8 o superior.
*   **Scapy:** Versión 2.5.0 o superior.
*   **PyYAML:** Versión 6.0 o superior.
*   Otras dependencias listadas en `requirements.txt`.
*   **Permisos:** Para la captura de paquetes en vivo, podrías necesitar privilegios de administrador o root, dependiendo de tu sistema operativo.

### 2.2. Pasos de Instalación

1.  **Clonar el Repositorio (si aplica):**
    Si has obtenido el código fuente desde un repositorio Git:
    ```bash
    git clone <https://github.com/Yosoyepa/Networking_tester.git>
    cd networking_tester
    ```

2.  **Crear un Entorno Virtual (Recomendado):**
    Es una buena práctica usar entornos virtuales para aislar las dependencias del proyecto.
    ```bash
    python -m venv venv
    ```

3.  **Activar el Entorno Virtual:**
    *   En Windows:
        ```bash
        venv\Scripts\activate
        ```
    *   En macOS/Linux:
        ```bash
        source venv/bin/activate
        ```

4.  **Instalar Dependencias:**
    Desde el directorio raíz del proyecto (`networking_tester`), ejecuta:
    ```bash
    pip install -r requirements.txt
    ```

## 3. Configuración

`networking_tester` utiliza un archivo de configuración centralizado ubicado en `config/settings.yaml`. Puedes modificar este archivo para ajustar el comportamiento de la herramienta.

Algunas configuraciones clave incluyen:

*   **`logging`**: Nivel de logging, formato y archivo de salida.
*   **`capture.default_interface`**: Interfaz de red por defecto para la captura en vivo (ej. `eth0`, `Wi-Fi`, o `auto` para que Scapy intente seleccionar una).
*   **`analysis.known_ports`**: Mapeo de puertos a nombres de servicios conocidos.
*   **`reporting.default_format`**: Formato de reporte por defecto (`json`, `csv`, `console`).
*   **`reporting.output_directory`**: Directorio donde se guardarán los reportes.
*   **`storage.database_enabled`**: Habilitar o deshabilitar el almacenamiento en base de datos.

Consulta el archivo `config/settings.yaml` para ver todas las opciones disponibles y sus descripciones.

## 4. Uso Básico

`networking_tester` se ejecuta desde la línea de comandos a través del script `main.py`.

Para ver todas las opciones disponibles, ejecuta:
```bash
python main.py --help
```

### 4.1. Argumentos Principales de la CLI

*   **`-i INTERFACE`, `--interface INTERFACE`**:
    Especifica la interfaz de red para la captura en vivo (ej. `eth0`, `en0`, `Wi-Fi`). Si se omite o se usa `auto`, se intentará usar la interfaz por defecto definida en `config/settings.yaml` o Scapy intentará seleccionar una.

*   **`-c COUNT`, `--count COUNT`**:
    Número de paquetes a capturar. El valor por defecto es `0`, lo que significa captura ilimitada hasta que se detenga manualmente (Ctrl+C) o por un timeout.

*   **`-t TIMEOUT`, `--timeout TIMEOUT`**:
    Detiene la captura después de `N` segundos.

*   **`-r PCAP_FILE`, `--read PCAP_FILE`**:
    Lee paquetes desde un archivo PCAP especificado en lugar de realizar una captura en vivo.

*   **`-w PCAP_FILE`, `--write PCAP_FILE`**:
    Guarda los paquetes capturados en un archivo PCAP. (Nota: Esta funcionalidad puede estar en desarrollo o tener integración limitada con el flujo principal del motor de análisis).

*   **`-f FILTER`, `--filter FILTER`**:
    Aplica un filtro de captura BPF (Berkeley Packet Filter) a la captura en vivo (ej. `'tcp port 80'`, `'host 192.168.1.100'`).

*   **`--report-format {console,json,csv}`**:
    Especifica el formato del reporte de salida, sobrescribiendo el valor por defecto del archivo de configuración.

### 4.2. Ejemplos de Comandos

1.  **Capturar 100 paquetes desde la interfaz por defecto y generar un reporte JSON:**
    ```bash
    python main.py -c 100 --report-format json
    ```

2.  **Capturar tráfico en la interfaz `eth0` durante 60 segundos, filtrando solo tráfico TCP, y mostrar el reporte en consola:**
    ```bash
    python main.py -i eth0 -t 60 -f "tcp" --report-format console
    ```

3.  **Leer paquetes desde un archivo `capture.pcap` y generar un reporte CSV:**
    ```bash
    python main.py -r data/captures/capture.pcap --report-format csv
    ```

4.  **Capturar paquetes en la interfaz `Wi-Fi`, guardar los primeros 50 paquetes en `output.pcap` (si la funcionalidad está completamente integrada):**
    ```bash
    python main.py -i Wi-Fi -c 50 -w data/captures/output.pcap
    ```

## 5. Salida y Reportes

Los reportes generados por `networking_tester` se guardan por defecto en el directorio `reports/` (configurable en `settings.yaml`). El nombre del archivo de reporte típicamente incluye una marca de tiempo para evitar sobrescrituras.

Los formatos de reporte soportados son:

*   **JSON (`.json`):** Un formato estructurado que contiene todos los datos analizados por paquete y las estadísticas generales. Ideal para procesamiento programático posterior.
*   **CSV (`.csv`):** Formato de valores separados por comas, útil para importar en hojas de cálculo. El contenido exacto puede variar.
*   **Consola:** Muestra un resumen de las estadísticas directamente en la terminal.

## 6. Funcionalidades Avanzadas (Visión General)

`networking_tester` está diseñado para ser extensible y puede incluir (o incluirá en el futuro) funcionalidades más avanzadas como:

*   **Análisis de Flujos:** Identificación y análisis de flujos de comunicación.
*   **Detección de Anomalías:** Potencialmente utilizando reglas o modelos de Machine Learning para identificar comportamientos inusuales en la red.
*   **Análisis Específico de WiFi (IEEE 802.11):** Extracción detallada de información de tramas WiFi.

Consulta la documentación de arquitectura (`docs/arquitectura.md`) para más detalles sobre los componentes internos.

## 7. Solución de Problemas (Básico)

*   **Error de Permisos en Captura en Vivo:**
    *   **Problema:** Recibes un error relacionado con permisos al intentar capturar paquetes.
    *   **Solución:** Ejecuta el script con privilegios de administrador (ej. `sudo python main.py` en Linux/macOS, o ejecutar la terminal como Administrador en Windows).

*   **Interfaz No Encontrada:**
    *   **Problema:** La interfaz especificada con `-i` no es reconocida.
    *   **Solución:** Verifica el nombre correcto de tus interfaces de red (ej. usando `ipconfig` en Windows, `ifconfig` o `ip addr` en Linux/macOS). Asegúrate de que la interfaz esté activa.

*   **Scapy No Instalado o Versión Incorrecta:**
    *   **Problema:** Errores de importación relacionados con Scapy.
    *   **Solución:** Asegúrate de haber activado tu entorno virtual y de que Scapy y sus dependencias estén instalados correctamente (`pip install -r requirements.txt`).

## 8. Contribuciones y Soporte

Para reportar bugs, solicitar nuevas funcionalidades o contribuir al proyecto, por favor consulta el repositorio del proyecto (si aplica) o contacta a los desarrolladores.

---

Gracias por usar `networking_tester`!
