#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Módulo para administrar los servicios Docker de la plataforma"""

import logging
import subprocess
import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import json

logger = logging.getLogger(__name__)

class DockerServiceManager:
    """
    Clase para administrar los servicios Docker de la arquitectura de microservicios.
    Permite iniciar, detener, verificar estado y ver logs de los servicios.
    """
    
    def __init__(self, project_root: Optional[str] = None):
        """
        Inicializa el gestor de servicios Docker
        
        Args:
            project_root: Ruta raíz del proyecto donde se encuentra el docker-compose.yml
        """
        if project_root:
            self.project_root = Path(project_root)
        else:
            # Asume que estamos en src/ui/ y subimos tres niveles
            self.project_root = Path(__file__).resolve().parent.parent.parent
            
        self.compose_file = self.project_root / "docker-compose.yml"
        
    def is_docker_available(self) -> bool:
        """
        Verifica si Docker está disponible en el sistema
        
        Returns:
            True si Docker está disponible, False en caso contrario
        """
        try:
            if sys.platform == "win32":
                cmd = "where docker"
            else:
                cmd = "which docker"
                
            result = subprocess.run(
                cmd,
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error verificando disponibilidad de Docker: {e}")
            return False
            
    def is_docker_running(self) -> bool:
        """
        Verifica si Docker está en ejecución
        
        Returns:
            True si Docker está ejecutándose, False en caso contrario
        """
        try:
            if sys.platform == "win32":
                # En Windows, verificamos si el proceso Docker Desktop está ejecutándose
                cmd = "powershell -Command \"Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue\""
            else:
                # En Linux, verificamos el estado del servicio Docker
                cmd = "systemctl is-active docker"
                
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error verificando si Docker está en ejecución: {e}")
            return False
            
    def is_compose_file_valid(self) -> bool:
        """
        Verifica si el archivo docker-compose.yml existe y es válido
        
        Returns:
            True si el archivo existe y es válido, False en caso contrario
        """
        if not self.compose_file.exists():
            logger.error(f"El archivo docker-compose.yml no existe en {self.project_root}")
            return False
            
        try:
            cmd = f"cd {self.project_root} && docker-compose config"
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"El archivo docker-compose.yml no es válido: {result.stderr}")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Error verificando validez del archivo docker-compose.yml: {e}")
            return False
            
    def start_services(self) -> Tuple[bool, str]:
        """
        Inicia todos los servicios definidos en docker-compose.yml
        
        Returns:
            Tupla (éxito, mensaje)
        """
        if not self.is_docker_available():
            return False, "Docker no está disponible en el sistema"
            
        if not self.is_docker_running():
            return False, "Docker no está en ejecución. Inicie Docker Desktop y vuelva a intentarlo"
            
        if not self.is_compose_file_valid():
            return False, "El archivo docker-compose.yml no es válido"
            
        try:
            logger.info("Iniciando servicios Docker...")
            cmd = f"cd {self.project_root} && docker-compose up -d"
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                return True, "Servicios iniciados correctamente"
            else:
                logger.error(f"Error al iniciar servicios: {result.stderr}")
                return False, f"Error al iniciar servicios: {result.stderr}"
        except Exception as e:
            logger.error(f"Excepción al iniciar servicios: {e}")
            return False, f"Error: {e}"
            
    def stop_services(self) -> Tuple[bool, str]:
        """
        Detiene todos los servicios
        
        Returns:
            Tupla (éxito, mensaje)
        """
        if not self.is_docker_available():
            return False, "Docker no está disponible en el sistema"
            
        if not self.is_docker_running():
            return False, "Docker no está en ejecución"
            
        try:
            logger.info("Deteniendo servicios Docker...")
            cmd = f"cd {self.project_root} && docker-compose down"
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                return True, "Servicios detenidos correctamente"
            else:
                logger.error(f"Error al detener servicios: {result.stderr}")
                return False, f"Error al detener servicios: {result.stderr}"
        except Exception as e:
            logger.error(f"Excepción al detener servicios: {e}")
            return False, f"Error: {e}"
            
    def restart_services(self) -> Tuple[bool, str]:
        """
        Reinicia todos los servicios
        
        Returns:
            Tupla (éxito, mensaje)
        """
        success, msg = self.stop_services()
        if not success:
            return False, f"Error al detener servicios: {msg}"
            
        # Pequeña pausa para permitir que todos los contenedores se detengan completamente
        import time
        time.sleep(3)
        
        return self.start_services()
        
    def get_service_status(self) -> Tuple[bool, str, List[Dict]]:
        """
        Obtiene el estado de los servicios
        
        Returns:
            Tupla (éxito, mensaje, lista de información de servicios)
        """
        if not self.is_docker_available():
            return False, "Docker no está disponible en el sistema", []
            
        if not self.is_docker_running():
            return False, "Docker no está en ejecución", []
            
        try:
            cmd = f"cd {self.project_root} && docker-compose ps"
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                # Parse the output
                lines = result.stdout.strip().split('\n')
                services = []
                
                # Simple parsing de la salida (podría mejorarse para diferentes formatos)
                if len(lines) > 1:  # Al menos un servicio (más la cabecera)
                    return True, "Estado de servicios obtenido correctamente", result.stdout
                else:
                    return True, "No hay servicios en ejecución", []
            else:
                logger.error(f"Error al obtener estado de servicios: {result.stderr}")
                return False, f"Error al obtener estado de servicios: {result.stderr}", []
        except Exception as e:
            logger.error(f"Excepción al obtener estado de servicios: {e}")
            return False, f"Error: {e}", []
            
    def get_service_logs(self, service_name: str = None, tail: int = 100) -> Tuple[bool, str]:
        """
        Obtiene los logs de un servicio específico o de todos los servicios
        
        Args:
            service_name: Nombre del servicio para obtener logs, None para todos
            tail: Número de líneas a mostrar
            
        Returns:
            Tupla (éxito, contenido de los logs)
        """
        if not self.is_docker_available():
            return False, "Docker no está disponible en el sistema"
            
        if not self.is_docker_running():
            return False, "Docker no está en ejecución"
            
        try:
            cmd = f"cd {self.project_root} && docker-compose logs --tail={tail}"
            if service_name:
                cmd += f" {service_name}"
                
            result = subprocess.run(
                cmd, 
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                logger.error(f"Error al obtener logs: {result.stderr}")
                return False, f"Error al obtener logs: {result.stderr}"
        except Exception as e:
            logger.error(f"Excepción al obtener logs: {e}")
            return False, f"Error: {e}"
            
    def check_reporting_services(self) -> Tuple[bool, Dict[str, str]]:
        """
        Checks the status of reporting-related services specifically
        
        Returns:
            Tuple containing (success flag, dictionary of service health details)
        """
        if not self.is_docker_available() or not self.is_docker_running():
            return False, {"error": "Docker is not available or not running"}
            
        try:
            report_services = {
                "packet_parser": "unknown",
                "feature_extractor": "unknown",
                "core_analysis": "unknown", 
                "reporting_service": "unknown",
                "rabbitmq": "unknown"
            }
            
            # Check each service
            for service_name in report_services.keys():
                cmd = f"cd {self.project_root} && docker-compose ps {service_name} --format json"
                result = subprocess.run(
                    cmd, 
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        # Try to parse as JSON (newer docker-compose versions)
                        service_info = json.loads(result.stdout)
                        if isinstance(service_info, list) and len(service_info) > 0:
                            service_info = service_info[0]  # Get the first item if it's a list
                        
                        state = service_info.get("State", "unknown")
                        report_services[service_name] = state
                    except json.JSONDecodeError:
                        # Fall back to parsing the text output for older docker-compose versions
                        if "running" in result.stdout.lower():
                            report_services[service_name] = "running"
                        elif "exited" in result.stdout.lower() or "stopped" in result.stdout.lower():
                            report_services[service_name] = "exited"
                        elif "restarting" in result.stdout.lower():
                            report_services[service_name] = "restarting"
                        else:
                            report_services[service_name] = "unknown"
                else:
                    # Service might not be created or docker-compose has an error
                    report_services[service_name] = "not created"
            
            # Check if RabbitMQ queues are properly set up
            if report_services["rabbitmq"] == "running":
                try:
                    # Check for RabbitMQ management API availability
                    cmd = f"docker exec $(docker-compose -f {self.project_root}/docker-compose.yml ps -q rabbitmq) rabbitmqctl list_queues"
                    result = subprocess.run(
                        cmd, 
                        shell=True,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=5  # Add timeout to prevent long waits
                    )
                    
                    if result.returncode == 0:
                        # Parse output to find required queues
                        queue_lines = result.stdout.strip().split('\n')
                        queues_found = []
                        
                        for line in queue_lines:
                            if line.strip():
                                parts = line.strip().split()
                                if len(parts) > 0:
                                    queue_name = parts[0]
                                    # Check if this is one of our important queues
                                    if queue_name in ["raw_frames_queue", "parsed_packets_queue", 
                                                     "feature_vectors_queue", "analysis_results_queue"]:
                                        queues_found.append(queue_name)
                        
                        # Add queues info to the result
                        report_services["queues"] = queues_found
                except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                    report_services["queues_error"] = str(e)
            
            # Determine overall status based on service states
            all_running = all(status == "running" for service, status in report_services.items() 
                             if service != "queues" and service != "queues_error")
            
            return all_running, report_services
            
        except Exception as e:
            logger.error(f"Error checking reporting services: {e}", exc_info=True)
            return False, {"error": str(e)}
            
def manage_docker_services(config):
    """
    Función de interfaz para administrar servicios Docker desde la CLI
    
    Args:
        config: Configuración de la aplicación
    """
    manager = DockerServiceManager()
    
    # Verificar disponibilidad de Docker
    if not manager.is_docker_available():
        print("\nError: Docker no está disponible en el sistema.")
        print("Asegúrese de que Docker esté instalado y en su PATH.")
        return
    
    # Verificar si Docker está en ejecución
    if not manager.is_docker_running():
        print("\nError: Docker no está en ejecución.")
        print("Inicie Docker Desktop y vuelva a intentarlo.")
        return
        
    # Menú de opciones
    while True:
        print("\n=== Gestión de Servicios Docker ===")
        print("1. Iniciar todos los servicios")
        print("2. Detener todos los servicios")
        print("3. Reiniciar todos los servicios")
        print("4. Ver estado de los servicios")
        print("5. Ver logs de los servicios")
        print("6. Diagnosticar pipeline de reportes")
        print("7. Reiniciar pipeline de reportes")
        print("8. Volver al menú principal")
        
        try:
            choice = input("Ingrese su opción (1-8): ").strip()
            
            if choice == "1":
                print("\nIniciando servicios Docker... Esto puede tardar unos momentos.")
                success, message = manager.start_services()
                if success:
                    print("\n✅ " + message)
                    print("Los servicios pueden tardar un momento en inicializarse completamente.")
                    print("Use la opción '5. Ver logs de los servicios' para monitorear el progreso.")
                else:
                    print("\n❌ " + message)
                    
            elif choice == "2":
                print("\nDeteniendo servicios Docker...")
                success, message = manager.stop_services()
                if success:
                    print("\n✅ " + message)
                else:
                    print("\n❌ " + message)
                    
            elif choice == "3":
                print("\nReiniciando servicios Docker... Esto puede tardar unos momentos.")
                success, message = manager.restart_services()
                if success:
                    print("\n✅ " + message)
                    print("Los servicios pueden tardar un momento en inicializarse completamente.")
                    print("Use la opción '5. Ver logs de los servicios' para monitorear el progreso.")
                else:
                    print("\n❌ " + message)
                    
            elif choice == "4":
                print("\nObteniendo estado de los servicios Docker...")
                success, message, output = manager.get_service_status()
                if success:
                    print("\n" + output if isinstance(output, str) else message)
                else:
                    print("\n❌ " + message)
                    
            elif choice == "5":
                service_name = input("\nIngrese el nombre del servicio para ver logs (ej: rabbitmq, reporting_service),\n"
                                    "o presione Enter para ver logs de todos los servicios: ").strip()
                
                print(f"\nMostrando logs para {'todos los servicios' if not service_name else service_name}...")
                print("(Presione Ctrl+C para salir de la vista de logs)\n")
                
                try:
                    success, logs = manager.get_service_logs(service_name)
                    if success:
                        print(logs)
                    else:
                        print("\n❌ " + logs)
                except KeyboardInterrupt:
                    print("\nSalida de la vista de logs.")
            
            elif choice == "6":
                print("\nDiagnosticando pipeline de reportes...")
                success, services_info = manager.check_reporting_services()
                
                if "error" in services_info:
                    print(f"\n❌ Error: {services_info['error']}")
                else:
                    print("\n=== Estado del Pipeline de Reportes ===")
                    
                    # Print service status with color-coded indicators
                    for service, status in services_info.items():
                        if service not in ["queues", "queues_error"]:
                            status_symbol = "✅" if status == "running" else "⚠️" if status == "restarting" else "❌"
                            print(f"{status_symbol} {service}: {status}")
                    
                    # Print queue information
                    print("\n--- Colas de RabbitMQ ---")
                    if "queues" in services_info:
                        if not services_info["queues"]:
                            print("⚠️ No se encontraron colas configuradas para el pipeline de reportes")
                        else:
                            print("Colas encontradas:")
                            for queue in services_info["queues"]:
                                print(f"✅ {queue}")
                            
                            # Check for missing queues
                            expected_queues = ["raw_frames_queue", "parsed_packets_queue", 
                                             "feature_vectors_queue", "analysis_results_queue"]
                            missing_queues = [q for q in expected_queues if q not in services_info["queues"]]
                            
                            if missing_queues:
                                print("\n⚠️ Colas esperadas que no fueron encontradas:")
                                for queue in missing_queues:
                                    print(f"- {queue}")
                    elif "queues_error" in services_info:
                        print(f"❌ Error al consultar colas: {services_info['queues_error']}")
                    
                    # Overall status
                    if success:
                        print("\n✅ Todos los servicios necesarios para el pipeline de reportes están en ejecución.")
                    else:
                        print("\n⚠️ Hay problemas con uno o más servicios del pipeline de reportes.")
                        print("Puede intentar reiniciar el pipeline con la opción 7.")
            
            elif choice == "7":
                print("\nReiniciando servicios del pipeline de reportes...")
                
                # Create a list of reporting pipeline services
                report_services = ["rabbitmq", "packet_parser", "feature_extractor", 
                                  "core_analysis", "reporting_service"]
                
                # First check if the services are currently running
                success, services_info = manager.check_reporting_services()
                
                # For each service that's not running, try to restart it
                for service in report_services:
                    if service in services_info and services_info[service] != "running":
                        print(f"Reiniciando {service}...")
                        
                        # Run docker-compose restart for the specific service
                        cmd = f"cd {manager.project_root} && docker-compose restart {service}"
                        result = subprocess.run(
                            cmd, 
                            shell=True,
                            check=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        
                        if result.returncode == 0:
                            print(f"✅ Servicio {service} reiniciado correctamente")
                        else:
                            print(f"❌ Error al reiniciar {service}: {result.stderr}")
                
                # Check final status after restart attempts
                print("\nVerificando estado final después de reinicio...")
                success, final_services_info = manager.check_reporting_services()
                
                if success:
                    print("\n✅ Pipeline de reportes reiniciado correctamente.")
                else:
                    print("\n⚠️ El pipeline de reportes aún tiene problemas después del reinicio.")
                    print("Intente reiniciar todos los servicios con la opción 3 o revise los logs con la opción 5.")
            
            elif choice == "8":
                break
                
            else:
                print("Opción inválida. Intente de nuevo.")
                
        except KeyboardInterrupt:
            print("\nVolviendo al menú principal...")
            break
        except Exception as e:
            logger.error(f"Error en la gestión de servicios Docker: {e}", exc_info=True)
            print(f"\nError: {e}")

if __name__ == "__main__":
    # Para pruebas directas
    logging.basicConfig(level=logging.INFO)
    manager = DockerServiceManager()
    
    # Verificar disponibilidad de Docker
    print(f"Docker disponible: {manager.is_docker_available()}")
    
    # Verificar si Docker está en ejecución
    print(f"Docker en ejecución: {manager.is_docker_running()}")
    
    # Verificar validez del archivo docker-compose.yml
    print(f"Archivo docker-compose.yml válido: {manager.is_compose_file_valid()}")
