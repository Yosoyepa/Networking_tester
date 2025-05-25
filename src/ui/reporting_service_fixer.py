#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para diagnosticar y reparar el flujo de procesamiento del pipeline de reportes
"""

import logging
import subprocess
import pika
import json
import time
import os
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

from src.ui.report_service_client import ReportServiceClient
from src.ui.docker_service_manager import DockerServiceManager

logger = logging.getLogger(__name__)

class ReportingServiceFixer:
    """
    Clase para diagnosticar y reparar problemas en el pipeline de generación de reportes
    """
    
    def __init__(self, config: Dict):
        """
        Inicializa el ReportingServiceFixer
        
        Args:
            config: Configuración de la aplicación
        """
        self.config = config
        self.docker_manager = DockerServiceManager()
        
        # Obtener configuración de RabbitMQ desde el config
        rabbitmq_config = config.get('rabbitmq', {})
        self.rabbitmq_host = rabbitmq_config.get('host', 'localhost')
        self.rabbitmq_port = rabbitmq_config.get('port', 5672)
        self.rabbitmq_user = rabbitmq_config.get('user')
        self.rabbitmq_password = rabbitmq_config.get('password')
        
        # Nombres de colas requeridas para el pipeline
        self.required_queues = [
            "raw_frames_queue",
            "parsed_packets_queue",
            "feature_vectors_queue",
            "ml_results_queue",
            "analysis_results_queue"
        ]
        
        # Servicios requeridos para el pipeline
        self.required_services = [
            "rabbitmq",
            "packet_parser",
            "feature_extractor",
            "core_analysis",
            "reporting_service"
        ]
        
    def diagnose_pipeline(self) -> Dict:
        """
        Ejecuta un diagnóstico completo del pipeline de reportes
        
        Returns:
            Un diccionario con los resultados del diagnóstico
        """
        diagnosis = {
            "status": "ok",
            "rabbitmq_connection": False,
            "docker_available": False,
            "docker_running": False,
            "queue_status": {},
            "service_status": {},
            "issues": [],
            "recommendations": []
        }
        
        # Verificar Docker
        diagnosis["docker_available"] = self.docker_manager.is_docker_available()
        if not diagnosis["docker_available"]:
            diagnosis["status"] = "warning"  # Cambiado de error a warning - puede funcionar parcialmente sin Docker
            diagnosis["issues"].append("Docker no está disponible en el sistema")
            diagnosis["recommendations"].append("Instale Docker y Docker Compose para funcionalidad completa")
            # Continue with the diagnosis instead of returning early
        
        diagnosis["docker_running"] = self.docker_manager.is_docker_running()
        if diagnosis["docker_available"] and not diagnosis["docker_running"]:
            diagnosis["status"] = "warning"  # Cambiado de error a warning
            diagnosis["issues"].append("Docker está instalado pero no está en ejecución")
            diagnosis["recommendations"].append("Inicie Docker Desktop y vuelva a ejecutar el diagnóstico")
            # Continue with the diagnosis instead of returning early
        
        # Verificar RabbitMQ sin depender de Docker
        try:
            # Crear cliente de RabbitMQ
            client = ReportServiceClient(
                host=self.rabbitmq_host,
                port=self.rabbitmq_port,
                username=self.rabbitmq_user,
                password=self.rabbitmq_password
            )
            
            # Intentar conectar
            connection_ok = client.connect()
            diagnosis["rabbitmq_connection"] = connection_ok
            
            if connection_ok:
                # Verificar colas necesarias
                pipeline_status = client.check_pipeline_status()
                diagnosis["queue_status"] = pipeline_status["details"]["queue_status"]
                
                # Verificar colas faltantes o sin consumidores
                missing_queues = []
                queues_without_consumers = []
                
                for queue in self.required_queues:
                    if queue not in pipeline_status["details"]["queue_status"]:
                        missing_queues.append(queue)
                    elif pipeline_status["details"]["queue_status"][queue].get("consumer_count", 0) == 0:
                        queues_without_consumers.append(queue)
                
                if missing_queues:
                    diagnosis["status"] = "warning" if diagnosis["status"] == "ok" else diagnosis["status"]
                    diagnosis["issues"].append(f"Las siguientes colas requeridas no existen: {', '.join(missing_queues)}")
                    if diagnosis["docker_available"] and diagnosis["docker_running"]:
                        diagnosis["recommendations"].append("Reinicie los servicios para crear las colas faltantes")
                    else:
                        diagnosis["recommendations"].append("Cree manualmente las colas faltantes o active Docker con los servicios")
                
                if queues_without_consumers:
                    diagnosis["status"] = "warning" if diagnosis["status"] == "ok" else diagnosis["status"]
                    diagnosis["issues"].append(f"Las siguientes colas no tienen consumidores: {', '.join(queues_without_consumers)}")
                    if diagnosis["docker_available"] and diagnosis["docker_running"]:
                        diagnosis["recommendations"].append("Asegúrese de que todos los servicios están en ejecución")
                    else:
                        diagnosis["recommendations"].append("Sin Docker, las colas no tendrán consumidores automáticamente")
            else:
                diagnosis["status"] = diagnosis["status"] if diagnosis["status"] == "error" else "error"
                diagnosis["issues"].append("No se pudo conectar a RabbitMQ")
                diagnosis["recommendations"].append("Verifique que RabbitMQ esté en ejecución y accesible")
        except Exception as e:
            diagnosis["status"] = diagnosis["status"] if diagnosis["status"] == "error" else "error"
            diagnosis["issues"].append(f"Error al conectar con RabbitMQ: {e}")
            diagnosis["recommendations"].append("Verifique la configuración de RabbitMQ y su estado")
        
        # Verificar estado de los servicios (solo si Docker está disponible)
        if diagnosis["docker_available"] and diagnosis["docker_running"]:
            success, services_info = self.docker_manager.check_reporting_services()
            diagnosis["service_status"] = services_info
            
            # Verificar servicios no iniciados
            services_not_running = []
            for service, status in services_info.items():
                if service not in ["queues", "queues_error"]:
                    if status != "running":
                        services_not_running.append(service)
            
            if services_not_running:
                diagnosis["status"] = "warning" if diagnosis["status"] == "ok" else diagnosis["status"]
                diagnosis["issues"].append(f"Los siguientes servicios no están en ejecución: {', '.join(services_not_running)}")
                diagnosis["recommendations"].append("Inicie los servicios faltantes")
        else:
            # Si Docker no está disponible, agregar información sobre qué servicios estarían faltando
            diagnosis["recommendations"].append("Sin Docker, los siguientes servicios no están disponibles:")
            for service in self.required_services:
                if service != "rabbitmq":  # Asumimos que RabbitMQ podría estar en ejecución localmente
                    diagnosis["recommendations"].append(f"- {service}")
        
        # Recomendación general si hay problemas
        if diagnosis["status"] != "ok":
            diagnosis["recommendations"].append("Ejecute la reparación automática para intentar resolver estos problemas")
        
        return diagnosis
    
    def fix_pipeline(self, diagnosis: Optional[Dict] = None) -> Dict:
        """
        Intenta reparar los problemas identificados en el pipeline
        
        Args:
            diagnosis: Resultados del diagnóstico (opcional, si no se proporciona se ejecutará uno nuevo)
            
        Returns:
            Un diccionario con los resultados de la reparación
        """
        if diagnosis is None:
            diagnosis = self.diagnose_pipeline()
            
        repair_result = {
            "status": "ok",
            "actions_taken": [],
            "successful_fixes": [],
            "failed_fixes": [],
            "recommendations": []
        }
        
        # Si Docker no está disponible, podemos intentar arreglar solo RabbitMQ
        docker_available = diagnosis.get("docker_available", False)
        docker_running = diagnosis.get("docker_running", False)
        docker_usable = docker_available and docker_running

        if not docker_usable:
            repair_result["actions_taken"].append("Docker no está disponible o no está en ejecución")
            repair_result["recommendations"].append("La arquitectura de microservicios requiere Docker para funcionar completamente")
            repair_result["recommendations"].append("Solo se intentarán correcciones limitadas relacionadas con RabbitMQ")
            
            # Aún así, podemos intentar crear colas faltantes si RabbitMQ está disponible
            if diagnosis.get("rabbitmq_connection", False):
                # Create missing queues
                missing_queues = []
                for queue in self.required_queues:
                    if queue not in diagnosis.get("queue_status", {}) or not diagnosis["queue_status"][queue].get("exists", False):
                        missing_queues.append(queue)
                
                if missing_queues:
                    repair_result["actions_taken"].append(f"Creando colas faltantes en RabbitMQ: {', '.join(missing_queues)}")
                    try:
                        # Create client for RabbitMQ
                        client = ReportServiceClient(
                            host=self.rabbitmq_host,
                            port=self.rabbitmq_port,
                            username=self.rabbitmq_user,
                            password=self.rabbitmq_password
                        )
                        
                        if client.connect():
                            for queue in missing_queues:
                                try:
                                    client.channel.queue_declare(queue=queue, durable=True)
                                    repair_result["successful_fixes"].append(f"Cola {queue} creada correctamente")
                                except Exception as e:
                                    repair_result["failed_fixes"].append(f"No se pudo crear la cola {queue}: {e}")
                            client.close()
                        else:
                            repair_result["failed_fixes"].append("No se pudo conectar a RabbitMQ para crear las colas")
                    except Exception as e:
                        repair_result["failed_fixes"].append(f"Error al crear colas: {e}")
                
                # Add recommendation for Docker
                repair_result["recommendations"].append("Instale Docker y ejecute los servicios para tener funcionalidad completa")
                repair_result["status"] = "warning"
                
                return repair_result
            else:
                repair_result["status"] = "error"
                repair_result["failed_fixes"].append("No se pudo conectar a RabbitMQ")
                repair_result["recommendations"].append("Verifique que RabbitMQ esté instalado y en ejecución")
                repair_result["recommendations"].append("Instale Docker y ejecute los servicios para tener funcionalidad completa")
                
                return repair_result
        
        # El resto del código permanece igual para cuando Docker está disponible
        # 1. Reiniciar servicios que no estén en ejecución
        services_to_restart = []
        for service, status in diagnosis["service_status"].items():
            if service not in ["queues", "queues_error"] and service in self.required_services:
                if status != "running":
                    services_to_restart.append(service)
        
        if services_to_restart:
            repair_result["actions_taken"].append(f"Reiniciando servicios: {', '.join(services_to_restart)}")
            
            for service in services_to_restart:
                try:
                    # Intentar reiniciar el servicio
                    cmd = f"cd {self.docker_manager.project_root} && docker-compose restart {service}"
                    result = subprocess.run(
                        cmd, 
                        shell=True,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        repair_result["successful_fixes"].append(f"Servicio {service} reiniciado correctamente")
                    else:
                        repair_result["status"] = "warning" if repair_result["status"] == "ok" else repair_result["status"]
                        repair_result["failed_fixes"].append(f"Error al reiniciar {service}: {result.stderr}")
                except Exception as e:
                    repair_result["status"] = "warning" if repair_result["status"] == "ok" else repair_result["status"]
                    repair_result["failed_fixes"].append(f"Error reiniciando {service}: {e}")
        
        # 2. Verificar si RabbitMQ está funcionando, si no, reiniciarlo específicamente
        if "rabbitmq" in self.required_services and not diagnosis["rabbitmq_connection"]:
            repair_result["actions_taken"].append("Reiniciando RabbitMQ")
            
            try:
                cmd = f"cd {self.docker_manager.project_root} && docker-compose restart rabbitmq"
                result = subprocess.run(
                    cmd, 
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    repair_result["successful_fixes"].append("RabbitMQ reiniciado correctamente")
                    
                    # Esperar a que RabbitMQ se inicie completamente
                    time.sleep(10)
                    
                    # Verificar conexión nuevamente
                    client = ReportServiceClient(
                        host=self.rabbitmq_host,
                        port=self.rabbitmq_port,
                        username=self.rabbitmq_user,
                        password=self.rabbitmq_password
                    )
                    
                    if client.connect():
                        repair_result["successful_fixes"].append("Conexión a RabbitMQ establecida después del reinicio")
                    else:
                        repair_result["status"] = "warning" if repair_result["status"] == "ok" else repair_result["status"]
                        repair_result["failed_fixes"].append("RabbitMQ reiniciado pero la conexión sigue fallando")
                else:
                    repair_result["status"] = "warning" if repair_result["status"] == "ok" else repair_result["status"]
                    repair_result["failed_fixes"].append(f"Error al reiniciar RabbitMQ: {result.stderr}")
            except Exception as e:
                repair_result["status"] = "warning" if repair_result["status"] == "ok" else repair_result["status"]
                repair_result["failed_fixes"].append(f"Error reiniciando RabbitMQ: {e}")
        
        # 3. Si hay colas faltantes o sin consumidores, reiniciar todos los servicios
        missing_queues = []
        queues_without_consumers = []
        
        if "queue_status" in diagnosis and diagnosis["queue_status"]:
            for queue in self.required_queues:
                if queue not in diagnosis["queue_status"]:
                    missing_queues.append(queue)
                elif diagnosis["queue_status"][queue].get("consumer_count", 0) == 0:
                    queues_without_consumers.append(queue)
        else:
            # Si no tenemos información de colas, asumimos que necesitamos reiniciar todo
            missing_queues = self.required_queues
        
        if missing_queues or queues_without_consumers:
            repair_result["actions_taken"].append("Reiniciando todos los servicios para restaurar el pipeline completo")
            
            try:
                # Primero detenemos todos los servicios
                cmd_down = f"cd {self.docker_manager.project_root} && docker-compose down"
                result_down = subprocess.run(
                    cmd_down, 
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result_down.returncode == 0:
                    repair_result["successful_fixes"].append("Todos los servicios detenidos correctamente")
                    
                    # Esperar un momento para asegurar que todo esté completamente detenido
                    time.sleep(5)
                    
                    # Iniciar todos los servicios
                    cmd_up = f"cd {self.docker_manager.project_root} && docker-compose up -d"
                    result_up = subprocess.run(
                        cmd_up, 
                        shell=True,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result_up.returncode == 0:
                        repair_result["successful_fixes"].append("Todos los servicios iniciados correctamente")
                        
                        # Esperar a que los servicios estén disponibles
                        repair_result["actions_taken"].append("Esperando a que los servicios inicialicen (30 segundos)...")
                        time.sleep(30)
                    else:
                        repair_result["status"] = "error"
                        repair_result["failed_fixes"].append(f"Error al iniciar servicios: {result_up.stderr}")
                else:
                    repair_result["status"] = "error"
                    repair_result["failed_fixes"].append(f"Error al detener servicios: {result_down.stderr}")
            except Exception as e:
                repair_result["status"] = "error"
                repair_result["failed_fixes"].append(f"Error reiniciando servicios: {e}")
        
        # 4. Verificar estado final
        final_diagnosis = self.diagnose_pipeline()
        
        if final_diagnosis["status"] == "ok":
            repair_result["status"] = "ok"
            repair_result["successful_fixes"].append("Pipeline de reportes reparado correctamente")
        else:
            repair_result["status"] = "warning" if len(repair_result["failed_fixes"]) == 0 else "error"
            repair_result["recommendations"].append("Algunos problemas no pudieron ser resueltos automáticamente")
            repair_result["recommendations"].append("Verifique los logs de los servicios para más detalles")
            repair_result["recommendations"].append("Considere reiniciar Docker completamente y volver a intentarlo")
        
        return repair_result

def fix_reporting_pipeline(config) -> None:
    """
    Función principal para diagnosticar y reparar el pipeline de reportes desde la CLI
    
    Args:
        config: Configuración de la aplicación
    """
    print("\n=== Diagnóstico y Reparación del Pipeline de Reportes ===")
    fixer = ReportingServiceFixer(config)
    
    print("\nEjecutando diagnóstico del pipeline de reportes...")
    diagnosis = fixer.diagnose_pipeline()
    
    # Mostrar resultados del diagnóstico
    status_icon = "✅" if diagnosis["status"] == "ok" else "⚠️" if diagnosis["status"] == "warning" else "❌"
    print(f"\n{status_icon} Estado del pipeline: {diagnosis['status'].upper()}")
    
    # Check Docker availability first
    docker_available = diagnosis.get("docker_available", False)
    docker_running = diagnosis.get("docker_running", False)
    
    if not docker_available:
        print("\n❗ Docker no está disponible en este sistema.")
        print("La funcionalidad completa del pipeline requiere Docker y Docker Compose.")
        print("Sin Docker, solo se pueden realizar reparaciones limitadas en las colas de RabbitMQ.")
    elif not docker_running:
        print("\n❗ Docker está instalado pero no está en ejecución.")
        print("Inicie Docker Desktop para poder aprovechar todas las funciones de reparación.")
    
    # Check RabbitMQ connection
    rabbitmq_connected = diagnosis.get("rabbitmq_connection", False)
    if not rabbitmq_connected:
        print("\n❌ No se pudo conectar a RabbitMQ.")
        print("Verifique que RabbitMQ esté en ejecución y accesible.")
    
    # Mostrar problemas encontrados
    if diagnosis["issues"]:
        print("\nProblemas encontrados:")
        for issue in diagnosis["issues"]:
            issue_icon = "❌" if "error" in issue.lower() else "⚠️"
            print(f"{issue_icon} {issue}")
    else:
        print("\n✅ No se encontraron problemas en el pipeline de reportes.")
        return  # Si no hay problemas, terminamos aquí
    
    # Mostrar recomendaciones
    if diagnosis["recommendations"]:
        print("\nRecomendaciones:")
        for rec in diagnosis["recommendations"]:
            print(f"📝 {rec}")
    
    # Show repair options based on diagnosis
    print("\nOpciones de reparación:")
    
    if not docker_available or not docker_running:
        print("1. Reparación limitada (solo colas de RabbitMQ)")
        print("2. Ver cómo habilitar Docker")
        print("3. Generar un reporte con datos de muestra")
        print("4. Volver al menú")
    else:
        print("1. Reparación automática completa")
        print("2. Reiniciar solo servicios específicos")
        print("3. Generar un reporte con datos de muestra")
        print("4. Volver al menú")
    
    choice = input("\nIngrese su opción (1-4): ").strip()
    
    if choice == "2" and not docker_available or not docker_running:
        print("\n=== Instrucciones para habilitar Docker ===")
        print("1. Instale Docker Desktop desde https://www.docker.com/products/docker-desktop/")
        print("2. Asegúrese de que Docker Desktop esté en ejecución")
        print("3. Ejecute nuevamente el diagnóstico del pipeline")
        print("\nSi Docker ya está instalado pero no está en ejecución:")
        print("1. Abra Docker Desktop")
        print("2. Espere a que inicie completamente")
        print("3. Ejecute nuevamente el diagnóstico del pipeline")
        input("\nPresione Enter para continuar...")
        return
    
    elif choice == "2" and docker_available and docker_running:
        # Reiniciar servicios específicos
        print("\n=== Reinicio de servicios específicos ===")
        print("Seleccione los servicios a reiniciar:")
        services = ["rabbitmq", "packet_parser", "feature_extractor", "core_analysis", "reporting_service"]
        
        for i, service in enumerate(services, 1):
            print(f"{i}. {service}")
        print(f"{len(services) + 1}. Todos los servicios")
        print(f"{len(services) + 2}. Cancelar")
        
        service_choice = input("\nIngrese su opción (1-7): ").strip()
        
        try:
            choice_num = int(service_choice)
            if choice_num < 1 or choice_num > len(services) + 2:
                print("Opción inválida. Volviendo al menú principal.")
                return
                
            if choice_num == len(services) + 2:  # Cancelar
                print("Operación cancelada. Volviendo al menú principal.")
                return
                
            from src.ui.docker_service_manager import DockerServiceManager
            docker_manager = DockerServiceManager()
            
            if choice_num == len(services) + 1:  # Reiniciar todos los servicios
                print("\nReiniciando todos los servicios Docker...")
                success, message = docker_manager.restart_services()
                if success:
                    print(f"\n✅ {message}")
                else:
                    print(f"\n❌ {message}")
            else:
                # Reiniciar servicio específico
                service_to_restart = services[choice_num - 1]
                print(f"\nReiniciando servicio {service_to_restart}...")
                
                cmd = f"cd {docker_manager.project_root} && docker-compose restart {service_to_restart}"
                import subprocess
                result = subprocess.run(
                    cmd, 
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    print(f"\n✅ Servicio {service_to_restart} reiniciado correctamente")
                else:
                    print(f"\n❌ Error al reiniciar {service_to_restart}: {result.stderr}")
        except ValueError:
            print("Entrada inválida. Volviendo al menú principal.")
            return
            
    elif choice == "3":
        # Generar reporte con datos de muestra
        print("\nGenerando reporte con datos de muestra...")
        from src.ui.report_service_client import process_reports
        process_reports(config, force_sample=True)
        return
        
    elif choice == "4" or choice not in ["1", "2", "3", "4"]:
        print("\nVolviendo al menú principal sin realizar cambios.")
        return
    
    if choice == "1":
        print("\nIniciando reparación del pipeline de reportes...")
        repair_result = fixer.fix_pipeline(diagnosis)
        
        # Mostrar acciones realizadas
        print("\nAcciones realizadas:")
        for action in repair_result["actions_taken"]:
            print(f"🔧 {action}")
        
        # Mostrar éxitos
        if repair_result["successful_fixes"]:
            print("\nReparaciones exitosas:")
            for fix in repair_result["successful_fixes"]:
                print(f"✅ {fix}")
        
        # Mostrar fallos
        if repair_result["failed_fixes"]:
            print("\nReparaciones fallidas:")
            for fix in repair_result["failed_fixes"]:
                print(f"❌ {fix}")
        
        # Mostrar estado final y recomendaciones
        status_icon = "✅" if repair_result["status"] == "ok" else "⚠️" if repair_result["status"] == "warning" else "❌"
        print(f"\n{status_icon} Estado final de la reparación: {repair_result['status'].upper()}")
        
        if repair_result["recommendations"]:
            print("\nRecomendaciones adicionales:")
            for rec in repair_result["recommendations"]:
                print(f"📝 {rec}")
        
        if repair_result["status"] == "ok":
            print("\n✅ El pipeline de reportes ha sido reparado correctamente.")
            print("\n¿Desea intentar generar un reporte para probar la reparación?")
            print("1. Sí, generar un reporte")
            print("2. No, volver al menú")
            
            test_choice = input("\nIngrese su opción (1-2): ").strip()
            if test_choice == "1":
                from src.ui.report_service_client import process_reports
                process_reports(config, force_sample=False)
        else:
            print("\n⚠️ La reparación automática no pudo resolver todos los problemas.")
            print("\n¿Desea generar un reporte con datos de muestra?")
            print("1. Sí, generar reporte con datos de muestra")
            print("2. No, volver al menú")
            
            sample_choice = input("\nIngrese su opción (1-2): ").strip()
            if sample_choice == "1":
                from src.ui.report_service_client import process_reports
                process_reports(config, force_sample=True)
    
    input("\nPresione Enter para continuar...")

if __name__ == "__main__":
    # Para pruebas directas
    from src.utils.logging_config import setup_logging
    from src.ui.menu_handler import load_app_config
    
    setup_logging()
    config = load_app_config()
    fix_reporting_pipeline(config)
