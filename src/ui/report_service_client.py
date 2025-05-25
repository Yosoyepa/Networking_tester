#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Cliente para interactuar con el servicio de reportes"""

import logging
import pika
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import pika.exceptions

logger = logging.getLogger(__name__)

class ReportServiceClient:
    """
    Cliente para interactuar con el servicio de reportes en la arquitectura de microservicios.
    Permite solicitar reportes y procesar los resultados del análisis.
    """
    
    def __init__(self, 
                 host='localhost', 
                 port=5672, 
                 username=None, 
                 password=None,
                 exchange_name='analysis_results_exchange',
                 queue_name='analysis_results_queue',
                 routing_key='analysis_results_queue'):
        """Initialize the ReportServiceClient with connection information."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.exchange_name = exchange_name
        self.queue_name = queue_name
        self.routing_key = routing_key
        self.connection = None
        self.channel = None
        
    def connect(self):
        """Establish a connection to RabbitMQ."""
        try:
            connection_params = {
                'host': self.host,
                'port': self.port
            }
            if self.username and self.password:
                connection_params['credentials'] = pika.PlainCredentials(self.username, self.password)
            
            logger.debug(f"Conectando a RabbitMQ en {self.host}:{self.port}...")
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(**connection_params))
            self.channel = self.connection.channel()
            logger.info(f"Successfully connected to RabbitMQ at {self.host}:{self.port}")
            return True
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            return False
        
    def close(self):
        """Close the RabbitMQ connection."""
        if hasattr(self, 'connection') and self.connection and self.connection.is_open:
            self.connection.close()
            logger.info("RabbitMQ connection closed")
    
    def setup_channels(self):
        """Setup exchanges and queues"""
        try:
            # Declare exchange
            self.channel.exchange_declare(
                exchange=self.exchange_name,
                exchange_type='direct',
                durable=True
            )
            
            # Declare queue and bind to exchange
            self.channel.queue_declare(
                queue=self.queue_name, 
                durable=True
            )
            
            self.channel.queue_bind(
                exchange=self.exchange_name,
                queue=self.queue_name,
                routing_key=self.routing_key
            )
            
            logger.info(f"Exchange '{self.exchange_name}' and queue '{self.queue_name}' set up successfully")
            return True
        except Exception as e:
            logger.error(f"Error setting up channels: {e}")
            return False
    
    def get_messages(self, count: int = 10, peek_only: bool = True) -> List[Dict]:
        """
        Get messages from the analysis results queue
        
        Args:
            count: Maximum number of messages to retrieve
            peek_only: If True, don't remove messages from the queue
            
        Returns:
            A list of message dictionaries
        """
        messages = []
        
        if not self.connect():
            return [{"error": "Failed to connect to RabbitMQ"}]
        
        try:
            for _ in range(count):
                method_frame, header_frame, body = self.channel.basic_get(
                    queue=self.queue_name,
                    auto_ack=not peek_only
                )
                
                if method_frame:
                    try:
                        message_data = json.loads(body)
                        messages.append(message_data)
                    except json.JSONDecodeError:
                        messages.append({"error": "Non-JSON message", "raw": body[:100]})
                else:
                    break # No more messages
                    
            return messages
        except Exception as e:
            logger.error(f"Error getting messages: {e}")
            return [{"error": str(e)}]
        finally:
            self.close()
    def request_report(self, report_id: str, report_format: str = 'json', timeout: int = 30) -> Dict:
        """
        Request a report from the reporting service and wait for response
        
        Args:
            report_id: Unique identifier for the report request
            report_format: Format for the report output ('json', 'csv', 'console')
            timeout: Maximum time to wait for a response in seconds
            
        Returns:
            Response information dictionary
        """
        if not self.connect():
            return {"error": "Failed to connect to RabbitMQ", "status": "error", "recovery_possible": True}
        
        try:
            # Setup necessary channels
            if not self.setup_channels():
                return {"error": "Failed to setup message channels", "status": "error", "recovery_possible": True}
            
            # Create a request message
            request_message = {
                "request_id": report_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "action": "generate_report",
                "format": report_format,
                "client_id": f"cli_client_{int(time.time())}",  # Unique client ID
            }
            
            # Create a response queue for this specific request 
            result = self.channel.queue_declare(queue='', exclusive=True)
            callback_queue = result.method.queue
            
            # Set up a correlation ID for the request
            correlation_id = f"report_req_{report_id}_{int(time.time())}"
            
            # Variable to store the response
            response = None
            
            # Define a callback to process the response
            def on_response(ch, method, props, body):
                nonlocal response
                if props.correlation_id == correlation_id:
                    try:
                        response = json.loads(body)
                    except json.JSONDecodeError:
                        response = {"error": "Invalid JSON response from service", "raw": body[:100], "status": "error", "recovery_possible": False}
                    ch.basic_ack(delivery_tag=method.delivery_tag)
            
            # Set up a consumer for the response queue
            self.channel.basic_consume(
                queue=callback_queue,
                on_message_callback=on_response,
                auto_ack=False
            )
            
            # Publish request to reporting service
            try:
                self.channel.basic_publish(
                    exchange=self.exchange_name,
                    routing_key=self.routing_key,
                    properties=pika.BasicProperties(
                        reply_to=callback_queue,
                        correlation_id=correlation_id,
                        expiration=str(timeout * 1000)  # Convert to milliseconds
                    ),
                    body=json.dumps(request_message)
                )
                logger.info(f"Sent report request: {request_message}")
            except Exception as e:
                return {"error": f"Failed to publish request: {e}", "status": "error", "recovery_possible": True}
            
            # Wait for the response with a timeout
            start_time = time.time()
            while response is None and (time.time() - start_time) < timeout:
                # Process events for 0.5 seconds at a time
                try:
                    self.connection.process_data_events(time_limit=0.5)
                except Exception as e:
                    # If we lose connection while waiting
                    return {"error": f"Connection error while waiting for response: {e}", "status": "error", "recovery_possible": True}
                
            if response is None:
                return {
                    "error": f"Timeout waiting for response after {timeout} seconds",
                    "status": "timeout",
                    "recovery_possible": True,
                    "recommendations": [
                        "Check if reporting service is running",
                        "Try again with a longer timeout",
                        "Verify RabbitMQ connection and queues"
                    ]
                }
            
            return response
        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"AMQP connection error requesting report: {e}")
            return {"error": f"AMQP Connection Error: {e}", "status": "error", "recovery_possible": True}
        except Exception as e:
            logger.error(f"Error requesting report: {e}")
            return {"error": str(e), "status": "error", "recovery_possible": False}
        finally:
            self.close()
    
    def check_pipeline_status(self) -> Dict:
        """
        Check the status of the reporting pipeline services
        
        This method checks whether all necessary components of the reporting
        pipeline are functioning correctly.
        
        Returns:
            Dictionary with status information
        """
        if not self.connect():
            return {
                "status": "error", 
                "message": "Failed to connect to RabbitMQ", 
                "details": {
                    "rabbitmq_connection": False,
                    "queue_status": {},
                    "services": {}
                }
            }
        
        try:
            # Check if the necessary queues exist
            pipeline_status = {
                "status": "checking",
                "message": "Checking reporting pipeline status",
                "details": {
                    "rabbitmq_connection": True,
                    "queue_status": {},
                    "services": {}
                }
            }
            
            # List of queues to check
            queues_to_check = [
                "raw_frames_queue", 
                "parsed_packets_queue",
                "feature_vectors_queue", 
                "ml_results_queue",
                "analysis_results_queue"
            ]
            
            all_queues_ok = True
            missing_queues = []
            queues_without_consumers = []
            
            # Check each queue
            for queue_name in queues_to_check:
                try:
                    # Try to declare the queue passively (which will fail if it doesn't exist)
                    self.channel.queue_declare(queue=queue_name, passive=True)
                    
                    # Get queue info to check if it has consumers
                    queue_info = self.channel.queue_declare(queue=queue_name, passive=True)
                    message_count = queue_info.method.message_count
                    consumer_count = queue_info.method.consumer_count
                    
                    pipeline_status["details"]["queue_status"][queue_name] = {
                        "exists": True,
                        "message_count": message_count,
                        "consumer_count": consumer_count,
                        "status": "ok" if consumer_count > 0 else "warning"
                    }
                    
                    # If any queue has no consumers, mark it as a warning
                    if consumer_count == 0:
                        all_queues_ok = False
                        queues_without_consumers.append(queue_name)
                        
                except pika.exceptions.ChannelClosedByBroker as e:
                    # This likely means the queue doesn't exist
                    pipeline_status["details"]["queue_status"][queue_name] = {
                        "exists": False,
                        "error": f"Queue does not exist: {e}",
                        "status": "error"
                    }
                    all_queues_ok = False
                    missing_queues.append(queue_name)
                    
                    # Reconnect as ChannelClosedByBroker closes the channel
                    self.connect()
                    
                except Exception as e:
                    pipeline_status["details"]["queue_status"][queue_name] = {
                        "exists": False,
                        "error": str(e),
                        "status": "error"
                    }
                    all_queues_ok = False
                    missing_queues.append(queue_name)
            
            # Try to auto-create missing queues if needed
            if missing_queues:
                logger.info(f"Attempting to create missing queues: {missing_queues}")
                for queue_name in missing_queues:
                    try:
                        self.channel.queue_declare(queue=queue_name, durable=True)
                        logger.info(f"Successfully created queue: {queue_name}")
                        
                        # Update the status for this queue
                        pipeline_status["details"]["queue_status"][queue_name] = {
                            "exists": True,
                            "message_count": 0,
                            "consumer_count": 0,
                            "status": "warning",
                            "note": "Queue was auto-created but has no consumers"
                        }
                    except Exception as e:
                        logger.error(f"Failed to create queue '{queue_name}': {e}")
            
            # Check Docker service status if available
            try:
                from src.ui.docker_service_manager import DockerServiceManager
                docker_manager = DockerServiceManager()
                
                if docker_manager.is_docker_available() and docker_manager.is_docker_running():
                    # Check Docker services status
                    success, services_info = docker_manager.check_reporting_services()
                    pipeline_status["details"]["docker_available"] = True
                    pipeline_status["details"]["docker_running"] = True
                    pipeline_status["details"]["services"] = services_info
                    
                    # Check service health
                    all_services_ok = True
                    for service, status in services_info.items():
                        if service not in ["queues", "queues_error"] and status != "running":
                            all_services_ok = False
                    
                    # Update overall status based on services
                    if not all_services_ok:
                        all_queues_ok = False  # Services impact overall status
                        
                else:
                    pipeline_status["details"]["docker_available"] = docker_manager.is_docker_available()
                    pipeline_status["details"]["docker_running"] = docker_manager.is_docker_running()
                    logger.info("Docker is not available or not running")
            except ImportError:
                pipeline_status["details"]["docker_available"] = False
                pipeline_status["details"]["docker_running"] = False
                logger.info("DockerServiceManager not importable, Docker status check skipped")
            except Exception as e:
                logger.error(f"Error checking Docker status: {e}")
            
            # Overall pipeline status
            if all_queues_ok:
                pipeline_status["status"] = "ok"
                pipeline_status["message"] = "All reporting pipeline components are operational"
            else:
                if missing_queues:
                    # Auto-creation attempted, so we need to recheck
                    if any(not pipeline_status["details"]["queue_status"][q].get("exists", False) for q in queues_to_check):
                        pipeline_status["status"] = "error"
                        pipeline_status["message"] = "Some required queues are missing from the reporting pipeline"
                    else:
                        pipeline_status["status"] = "warning"
                        pipeline_status["message"] = "All queues exist but some may not have consumers"
                elif queues_without_consumers:
                    pipeline_status["status"] = "warning"
                    pipeline_status["message"] = "Some reporting pipeline queues don't have active consumers"
                else:
                    pipeline_status["status"] = "warning"
                    pipeline_status["message"] = "Some reporting pipeline components may not be functioning properly"
            
            return pipeline_status
        
        except Exception as e:
            logger.error(f"Error checking pipeline status: {e}")
            return {
                "status": "error", 
                "message": f"Error checking pipeline status: {e}", 
                "details": {
                    "rabbitmq_connection": True,
                    "error": str(e)
                }
            }
        finally:
            self.close()

def process_reports(config, force_sample: bool = False) -> None:
    """
    Utility function to process reports either from the queue or sample data.
    
    Args:
        config: Application configuration dictionary
        force_sample: If True, use sample data even if real data is available
        
    Returns:
        None
    """
    from src.reporting.report_generator import ReportGenerator
    from src.ui.docker_service_manager import DockerServiceManager
    
    # Get RabbitMQ config
    rabbitmq_config = config.get('rabbitmq', {})
    rabbitmq_host = rabbitmq_config.get('host', 'localhost')
    rabbitmq_port = rabbitmq_config.get('port', 5672)
    rabbitmq_user = rabbitmq_config.get('user')
    rabbitmq_password = rabbitmq_config.get('password')
    
    # Get queue info
    analysis_results_exchange = config.get('messaging_topics', {}).get('analysis_results_exchange', 'analysis_results_exchange')
    analysis_queue_name = config.get('messaging_topics', {}).get('analysis_results_queue', 'analysis_results_queue')
    
    # Ask for report format
    print("\nSeleccione el formato de reporte:")
    print("1. JSON")
    print("2. CSV")
    print("3. Console")
    try:
        format_choice = int(input("Ingrese su opción (1-3): "))
        if format_choice < 1 or format_choice > 3:
            print("Opción inválida. Usando formato por defecto.")
            format_choice = 0
    except ValueError:
        print("Entrada inválida. Usando formato por defecto.")
        format_choice = 0
    
    report_format = None
    if format_choice == 1:
        report_format = "json"
    elif format_choice == 2:
        report_format = "csv"
    elif format_choice == 3:
        report_format = "console"
    else:
        # Using default from config
        report_format = config.get('reporting', {}).get('default_format', 'json')
    
    # Check if Docker is available first
    docker_manager = DockerServiceManager()
    docker_available = docker_manager.is_docker_available() and docker_manager.is_docker_running()
    
    if not docker_available:
        print("\n⚠️ Docker no está disponible o no está en ejecución.")
        print("La arquitectura de microservicios requiere Docker para funcionar correctamente.")
        if not force_sample:
            print("\n¿Desea proceder con datos de muestra?")
            print("1. Sí, usar datos de muestra")
            print("2. No, intentar conectar directamente a RabbitMQ")
            try:
                option = int(input("Ingrese su opción (1-2): "))
                if option == 1:
                    force_sample = True
            except ValueError:
                print("Entrada inválida. Intentando conectar directamente a RabbitMQ.")
    
    # Create the report service client
    client = ReportServiceClient(
        host=rabbitmq_host,
        port=rabbitmq_port,
        username=rabbitmq_user,
        password=rabbitmq_password,
        exchange_name=analysis_results_exchange,
        queue_name=analysis_queue_name
    )
    
    # First, check if the reporting pipeline is functioning properly (only if not forcing sample)
    if not force_sample:
        print("\nVerificando el estado del pipeline de reportes...")
        pipeline_status = client.check_pipeline_status()
        
        if pipeline_status["status"] == "error":
            print(f"\n❌ Error: {pipeline_status['message']}")
            force_sample = handle_pipeline_error(pipeline_status)
                
        elif pipeline_status["status"] == "warning":
            print(f"\n⚠️ Advertencia: {pipeline_status['message']}")
            # Display specific details about the pipeline
            for queue, status in pipeline_status["details"]["queue_status"].items():
                status_symbol = "✅" if status["status"] == "ok" else "⚠️" if status["status"] == "warning" else "❌"
                print(f"  {status_symbol} Cola {queue}: {'Existe' if status.get('exists', False) else 'No existe'}, " +
                     f"Mensajes: {status.get('message_count', 'N/A')}, Consumidores: {status.get('consumer_count', 'N/A')}")
                     
            if not docker_available:
                print("\nDocker no está disponible, lo que limita la funcionalidad del sistema.")
                print("Solo se pueden utilizar las colas y servicios que ya estén configurados.")
            else:
                print("\nEs posible que los servicios Docker no estén en ejecución o funcionando correctamente.")
                print("Puede iniciarlos desde el menú principal con la opción 'Manage Docker Services'.")
            
            # Try to auto-create missing queues if they don't exist but we have a connection
            if docker_available and "queue_status" in pipeline_status["details"]:
                try_autocreate_missing_queues(client, pipeline_status["details"]["queue_status"])
            
            if not force_sample:
                print("\n¿Desea intentar continuar con los datos disponibles o usar datos de muestra?")
                print("1. Intentar con los datos disponibles")
                print("2. Usar datos de muestra")
                try:
                    option = int(input("Ingrese su opción (1-2): "))
                    if option == 2:
                        force_sample = True
                except ValueError:
                    print("Entrada inválida. Intentando con los datos disponibles.")
        else:
            print(f"\n✅ {pipeline_status['message']}")
        
    if not force_sample:
        print("\nBuscando datos de análisis en RabbitMQ...")
        messages = client.get_messages(count=10, peek_only=True)
        
        if messages and not any("error" in msg for msg in messages):
            print(f"Encontrados {len(messages)} mensajes de análisis. Generando reporte...")
            
            # Create a report generator
            report_generator = ReportGenerator()
            
            # Generate the report
            result = report_generator.generate_report(messages, report_format)
            print("\nReporte generado exitosamente con los datos del servicio.")
            print("Si el formato no fue 'console', revise el directorio de reportes.")
            return
        else:
            print("No se encontraron mensajes válidos en la cola o ocurrió un error.")
            
            # Try to request a report directly from the reporting service if Docker is available
            if docker_available:
                print("\nIntentando solicitar un reporte al servicio de reportes...")
                report_id = f"cli_request_{int(time.time())}"
                response = client.request_report(report_id=report_id, report_format=report_format, timeout=15)
                
                if "error" not in response:
                    print(f"\nSolicitud de reporte enviada con ID: {report_id}")
                    print(f"Estado: {response.get('status', 'desconocido')}")
                    print(f"Mensaje: {response.get('message', 'Sin mensaje')}")
                    
                    if response.get('status') == 'processing' or response.get('status') == 'pending':
                        print("\nEl reporte está siendo generado por el servicio...")
                        print("Por favor revise el directorio de reportes en unos momentos.")
                        return
                    elif response.get('status') == 'complete':
                        print("\nReporte generado exitosamente por el servicio.")
                        print("Si el formato no fue 'console', revise el directorio de reportes.")
                        return
                else:
                    print(f"\nError al solicitar el reporte: {response.get('error', 'Error desconocido')}")
                    print("Procediendo a generar un reporte con datos de muestra.")
                    force_sample = True
            else:
                print("\nDocker no está disponible, utilizando datos de muestra para el reporte.")
                force_sample = True
    
    # If we got here, we either have no data or force_sample is True
    print("\nUsando datos de muestra para generar el reporte...")
    
    # Sample data for demonstration
    sample_data = generate_sample_data()
    
    # Create a report generator
    report_generator = ReportGenerator()
    
    # Generate the report
    result = report_generator.generate_report(sample_data, report_format)
    print("\nReporte generado exitosamente con datos de muestra.")
    print("Si el formato no fue 'console', revise el directorio de reportes.")

def handle_pipeline_error(pipeline_status):
    """
    Handle pipeline error based on status
    
    Args:
        pipeline_status: The pipeline status dictionary
    
    Returns:
        bool: Whether to use sample data
    """
    if not pipeline_status.get("details", {}).get("rabbitmq_connection", False):
        print("\nNo se pudo establecer conexión con RabbitMQ.")
        print("Esto puede deberse a que RabbitMQ no está en ejecución o no es accesible.")
        print("Si está utilizando Docker, verifique que el servicio rabbitmq esté en ejecución.")
        print("Si no está utilizando Docker, verifique que RabbitMQ esté instalado y en ejecución.")
    
    print("\n¿Desea intentar obtener datos directamente o usar datos de muestra?")
    print("1. Intentar obtener datos directamente")
    print("2. Usar datos de muestra")
    try:
        option = int(input("Ingrese su opción (1-2): "))
        return option != 1  # Return True for sample data if option != 1
    except ValueError:
        print("Entrada inválida. Intentando obtener datos directamente.")
        return False  # Default to not using sample

def try_autocreate_missing_queues(client, queue_status):
    """
    Attempt to create missing queues
    
    Args:
        client: The ReportServiceClient instance
        queue_status: Dictionary with queue status information
    """
    required_queues = [
        "raw_frames_queue", 
        "parsed_packets_queue",
        "feature_vectors_queue", 
        "ml_results_queue", 
        "analysis_results_queue"
    ]
    
    missing_queues = [q for q in required_queues if q not in queue_status or not queue_status[q].get("exists", False)]
    
    if missing_queues and client.connect():
        print("\nIntentando crear las colas faltantes...")
        
        for queue in missing_queues:
            try:
                client.channel.queue_declare(
                    queue=queue,
                    durable=True
                )
                print(f"✅ Cola {queue} creada correctamente.")
            except Exception as e:
                print(f"❌ No se pudo crear la cola {queue}: {e}")
        
        client.close()

def generate_sample_data():
    """
    Generate sample data for demonstration reports
    
    Returns:
        List of dictionaries with sample packet data
    """
    sample_data = [
        {"timestamp": "2025-05-18T10:15:30Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 64},
        {"timestamp": "2025-05-18T10:15:31Z", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 76},
        {"timestamp": "2025-05-18T10:15:32Z", "src_ip": "8.8.8.8", "dst_ip": "192.168.1.100", "protocol": "TCP", "length": 60}
    ]
    
    # Add more realistic sample data
    sample_data.extend([
        {"timestamp": "2025-05-18T10:15:33Z", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "protocol": "UDP", "length": 120, 
            "port_src": 53245, "port_dst": 53, "application": "DNS"},
        {"timestamp": "2025-05-18T10:15:34Z", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "UDP", "length": 180,
            "port_src": 53, "port_dst": 53245, "application": "DNS"},
        {"timestamp": "2025-05-18T10:15:35Z", "src_ip": "192.168.1.100", "dst_ip": "216.58.210.142", "protocol": "TCP", "length": 80,
            "port_src": 54321, "port_dst": 443, "application": "HTTPS"},
        {"timestamp": "2025-05-18T10:15:36Z", "src_ip": "216.58.210.142", "dst_ip": "192.168.1.100", "protocol": "TCP", "length": 1320,
            "port_src": 443, "port_dst": 54321, "application": "HTTPS", "flags": "ACK,PSH"},
        {"timestamp": "2025-05-18T10:15:37Z", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1", "protocol": "ICMP", "length": 84,
            "icmp_type": 8, "icmp_code": 0, "application": "PING"},
        {"timestamp": "2025-05-18T10:15:38Z", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.100", "protocol": "ICMP", "length": 84,
            "icmp_type": 0, "icmp_code": 0, "application": "PING"}
    ])
    
    return sample_data
