import logging
logger = logging.getLogger(__name__)

def handle_system_status(config):
    """Handles displaying system status and diagnostics."""
    try:
        # Try to use the new module if available
        try:
            # First check RabbitMQ and basic status
            from src.ui.queue_monitor import run_diagnostics
            diagnosis = run_diagnostics(config)
            
            # Now check for reporting pipeline status
            print("\nVerificando estado del pipeline de reportes...")
            try:
                from src.ui.report_service_client import ReportServiceClient
                from src.ui.docker_service_manager import DockerServiceManager
                
                # Check Docker availability first - it's fundamental to the microservices architecture
                docker_manager = DockerServiceManager()
                docker_available = docker_manager.is_docker_available()
                docker_running = docker_manager.is_docker_running()
                
                if not docker_available:
                    print("\n❌ Docker no está disponible en este sistema")
                    print("La arquitectura de microservicios requiere Docker para funcionar completamente")
                    print("Sin Docker, solo estarán disponibles funciones limitadas y datos de muestra.")
                elif not docker_running:
                    print("\n❌ Docker está instalado pero no está en ejecución")
                    print("Inicie Docker Desktop para habilitar la funcionalidad completa")
                
                # Create the report service client
                client = ReportServiceClient(
                    host=config.get('rabbitmq', {}).get('host', 'localhost'),
                    port=config.get('rabbitmq', {}).get('port', 5672),
                    username=config.get('rabbitmq', {}).get('user'),
                    password=config.get('rabbitmq', {}).get('password')
                )
                
                # Check pipeline status using the client
                pipeline_status = client.check_pipeline_status()
                
                # Print status with appropriate emoji
                status_icon = "✅" if pipeline_status["status"] == "ok" else "⚠️" if pipeline_status["status"] == "warning" else "❌"
                print(f"\n{status_icon} Estado del pipeline: {pipeline_status['status']}")
                print(f"Mensaje: {pipeline_status['message']}")
                
                # If RabbitMQ connection is successful, show queue status
                if pipeline_status["details"]["rabbitmq_connection"]:
                    # Check each queue
                    print("\n--- Estado de Colas de RabbitMQ ---")
                    for queue, status in pipeline_status["details"]["queue_status"].items():
                        status_icon = "✅" if status["status"] == "ok" else "⚠️" if status["status"] == "warning" else "❌"
                        exists = "Existe" if status.get("exists", False) else "No existe"
                        msg_count = status.get("message_count", "N/A")
                        consumer_count = status.get("consumer_count", "N/A")
                        print(f"{status_icon} Cola {queue}: {exists}, Mensajes: {msg_count}, Consumidores: {consumer_count}")
                
                # Also check Docker service status if we have that information
                if docker_available and docker_running:
                    success, services_info = docker_manager.check_reporting_services()
                    
                    # Print Docker service status
                    print("\n--- Estado de servicios Docker ---")
                    if "error" in services_info:
                        print(f"❌ Error: {services_info['error']}")
                    else:
                        for service, status in services_info.items():
                            if service not in ["queues", "queues_error"]:
                                status_icon = "✅" if status == "running" else "⚠️" if status == "restarting" else "❌"
                                print(f"{status_icon} {service}: {status}")
                else:
                    print("\n--- Estado de servicios Docker ---")
                    print("❌ Docker no está disponible o no está en ejecución")
                    print("No se pueden verificar los servicios")
            
            except ImportError as e:
                print(f"\n⚠️ No se pudo verificar el estado completo del pipeline: {e}")
                print("Algunos módulos de diagnóstico no están disponibles.")
            
            print("\n=== Opciones de Diagnóstico Adicionales ===")
            print("1. Verificar mensajes de muestra de una cola")
            print("2. Verificar estado de servicios Docker")
            print("3. Revisar pipeline completo de reportes")
            print("4. Diagnosticar y reparar pipeline de reportes")
            print("5. Volver al menú principal")
            
            option = input("\nIngrese su opción (1-5): ").strip()
            
            if option == "1":
                # Sample queue messages
                print("\nIngrese el nombre de la cola a inspeccionar (ej: raw_frames_queue, analysis_results_queue):")
                queue_name = input("> ").strip()
                
                if queue_name:
                    print(f"Buscando mensajes en la cola: {queue_name}")
                    from src.ui.queue_monitor import QueueMonitor
                    monitor = QueueMonitor(
                        host=config.get('rabbitmq', {}).get('host', 'localhost'),
                        port=config.get('rabbitmq', {}).get('port', 5672),
                        username=config.get('rabbitmq', {}).get('user'),
                        password=config.get('rabbitmq', {}).get('password')
                    )
                    
                    print("\nObteniendo mensajes de muestra...")
                    msgs = monitor.sample_messages(queue_name, 5)
                    
                    if msgs:
                        print(f"Encontrados {len(msgs)} mensajes.")
                        for i, msg in enumerate(msgs):
                            print(f"\nMensaje {i+1}:")
                            print(msg)
                    else:
                        print("No se encontraron mensajes o ocurrió un error al recuperarlos.")
                        
            elif option == "2":
                # Docker status check
                from src.ui.docker_service_manager import DockerServiceManager
                manager = DockerServiceManager()
                
                docker_available = manager.is_docker_available()
                
                if not docker_available:
                    print("\nDocker no está disponible en este sistema.")
                    print("La instalación de Docker es necesaria para la funcionalidad completa.")
                    print("Puede descargar Docker Desktop desde: https://www.docker.com/products/docker-desktop/")
                    return
                
                docker_running = manager.is_docker_running()
                if not docker_running:
                    print("\nDocker está instalado pero no está en ejecución.")
                    print("Por favor, inicie Docker Desktop y vuelva a ejecutar el diagnóstico.")
                    return
                
                success, message, output = manager.get_service_status()
                if success:
                    print("\nEstado de servicios Docker:")
                    print(output)
                else:
                    print(f"\nError al recuperar el estado de los servicios Docker: {message}")
            
            elif option == "3":
                # Full pipeline diagnostics
                print("\nEjecutando diagnóstico completo del pipeline de reportes...")
                
                # First check Docker services
                from src.ui.docker_service_manager import DockerServiceManager
                docker_manager = DockerServiceManager()
                
                docker_available = docker_manager.is_docker_available()
                docker_running = docker_manager.is_docker_running()
                
                if not docker_available:
                    print("\n❌ Docker no está disponible en este sistema.")
                    print("La arquitectura de microservicios requiere Docker para funcionar correctamente.")
                    print("Sin Docker, solo tendrá funcionalidad limitada y datos de muestra.")
                elif not docker_running:
                    print("\n❌ Docker está instalado pero no está en ejecución.")
                    print("Inicie Docker Desktop y vuelva a ejecutar el diagnóstico.")
                else:
                    # Check reporting services
                    success, services_info = docker_manager.check_reporting_services()
                    
                    # Print Docker service status
                    print("\n--- Estado de servicios Docker ---")
                    if "error" in services_info:
                        print(f"❌ Error: {services_info['error']}")
                    else:
                        services_running = True
                        for service, status in services_info.items():
                            if service not in ["queues", "queues_error"]:
                                status_icon = "✅" if status == "running" else "⚠️" if status == "restarting" else "❌"
                                print(f"{status_icon} {service}: {status}")
                                if status != "running" and service != "queues" and service != "queues_error":
                                    services_running = False
                
                # Now check RabbitMQ queues - this works even if Docker is not available
                from src.ui.report_service_client import ReportServiceClient
                client = ReportServiceClient(
                    host=config.get('rabbitmq', {}).get('host', 'localhost'),
                    port=config.get('rabbitmq', {}).get('port', 5672),
                    username=config.get('rabbitmq', {}).get('user'),
                    password=config.get('rabbitmq', {}).get('password')
                )
                
                pipeline_status = client.check_pipeline_status()
                
                # Print queue status
                print("\n--- Estado de colas de RabbitMQ ---")
                if pipeline_status["status"] == "error":
                    print(f"❌ Error: {pipeline_status['message']}")
                else:
                    for queue, status in pipeline_status["details"]["queue_status"].items():
                        status_icon = "✅" if status["status"] == "ok" else "⚠️" if status["status"] == "warning" else "❌"
                        exists = "Existe" if status.get("exists", False) else "No existe"
                        msg_count = status.get("message_count", "N/A")
                        consumer_count = status.get("consumer_count", "N/A")
                        print(f"{status_icon} Cola {queue}: {exists}, Mensajes: {msg_count}, Consumidores: {consumer_count}")
                
                # Print recommendations based on status
                if not docker_available or not docker_running:
                    print("\n--- Diagnóstico y Recomendaciones ---")
                    print("❌ Docker no está disponible o no está en ejecución.")
                    print("Recomendación: Instale Docker Desktop o inícielo para obtener la funcionalidad completa.")
                    print("Mientras tanto, puede utilizar la función de 'Generar reportes' con datos de muestra.")
                elif not services_running:
                    print("\n--- Diagnóstico y Recomendaciones ---")
                    print("❌ Algunos servicios de Docker no están en ejecución.")
                    print("Recomendación: Utilice la opción 'Diagnosticar y reparar pipeline de reportes' para solucionar estos problemas.")
                elif pipeline_status["status"] != "ok":
                    print("\n--- Diagnóstico y Recomendaciones ---")
                    print("⚠️ Las colas de RabbitMQ no están configuradas correctamente o no tienen consumidores.")
                    print("Recomendación: Utilice la opción 'Diagnosticar y reparar pipeline de reportes' para solucionar estos problemas.")
                else:
                    print("\n--- Diagnóstico y Recomendaciones ---")
                    print("✅ El pipeline de reportes parece estar funcionando correctamente.")
                
                # Check if we can generate a report
                print("\n¿Desea intentar generar un reporte de prueba para verificar el funcionamiento completo?")
                print("1. Sí, generar reporte de prueba")
                print("2. No, volver al diagnóstico")
                
                test_option = input("\nIngrese su opción (1-2): ").strip()
                
                if test_option == "1":
                    from src.ui.report_service_client import process_reports
                    process_reports(config, force_sample=False)
            
            elif option == "4":
                # Run the reporting pipeline fixer
                from src.ui.reporting_service_fixer import fix_reporting_pipeline
                fix_reporting_pipeline(config)
            
            # If option is 5 or invalid, just return to main menu
            
            return
            
        except ImportError as e:
            logger.info(f"Could not import new diagnostic modules: {e}. Using original implementation.")
            pass
        
        # Original implementation as fallback
        print("\nPerforming system diagnostics...")
        print("Networking Tester Status: Active")
        print("Log file: logs/networking_tester.log")
        
        # Check if we can access the RabbitMQ interface
        rabbitmq_host = config.get('rabbitmq', {}).get('host', 'localhost')
        rabbitmq_port = config.get('rabbitmq', {}).get('port', 5672)
        rabbitmq_user = config.get('rabbitmq', {}).get('user')
        rabbitmq_password = config.get('rabbitmq', {}).get('password')
        
        print(f"\nChecking RabbitMQ connection to {rabbitmq_host}:{rabbitmq_port}...")
        try:
            import pika
            credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_password) if rabbitmq_user and rabbitmq_password else None
            connection_params = pika.ConnectionParameters(
                host=rabbitmq_host,
                port=rabbitmq_port,
                credentials=credentials,
                connection_attempts=1,
                socket_timeout=2
            )
            connection = pika.BlockingConnection(connection_params)
            print("RabbitMQ connection: SUCCESS")
            connection.close()
        except Exception as e:
            print(f"RabbitMQ connection: FAILED - {str(e)}")
    
    except Exception as e:
        logger.error(f"Error in system status diagnostics: {e}", exc_info=True)
        print(f"An error occurred during system diagnostics: {e}")
        print("Try running with Docker services active or check the logs for more information.")
