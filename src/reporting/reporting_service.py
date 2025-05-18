"""
Reporting Service

Consumes AnalysisResult messages and generates reports.
"""
import logging
import time
import os
import signal
from typing import List, Dict, Any

from src.messaging.rabbitmq_client import RabbitMQClient
from src.messaging.schemas import AnalysisResult, ANALYSIS_RESULTS_TOPIC
from src.reporting.report_generator import ReportGenerator
from src.utils.logger_config import setup_logging

logger = logging.getLogger(__name__)

# Configuration for exchanges and queues
# Consumes from the exchange where CoreAnalysisService publishes AnalysisResult messages
ANALYSIS_RESULTS_EXCHANGE_NAME = "analysis_results_exchange"
REPORTING_SERVICE_QUEUE_NAME = "reporting_service_analysis_results_queue"
# The routing key should match what CoreAnalysisService uses for publishing
ANALYSIS_RESULTS_ROUTING_KEY = "analysis_results_queue"

class ReportingService:
    def __init__(self, mq_client: RabbitMQClient,
                 input_exchange_name: str, input_queue_name: str, input_routing_key: str):
        """
        Initializes the ReportingService.

        Args:
            mq_client: An instance of the message queue client.
            input_exchange_name: Exchange to consume AnalysisResult messages from.
            input_queue_name: Queue name for this service to consume messages.
            input_routing_key: Routing key to bind the queue to the exchange.
        """
        self.mq_client = mq_client
        self.input_exchange_name = input_exchange_name
        self.input_queue_name = input_queue_name
        self.input_routing_key = input_routing_key
        
        self.report_generator = ReportGenerator()
        self.collected_results: List[AnalysisResult] = []
        self.shutdown_flag = False

        self._setup_messaging()
        self._setup_signal_handlers()

    def _setup_messaging(self):
        logger.info("Setting up messaging for ReportingService.")
        # Input: Consuming AnalysisResult messages
        self.mq_client.declare_exchange(self.input_exchange_name, exchange_type='direct')
        # Declare a dedicated queue for this service and bind it to the exchange with the correct routing key
        self.mq_client.declare_queue(self.input_queue_name, self.input_exchange_name, self.input_routing_key)
        logger.info(f"Messaging setup complete. Consuming from queue '{self.input_queue_name}' bound to exchange '{self.input_exchange_name}' with key '{self.input_routing_key}'")

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        signal.signal(signal.SIGTERM, self._handle_shutdown_signal)

    def _handle_shutdown_signal(self, signum, frame):
        logger.info(f"Shutdown signal {signum} received. Initiating graceful shutdown.")
        self.shutdown_flag = True
        # Optionally, trigger a final report generation here
        self.generate_final_report()
        # Allow some time for the consumer to stop or force close connection
        if self.mq_client:
            self.mq_client.stop_consuming() # Assuming RabbitMQClient has such a method
            self.mq_client.close() 
        logger.info("ReportingService shut down.")
        exit(0)

    def _message_handler(self, analysis_result_msg: AnalysisResult):
        msg_type = analysis_result_msg.get("type", "unknown_type")
        analysis_id = analysis_result_msg.get("analysis_id", "unknown_id")
        # logger.debug(f"Received AnalysisResult: ID {analysis_id}, Type: {msg_type}")
        self.collected_results.append(analysis_result_msg)
        
        # For simplicity, we might generate a report periodically or when a certain number of results are collected.
        # For this example, report generation will be triggered manually or on shutdown.

    def generate_final_report(self, report_format: str = "console"):
        if not self.collected_results:
            logger.info("No analysis results collected. Skipping final report generation.")
            return

        logger.info(f"Generating final report with {len(self.collected_results)} collected analysis results.")
        try:
            # The ReportGenerator expects a list of dicts. AnalysisResult is a TypedDict.
            # The `stats` and `ai_results` are optional in ReportGenerator.
            # We pass None for them as this service only collects AnalysisResult items.
            report_output = self.report_generator.generate_report(
                analyzed_data_list=self.collected_results,
                report_format=report_format,
                stats=None,  # Or synthesize some basic stats from collected_results if needed
                ai_results=None # Or synthesize some basic AI summary if needed
            )
            if report_format == "console":
                print("\n--- Final Report ---")
                print(report_output)
                print("--- End of Final Report ---")
            else:
                logger.info(f"Final report generated to file (see ReportGenerator logs for path).")

        except Exception as e:
            logger.error(f"Error generating final report: {e}", exc_info=True)
        finally:
            self.collected_results.clear() # Clear after reporting

    def start_consuming(self):
        logger.info(f"ReportingService starting to consume from queue: '{self.input_queue_name}'")
        try:
            self.mq_client.consume(
                queue_name=self.input_queue_name,
                callback_function=self._message_handler,
                auto_ack=True # Set to True for simplicity
            )
            # Keep the main thread alive while consumer runs in its thread (if mq_client.consume is non-blocking)
            # Or if mq_client.consume is blocking, this loop is not strictly necessary here but good for clarity
            while not self.shutdown_flag:
                time.sleep(1) # Keep alive, check shutdown_flag periodically
        
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received by ReportingService. Shutting down.")
            self._handle_shutdown_signal(signal.SIGINT, None)
        except Exception as e:
            logger.error(f"ReportingService failed during consumption: {e}", exc_info=True)
            if self.mq_client:
                self.mq_client.close()
        finally:
            logger.info("ReportingService consumption loop finished or was interrupted.")
            if not self.shutdown_flag: # If shutdown wasn't triggered by signal
                self.generate_final_report()


if __name__ == '__main__':
    import pika # For AMQPConnectionError
    setup_logging()

    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))

    logger.info("Initializing Reporting Service Example...")
    mq_client_instance = None
    reporting_service_instance = None
    try:
        mq_client_instance = RabbitMQClient(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
        
        # CoreAnalysisService publishes to ANALYSIS_RESULTS_EXCHANGE_NAME with ANALYSIS_RESULTS_QUEUE_ROUTING_KEY.
        # ReportingService needs to consume from a queue bound to this exchange and routing key.
        reporting_service_instance = ReportingService(
            mq_client=mq_client_instance,
            input_exchange_name=ANALYSIS_RESULTS_EXCHANGE_NAME,
            input_queue_name=REPORTING_SERVICE_QUEUE_NAME, # Dedicated queue for this service
            input_routing_key=ANALYSIS_RESULTS_ROUTING_KEY # Key used by CoreAnalysisService to publish
        )
        
        logger.info(f"Starting Reporting Service. Press Ctrl+C to generate a final report and stop.")
        reporting_service_instance.start_consuming()

    except pika.exceptions.AMQPConnectionError as amqp_err:
        logger.error(f"AMQP Connection Error: {amqp_err}. Is RabbitMQ running at {RABBITMQ_HOST}:{RABBITMQ_PORT}?")
    except KeyboardInterrupt:
        logger.info("Reporting Service main block interrupted by user. Final report should be generated.")
        # The signal handler in the service should take care of the report.
    except Exception as e:
        logger.error(f"An unexpected error occurred in the Reporting Service main execution block: {e}", exc_info=True)
    finally:
        # Ensure final report is generated if service instance exists and shutdown wasn't clean via signal
        if reporting_service_instance and not reporting_service_instance.shutdown_flag:
            logger.info("Main block finally: Generating final report as a fallback.")
            reporting_service_instance.generate_final_report(report_format="console")
        
        if mq_client_instance and mq_client_instance.connection and mq_client_instance.connection.is_open:
            logger.info("Closing RabbitMQ connection from main block.")
            mq_client_instance.close()
        logger.info("Reporting Service Example finished.")
