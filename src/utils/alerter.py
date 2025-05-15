import logging

logger = logging.getLogger(__name__)

class Alerter:
    def __init__(self, config_manager):
        self.config_manager = config_manager
        # In the future, this could load email settings, webhook URLs, etc.
        logger.debug("Alerter initialized.")

    def send_alert(self, message, severity="INFO", details=None):
        """
        Sends an alert. Currently logs to console.
        Could be extended for email, SMS, etc.
        """
        log_message = f"ALERT [{severity}]: {message}"
        if details:
            log_message += f" | Details: {details}"
        
        if severity == "CRITICAL":
            logger.critical(log_message)
        elif severity == "ERROR":
            logger.error(log_message)
        elif severity == "WARNING":
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Placeholder for other alert mechanisms
        # if self.config_manager.get('alerts.email.enabled'):
        #     self._send_email_alert(message, severity, details)