"""
Messaging module for handling communication between services using message queues.

This module will contain:
- Producers for sending messages.
- Consumers for receiving messages.
- Definitions of message schemas (though actual schemas might be in a docs folder or a shared library).
"""

from .message_producer import MessageProducer
from .message_consumer import MessageConsumer

__all__ = [
    "MessageProducer",
    "MessageConsumer"
]
