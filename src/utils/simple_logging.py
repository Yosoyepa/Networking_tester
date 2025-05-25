#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple logging configuration for networking_tester."""

import logging
import sys


def setup_logging(log_level=logging.INFO, console_only=True):
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (default INFO)
        console_only: If True, only log to console (useful for tests)
    """
    # Basic configuration for tests and general use
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-7s] [%(name)-20s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
