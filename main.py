#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

import logging
from src.utils.logging_config import setup_logging
from src.ui.menu_handler import run_main_loop # Import new functions

def main():
    # Setup logging first, as it now reads from config
    setup_logging() # This should be called before any logging is done, including in menu_handler
    logger = logging.getLogger(__name__) # Get logger after setup

    run_main_loop()

if __name__ == "__main__":
    main()
