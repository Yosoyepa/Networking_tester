#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Punto de entrada principal para networking_tester."""

from src.utils.logging_config import setup_logging
from src.ui.menu_handler import run_main_loop # Import new functions

def main():
    # Setup logging first
    setup_logging()

    run_main_loop()

if __name__ == "__main__":
    main()
