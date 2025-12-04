#!/usr/bin/env python3

"""
TPM Event Log Parser CLI Module

This module contains command-line interfaces for the TPM Event Log Parser package.
"""

import os
import sys
from typing import Dict, List, Any, Optional

# Ensure parent directory is in path for imports
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Import CLI modules
from . import summary
from . import pcr_extend
from . import analyse
from . import pcr7_measured_boot
from . import bitlocker_parser_cli

__all__ = ['yaml_parser_main', 'tcg_parser_main', 'pcr7_measured_boot', 'bitlocker_parser_cli'] 