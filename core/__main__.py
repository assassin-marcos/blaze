"""Allow running as: python -m core"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blaze import cli_entry
cli_entry()
