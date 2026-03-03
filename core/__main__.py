"""Allow running as: python -m blaze"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blaze import main
import asyncio
asyncio.run(main())
