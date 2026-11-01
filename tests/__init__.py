"""
APAAR Verify Test Suite Package
"""

import sys
from pathlib import Path

# Ensure project root is present in sys.path for test discovery and direct execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

