"""Init module."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent / "libraries/Obfuscapk/src"))
sys.path.append(str(Path(__file__).parent / "libraries/maltorch/src"))

from .evaluation import evaluate

__all__ = ["evaluate"]
