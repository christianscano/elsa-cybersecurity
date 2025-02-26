
"""Black-Box Problem-Space attack."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent / "Obfuscapk/src"))


from .manipulation_space import Manipulations, ManipulationSpace
from .manipulator import Manipulator

__all__ = [
    "ManipulationSpace",
    "Manipulations",
    "Manipulator"
]
