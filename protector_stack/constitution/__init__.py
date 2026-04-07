"""protector_stack.constitution"""

from .doctrine import (
    MISSION_STATEMENT,
    PRINCIPLES,
    HARD_NON_GOALS,
    AUTHORITY_BOUNDARY,
    check_action_permitted,
    get_doctrine_summary,
)
from .integrity import verify_doctrine_integrity, get_constitution_status

__all__ = [
    "MISSION_STATEMENT",
    "PRINCIPLES",
    "HARD_NON_GOALS",
    "AUTHORITY_BOUNDARY",
    "check_action_permitted",
    "get_doctrine_summary",
    "verify_doctrine_integrity",
    "get_constitution_status",
]
