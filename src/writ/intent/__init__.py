"""Intent modelling: interventional goal recognition, anytime-valid holds, and risk budgets.

See paper/ for the formal model. The modules here are deterministic given their inputs; the
only learned component is the optional LLM claim extractor, whose output is treated as data.
"""

from .abstract import AbstractAction, IntentModel, IntentState, Observation
from .spec import IntentSpec, NonGoal

__all__ = ["IntentSpec", "NonGoal", "AbstractAction", "IntentModel", "IntentState", "Observation"]
