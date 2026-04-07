"""protector_stack.threat"""

from .injection_detector import analyze_text as detect_injection, InjectionAnalysis
from .escalation_detector import analyze_text as detect_escalation, EscalationAnalysis
from .exfil_detector import analyze_text as detect_exfil, ExfilAnalysis
from .drift_detector import DriftDetector, AgentDriftTracker, DriftAnalysis
from .scorer import ThreatScorer, ThreatAssessment, get_scorer
from .analyzer import ThreatAnalyzer, get_analyzer

__all__ = [
    "detect_injection",
    "InjectionAnalysis",
    "detect_escalation",
    "EscalationAnalysis",
    "detect_exfil",
    "ExfilAnalysis",
    "DriftDetector",
    "AgentDriftTracker",
    "DriftAnalysis",
    "ThreatScorer",
    "ThreatAssessment",
    "get_scorer",
    "ThreatAnalyzer",
    "get_analyzer",
]
