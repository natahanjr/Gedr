"""
Gedr Reporting Engine.

Pipeline:  DATA -> REPORT MODEL -> SECTION GENERATION -> VISUALISATION
           -> PDF LAYOUT -> VALIDATION -> DELIVERY

Modules:
- report_model  pure data layer: normalisation, aggregation, sanitisation
- theme         design system (palette, typography, severity semantics)
- charts        native vector visualisations
- layout        GedrPDF layout engine (headers/footers, components)
- generator     SecurityReportGenerator orchestrator + section builders
- validator     automated quality control before delivery
"""
from .generator import (
    REPORT_TYPE_SECURITY,
    REPORTS_DIR,
    SecurityReportGenerator,
)
from .report_model import ENGINE_NAME, ENGINE_VERSION
from .validator import ReportValidation, ValidationError

__all__ = [
    "SecurityReportGenerator",
    "REPORTS_DIR",
    "REPORT_TYPE_SECURITY",
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "ReportValidation",
    "ValidationError",
]
