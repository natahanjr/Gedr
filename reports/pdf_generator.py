"""Backward-compatible entry point.

The reporting system has been re-architected into a package (see reports/
__init__.py). This module keeps the historical import path working:

    from reports.pdf_generator import SecurityReportGenerator
"""
from .generator import (  # noqa: F401
    REPORTS_DIR,
    REPORT_TYPE_SECURITY,
    SecurityReportGenerator,
)
from .report_model import build_report_model  # noqa: F401

__all__ = ["SecurityReportGenerator", "REPORTS_DIR",
           "REPORT_TYPE_SECURITY", "build_report_model"]
