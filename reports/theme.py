"""
Gədr Reporting Engine - design system.

Central definition of the visual language used by every generated report:
palette, typography scale, spacing constants and severity styling.

The palette is deliberately light and print-first: every colour pair keeps
sufficient contrast in both digital viewing and greyscale printing, and
severity is never communicated by colour alone (label + score + shade always
accompany it).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #

WHITE: tuple = (255, 255, 255)
INK: tuple = (24, 29, 38)          # primary text
BODY: tuple = (54, 62, 76)         # body copy
MUTED: tuple = (106, 115, 130)     # secondary text
FAINT: tuple = (152, 159, 171)     # tertiary text
HAIRLINE: tuple = (222, 226, 233)  # rules and borders
SURFACE: tuple = (245, 246, 249)   # subtle panel background
SURFACE2: tuple = (250, 250, 252)  # alternating rows

NAVY: tuple = (15, 40, 66)         # brand primary
STEEL: tuple = (43, 84, 124)       # brand accent

SEVERITY_COLORS: dict[str, tuple] = {
    "Critical": (155, 28, 30),
    "High": (172, 72, 15),
    "Medium": (143, 101, 16),
    "Low": (30, 96, 61),
    "Informational": (86, 95, 108),
}

SEVERITY_TINTS: dict[str, tuple] = {
    "Critical": (250, 238, 238),
    "High": (250, 240, 231),
    "Medium": (249, 245, 232),
    "Low": (236, 245, 240),
    "Informational": (242, 243, 246),
}

CHART_SERIES: tuple[tuple, ...] = (
    NAVY, STEEL, (96, 125, 155), (139, 161, 183),
    (176, 192, 207), (206, 216, 225), FAINT,
)

# --------------------------------------------------------------------------- #
# Typography scale (pt)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TypeScale:
    display: int = 30   # cover title
    h1: int = 19        # section titles
    h2: int = 13        # sub-section titles
    h3: int = 10        # component titles
    lead: int = 10      # lead paragraphs
    body: int = 9
    small: int = 8
    micro: int = 7      # chips, footers, captions
    mono: int = 7.6     # evidence blocks


TYPE = TypeScale()

# --------------------------------------------------------------------------- #
# Geometry (mm) - A4 portrait
# --------------------------------------------------------------------------- #

PAGE_W: float = 210.0
PAGE_H: float = 297.0
MARGIN_L: float = 16.0
MARGIN_R: float = 16.0
MARGIN_T: float = 24.0          # below running header
MARGIN_B: float = 20.0          # above running footer
CONTENT_W: float = PAGE_W - MARGIN_L - MARGIN_R
FOOTER_RESERVE: float = 6.0     # extra keep-out zone above footer rule


def content_right(pdf) -> float:
    return PAGE_W - MARGIN_R


# --------------------------------------------------------------------------- #
# Severity semantics
# --------------------------------------------------------------------------- #

SEVERITY_ORDER: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Informational")

SEVERITY_DEFINITIONS: dict[str, str] = {
    "Critical": "Score 9-10. Immediately exploitable weakness with severe impact on "
                "confidentiality, integrity or availability.",
    "High": "Score 7-8. Serious weakness that is likely exploitable or has significant impact.",
    "Medium": "Score 4-6. Moderate weakness requiring remediation in the regular development cycle.",
    "Low": "Score 1-3. Minor issue or hardening opportunity with limited direct impact.",
    "Informational": "Observation recorded for completeness; no direct security impact identified.",
}


def severity_of(raw: str | None, score: int | None = None) -> str:
    """Normalise a severity label, optionally inferring it from a 1-10 score."""
    if raw:
        for name in SEVERITY_ORDER:
            if raw.strip().lower() == name.lower():
                return name
    if isinstance(score, int) and not isinstance(score, bool):
        if score >= 9: return "Critical"
        if score >= 7: return "High"
        if score >= 4: return "Medium"
        return "Low"
    return "Informational"


def grade_for(score: int) -> str:
    """Documented grading scale - identical to the platform's risk engine."""
    s = max(0, min(100, int(score)))
    if s >= 90: return "A+"
    if s >= 80: return "A"
    if s >= 70: return "B"
    if s >= 50: return "C"
    if s >= 30: return "D"
    return "F"


GRADE_BAND: dict[str, str] = {
    "A+": "Strong posture",
    "A": "Strong posture",
    "B": "Generally sound, targeted improvements required",
    "C": "Elevated risk, structured remediation needed",
    "D": "High risk, prompt remediation required",
    "F": "Severe risk, immediate action required",
}

GRADE_COLOR: dict[str, tuple] = {
    "A+": SEVERITY_COLORS["Low"],
    "A": SEVERITY_COLORS["Low"],
    "B": STEEL,
    "C": SEVERITY_COLORS["Medium"],
    "D": SEVERITY_COLORS["High"],
    "F": SEVERITY_COLORS["Critical"],
}


# --------------------------------------------------------------------------- #
# Font discovery - prefer a full-Unicode family so branding ("Gədr"),
# typographic punctuation and international text render correctly.
# --------------------------------------------------------------------------- #

_FONT_DIRS = (
    Path(r"C:\Windows\Fonts"),
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts"),
    Path("/Library/Fonts"),
    Path.home() / ".fonts",
)

_SANS_CANDIDATES = [  # (regular, bold, italic)
    ("segoeui.ttf", "segoeuib.ttf", "segoeuii.ttf"),
    ("arial.ttf", "arialbd.ttf", "ariali.ttf"),
    ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans-Oblique.ttf"),
    ("calibri.ttf", "calibrib.ttf", "calibrii.ttf"),
]
_MONO_CANDIDATES = [
    ("consola.ttf", "consolab.ttf"),
    ("cour.ttf", "courbd.ttf"),
    ("DejaVuSansMono.ttf", "DejaVuSansMono-Bold.ttf"),
]


def _find(names: tuple[str, ...]) -> Path | None:
    for name in names:
        for base in _FONT_DIRS:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


@dataclass(frozen=True)
class FontBundle:
    sans_regular: str | None
    sans_bold: str | None
    sans_italic: str | None
    mono_regular: str | None
    mono_bold: str | None

    @property
    def unicode_capable(self) -> bool:
        return self.sans_regular is not None


def discover_fonts() -> FontBundle:
    reg = None
    bold = ital = None
    for r_name, b_name, i_name in _SANS_CANDIDATES:
        r = _find((r_name,))
        if not r:
            continue
        b = _find((b_name,))
        if b and b.parent == r.parent:
            reg, bold, ital = r, b, _find((i_name,))
            break
    mreg = mbold = None
    for r_name, b_name in _MONO_CANDIDATES:
        r = _find((r_name,))
        if not r:
            continue
        b = _find((b_name,))
        if b and b.parent == r.parent:
            mreg, mbold = r, b
            break
    return FontBundle(reg, bold, ital, mreg, mbold)
