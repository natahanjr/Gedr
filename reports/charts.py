"""
Gedr Reporting Engine - native vector visualisations.

All charts are drawn with PDF vector primitives (no raster images), so they
stay crisp at any zoom level and in print. Charts never rely on colour alone:
every segment/bar is labelled with its value directly.

Only render a chart when the underlying data adds understanding - callers
decide that; this module stays purely presentational.
"""
from __future__ import annotations

import math

from fpdf import FPDF

from .theme import (
    BODY, FAINT, HAIRLINE, INK, MUTED, SURFACE2, WHITE,
)


def _annular_sector(cx: float, cy: float, r_out: float, r_in: float,
                    a0: float, a1: float, segments: int = 28) -> list[tuple[float, float]]:
    """Polygon points approximating an annular sector from angle a0 to a1."""
    pts: list[tuple[float, float]] = []
    for i in range(segments + 1):
        a = math.radians(a0 + (a1 - a0) * i / segments)
        pts.append((cx + r_out * math.cos(a), cy + r_out * math.sin(a)))
    for i in range(segments + 1):
        a = math.radians(a1 - (a1 - a0) * i / segments)
        pts.append((cx + r_in * math.cos(a), cy + r_in * math.sin(a)))
    return pts


def donut(pdf: FPDF, cx: float, cy: float, r_out: float, r_in: float,
          values: list[tuple[str, int, tuple]],
          total: int | None = None, center_label: str = "") -> None:
    """Severity-style distribution ring. `values`: (label, count, colour)."""
    data = [(label, count, color) for label, count, color in values if count > 0]
    total = total if total is not None else sum(c for _, c, _ in data)
    if total <= 0 or not data:
        # Empty-state ring
        pdf.set_fill_color(*SURFACE2)
        pdf.set_draw_color(*HAIRLINE)
        pdf.ellipse(cx - r_out, cy - r_out, 2 * r_out, 2 * r_out, style="DF")
        pdf.set_font("helvetica" if pdf.font_family == "helvetica" else pdf.font_family, "", 8)
        return

    start = -90.0
    gap = 2.0 if len(data) > 1 else 0.0   # degrees of white separation
    span = 360.0 - gap * len(data)
    degrees_used = 0.0
    for label, count, color in data:
        frac = count / total
        arc = max(span * frac, 1.5)
        a0 = start + degrees_used + gap / 2
        a1 = a0 + arc
        pdf.set_fill_color(*color)
        pts = _annular_sector(cx, cy, r_out, r_in, a0, a1,
                              segments=max(8, int(arc // 6)))
        pdf.polygon(pts, style="F")
        degrees_used += arc + gap

    # Center hole
    pdf.set_fill_color(*WHITE)
    pdf.ellipse(cx - r_in - 0.4, cy - r_in - 0.4, 2 * (r_in + 0.4), 2 * (r_in + 0.4), style="F")

    if center_label:
        pdf.set_font(pdf.font_family, "B", max(11.0, r_out * 0.85))
        pdf.set_text_color(*INK)
        pdf.set_xy(cx - r_out, cy - r_out * 0.30)
        pdf.cell(2 * r_out, r_out * 0.7, str(total), align="C")
        pdf.set_font(pdf.font_family, "", 6.4)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(cx - r_out, cy + 3.6)
        pdf.cell(2 * r_out, 4.0, center_label, align="C")


def legend(pdf: FPDF, x: float, y: float, w: float,
           values: list[tuple[str, int, tuple]], row_h: float = 6.4,
           show_share_of: int | None = None) -> float:
    """Swatch legend rows; returns final y after the last row."""
    total = show_share_of if show_share_of is not None else sum(c for _, c, _ in values)
    pdf.set_font(pdf.font_family, "", 8)
    for label, count, color in values:
        pdf.set_fill_color(*color)
        pdf.rect(x, y + 0.9, 3.2, 3.2, "F")
        pdf.set_xy(x + 4.6, y)
        pdf.set_text_color(*BODY)
        share = f"  ({count / total * 100:.0f}%)" if total and count else ""
        pdf.cell(w - 4.6, row_h, f"{label}{share}")
        pdf.set_text_color(*INK)
        pdf.set_xy(x + w - 12, y)
        pdf.cell(12, row_h, str(count), align="R")
        y += row_h
    return y


def score_meter(pdf: FPDF, x: float, y: float, w: float, score: int,
                fill_color: tuple, label_left: str = "0",
                label_right: str = "100") -> float:
    """Horizontal score meter with documented grade threshold ticks."""
    h = 5.2
    track_w = w
    pdf.set_fill_color(*SURFACE2)
    pdf.set_draw_color(*HAIRLINE)
    pdf.rect(x, y, track_w, h, "DF")
    filled = max(0.0, min(100, score)) / 100 * track_w
    pdf.set_fill_color(*fill_color)
    if filled > 0:
        pdf.rect(x, y, filled, h, "F")
    # Grade thresholds used by the documented scoring model
    pdf.set_draw_color(*FAINT)
    pdf.set_line_width(0.18)
    for mark in (30, 50, 70, 80, 90):
        mx = x + track_w * mark / 100
        pdf.line(mx, y + h, mx, y + h + 1.8)
    pdf.set_font(pdf.font_family, "", 6.6)
    pdf.set_text_color(*MUTED)
    pdf.set_xy(x, y + h + 2.0)
    pdf.cell(track_w, 3.4, label_left)
    pdf.set_xy(x, y + h + 2.0)
    pdf.cell(track_w, 3.4, label_right, align="R")
    return y + h + 5.8


def hbars(pdf: FPDF, x: float, y: float, w: float,
          items: list[tuple[str, int]], *,
          color: tuple = None, row_h: float = 6.6, label_w: float | None = None,
          value_suffix: str = "", max_value: int | None = None) -> float:
    """Labelled horizontal bars; returns final y."""
    if not items:
        return y
    peak = max_value if max_value else max(c for _, c in items)
    if peak <= 0:
        peak = 1
    pdf.set_font(pdf.font_family, "", 8)
    if not label_w:
        label_w = min(w * 0.52, max(pdf.get_string_width(t) for t, _ in items) + 3)
    bar_x = x + label_w + 2
    bar_max_w = w - label_w - 14
    for label, count in items:
        pdf.set_text_color(*BODY)
        pdf.set_xy(x, y)
        shown = label if len(label) <= 48 else label[:47] + "\u2026"
        pdf.cell(label_w, row_h, shown)
        bw = max(1.2, bar_max_w * (count / peak))
        pdf.set_fill_color(*(color or (43, 84, 124)))
        pdf.rect(bar_x, y + row_h * 0.22, bw, row_h * 0.56, "F")
        pdf.set_text_color(*INK)
        pdf.set_xy(bar_x + bar_max_w + 2.2, y)
        pdf.cell(11, row_h, f"{count}{value_suffix}", align="R")
        y += row_h
    return y


def mini_tiles(pdf: FPDF, x: float, y: float, tile_w: float, tile_h: float,
               tiles: list[tuple[str, int, tuple, tuple]]) -> None:
    """Row of severity snapshot tiles: (label, count, accent, tint)."""
    gap = 3.0
    pdf.set_font(pdf.font_family, "", 7)
    for i, (label, count, accent, tint) in enumerate(tiles):
        tx = x + i * (tile_w + gap)
        pdf.set_fill_color(*tint)
        pdf.set_draw_color(*HAIRLINE)
        pdf.rect(tx, y, tile_w, tile_h, "DF")
        pdf.set_fill_color(*accent)
        pdf.rect(tx, y, tile_w, 1.1, "F")
        pdf.set_text_color(*MUTED)
        pdf.set_xy(tx, y + 3.0)
        pdf.cell(tile_w, 3.2, label.upper(), align="C")
        pdf.set_font(pdf.font_family, "B", 15)
        pdf.set_text_color(*INK)
        pdf.set_xy(tx, y + 6.2)
        pdf.cell(tile_w, 7.4, str(count), align="C")
        pdf.set_font(pdf.font_family, "", 7)
