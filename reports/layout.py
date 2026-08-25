"""
Gedr Reporting Engine - PDF layout engine.

GedrPDF extends fpdf2 with the report's design language:

- Unicode font loading with graceful core-font fallback
- running header/footer system (brand, current section, classification,
  "Page X of Y")
- numbered section / subsection management
- reusable components: paragraphs, metadata grids, callouts, evidence
  code blocks, severity chips, finding cards, data tables, KPI tiles

Layout invariants:
- consistent margins on every page
- keep-together guards prevent stranded headings and split components
- tables repeat their header row across page breaks
"""
from __future__ import annotations

from typing import Iterable, Sequence

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from .sanitizer import sanitize_code
from .theme import (
    BODY, CHART_SERIES, FAINT, GRADE_BAND, GRADE_COLOR, HAIRLINE,
    INK, MARGIN_B, MARGIN_L, MARGIN_R, MARGIN_T, MUTED, NAVY, PAGE_H,
    PAGE_W, SEVERITY_COLORS, SEVERITY_DEFINITIONS, SEVERITY_ORDER,
    SEVERITY_TINTS, STEEL, SURFACE, SURFACE2, TYPE, WHITE,
    discover_fonts, grade_for,
)


class GedrPDF(FPDF):
    """Layout engine implementing the Gedr report design language."""

    def __init__(self, *, classification: str = "", report_id: str = "",
                 platform_label: str = "GEDR"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.classification = classification or "Confidential"
        self.report_id = report_id
        self.platform_label = platform_label
        self.current_section = ""
        self.section_no = 0

        self._load_fonts()
        self.set_margins(MARGIN_L, MARGIN_T, MARGIN_R)
        self.set_auto_page_break(auto=True, margin=MARGIN_B)
        self.alias_nb_pages()
        self.set_title(f"{self.platform_label} Security Analysis Report {report_id}".strip())
        self.set_author("Gedr - Automated Security Reporting")
        self.set_creator("Gedr Reporting Engine 3.0 (fpdf2)")
        self.set_subject("Automated security analysis report")
        self.set_keywords("security, SAST, vulnerability assessment, automated reporting")
        try:
            self.set_lang("en")
        except Exception:  # pragma: no cover - cosmetic only
            pass

    # ------------------------------------------------------------------ #
    # Fonts
    # ------------------------------------------------------------------ #
    def _load_fonts(self) -> None:
        bundle = discover_fonts()
        if bundle.unicode_capable and bundle.sans_bold:
            try:
                self.add_font("gedr", "", str(bundle.sans_regular))
                self.add_font("gedr", "B", str(bundle.sans_bold))
                if bundle.sans_italic:
                    self.add_font("gedr", "I", str(bundle.sans_italic))
                if bundle.mono_regular:
                    self.add_font("gedrmono", "", str(bundle.mono_regular))
                if bundle.mono_bold:
                    self.add_font("gedrmono", "B", str(bundle.mono_bold))
                self.font_sans = "gedr"
                self.font_mono = "gedrmono" if bundle.mono_regular else "courier"
                return
            except Exception:
                pass
        self.font_sans = "helvetica"
        self.font_mono = "courier"

    def sans(self, style: str = "", size: float | None = None) -> None:
        self.set_font(self.font_sans, style, size)

    def mono(self, style: str = "", size: float | None = None) -> None:
        self.set_font(self.font_mono, style, size)

    # ------------------------------------------------------------------ #
    # Header / footer system
    # ------------------------------------------------------------------ #
    HEADER_BRAND = "GEDR  \u00b7  SECURITY ANALYSIS REPORT"

    def header(self) -> None:
        if self.page_no() == 1:
            return  # cover carries its own masthead
        y = 12.5
        self.set_draw_color(*HAIRLINE)
        self.set_line_width(0.2)
        self.line(MARGIN_L, y + 4.4, PAGE_W - MARGIN_R, y + 4.4)
        self.sans("B", 7.2)
        self.set_text_color(*NAVY)
        self.set_xy(MARGIN_L, y)
        self.cell(90, 4.4, self.brand_text(self.HEADER_BRAND))
        if self.current_section:
            self.sans("", 7.2)
            self.set_text_color(*MUTED)
            title = self.current_section
            while self.get_string_width(title) > 92 and len(title) > 12:
                title = title[:-2]
            self.set_xy(PAGE_W - MARGIN_R - 92, y)
            self.cell(92, 4.4, title, align="R")
        # Leave the cursor where fpdf2 expects it after a page break.
        self.set_xy(MARGIN_L, MARGIN_T)

    def footer(self) -> None:
        y = PAGE_H - 13.0
        self.set_draw_color(*HAIRLINE)
        self.set_line_width(0.2)
        self.line(MARGIN_L, y, PAGE_W - MARGIN_R, y)
        self.sans("", 6.8)
        self.set_text_color(*FAINT)
        self.set_xy(MARGIN_L, y + 1.6)
        self.cell(80, 3.6, self.brand_text("Generated by Gedr \u00b7 Automated security reporting"))
        self.set_xy(PAGE_W / 2 - 20, y + 1.6)
        self.cell(40, 3.6, f"Page {self.page_no()} of {{nb}}", align="C")
        self.set_xy(PAGE_W - MARGIN_R - 78, y + 1.6)
        self.sans("B", 6.8)
        self.set_text_color(*MUTED)
        self.cell(78, 3.6, self.brand_text(f"{self.report_id}  \u00b7  {self.classification}").upper(),
                  align="R")

    def brand_text(self, text: str) -> str:
        """Branding text; transliterates the schwa on core-font fallback."""
        if self.font_sans == "gedr":
            return text
        return text.replace("\u0259", "e")

    # ------------------------------------------------------------------ #
    # Sections
    # ------------------------------------------------------------------ #
    def open_section(self, title: str, *, numbered: bool = True, new_page: bool = True) -> str:
        self.section_no += 1
        label = f"{self.section_no}.  {title}" if numbered else title
        # Set before add_page so the running header of the new page shows it.
        self.current_section = f"{self.section_no}. {title}" if numbered else title
        if new_page:
            self.add_page()

        y = self.get_y()
        self.set_fill_color(*NAVY)
        self.rect(MARGIN_L, y, 1.6, TYPE.h1 * 0.62 + 1.6, "F")
        self.sans("B", TYPE.h1)
        self.set_text_color(*INK)
        self.set_xy(MARGIN_L + 4.6, y)
        self.cell(0, TYPE.h1 * 0.62 + 1.6, self._disp(label), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1.2)
        self.set_draw_color(*HAIRLINE)
        self.set_line_width(0.25)
        self.line(MARGIN_L, self.get_y(), PAGE_W - MARGIN_R, self.get_y())
        self.ln(5)
        return label

    def subsection(self, title: str) -> None:
        self.ensure_space(TYPE.h2 * 0.62 + 10)
        y = self.get_y()
        self.sans("B", TYPE.h2)
        self.set_text_color(*INK)
        self.set_xy(MARGIN_L, y)
        self.cell(0, TYPE.h2 * 0.62 + 1.4, self._disp(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1.0)

    # ------------------------------------------------------------------ #
    # Primitives
    # ------------------------------------------------------------------ #
    def _disp(self, text: str) -> str:
        if self.font_sans == "helvetica":
            return (text.replace("\u0259", "e").replace("\u2019", "'")
                        .replace("\u201c", '"').replace("\u201d", '"')
                        .replace("\u2014", "-").replace("\u2013", "-")
                        .replace("\u2026", "...").replace("\u00b7", "-")
                        .replace("\u2192", "->"))
        return text

    def ensure_space(self, needed: float) -> None:
        if self.get_y() + needed > self.page_break_trigger - 4:
            self.add_page()

    def para(self, text: str, *, size: float | None = None, style: str = "",
             color: tuple | None = None, align: str = "L",
             line_h: float | None = None, indent: float = 0.0) -> None:
        size = size or TYPE.body
        line_h = line_h if line_h else size * 0.48
        self.sans(style, size)
        self.set_text_color(*(color or BODY))
        x = MARGIN_L + indent
        w = PAGE_W - MARGIN_R - x
        self.set_xy(x, self.get_y())
        for chunk in str(text).split("\n"):
            self.multi_cell(w, line_h, self._disp(chunk), align=align,
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1.2)

    def kv_grid(self, pairs: Sequence[tuple[str, str]], *,
                cols: int = 2, box_pad: float = 3.0, row_gap: float = 2.4) -> None:
        """Metadata grid of label/value boxes."""
        if not pairs:
            return
        gap = 4.0
        box_w = (PAGE_W - MARGIN_L - MARGIN_R - gap * (cols - 1)) / cols
        row_h_est = 11.5
        for start in range(0, len(pairs), cols):
            chunk = pairs[start:start + cols]
            self.ensure_space(row_h_est + 6)
            y0 = self.get_y()
            max_lines = 1
            for j, (label, value) in enumerate(chunk):
                bx = MARGIN_L + j * (box_w + gap)
                self.set_fill_color(*SURFACE)
                self.rect(bx, y0, box_w, row_h_est, "F")
                self.set_draw_color(*HAIRLINE)
                self.rect(bx, y0, box_w, row_h_est, "D")
                self.sans("B", 6.4)
                self.set_text_color(*MUTED)
                self.set_xy(bx + box_pad, y0 + 1.6)
                self.cell(box_w - 2 * box_pad, 3.0, self._disp(label).upper())
                self.sans("", 8.6)
                self.set_text_color(*INK)
                value = self._disp(value or "-")
                vw = box_w - 2 * box_pad
                trimmed = False
                while self.get_string_width(value) > vw and len(value) > 8:
                    value = value[:-2]
                    trimmed = True
                if trimmed and not value.endswith("\u2026"):
                    value = value.rstrip() + "\u2026"
                self.set_xy(bx + box_pad, y0 + 5.0)
                self.cell(vw, 4.6, value)
            self.set_y(y0 + row_h_est + row_gap)

    def callout(self, kind: str, title: str, body: str, *, indent: float = 0.0) -> None:
        styles = {
            "info": (STEEL, (238, 242, 247)),
            "warn": (SEVERITY_COLORS["Medium"], (250, 246, 232)),
            "note": (MUTED, SURFACE),
            "ok": (SEVERITY_COLORS["Low"], (236, 245, 240)),
        }
        accent, tint = styles.get(kind, styles["note"])
        w = PAGE_W - MARGIN_L - MARGIN_R - indent
        self.ensure_space(16)
        self.sans("", TYPE.body)
        est = self._estimate_height(body, TYPE.small, w - 14) + 11
        self.ensure_space(est + 4)
        y = self.get_y()
        self.set_fill_color(*tint)
        self.rect(MARGIN_L + indent, y, w, est, "F")
        self.set_fill_color(*accent)
        self.rect(MARGIN_L + indent, y, 1.4, est, "F")
        tx = MARGIN_L + indent + 6
        self.sans("B", 8.4)
        self.set_text_color(*accent)
        self.set_xy(tx, y + 2.6)
        self.cell(w - 10, 3.6, self._disp(title).upper())
        self.sans("", TYPE.small)
        self.set_text_color(*BODY)
        self.set_xy(tx, y + 6.4)
        lines = self._wrap(body, TYPE.small, w - 12)
        lh = TYPE.small * 0.46
        self.multi_cell(w - 12, lh, self._disp(lines), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(max(y + est, self.get_y()) + 2.6)

    def code_block(self, code: str, caption: str = "EVIDENCE", *,
                   max_lines: int = 14) -> None:
        lines, omitted = sanitize_code(code, max_lines=max_lines)
        if not lines:
            return
        lh = TYPE.mono * 0.52
        head_h = 6.2
        block_h = head_h + len(lines) * lh + (3.4 if omitted else 2.6)
        self.ensure_space(min(block_h, 60))  # allow split across pages for long blocks
        y = self.get_y()
        w = PAGE_W - MARGIN_L - MARGIN_R
        self.set_fill_color((28, 32, 40))
        self.rect(MARGIN_L, y, w, head_h, "F")
        self.sans("B", 6.6)
        self.set_text_color(*WHITE)
        self.set_xy(MARGIN_L + 3, y + 1.7)
        self.cell(w - 6, 3.0, caption)
        gutter_w = 9.0
        body_x, body_w = MARGIN_L, w
        inner_y = y + head_h
        self.sans("", 7.6)
        line_count = len(lines)
        body_h = line_count * lh + 2.4
        self.set_fill_color(*SURFACE)
        self.rect(body_x, inner_y, body_w, body_h, "F")
        self.set_draw_color(*HAIRLINE)
        self.rect(body_x, inner_y, body_w, body_h, "D")
        ty = inner_y + 1.2
        for i, line in enumerate(lines, start=1):
            self.mono("", TYPE.mono)
            self.set_text_color(*FAINT)
            self.set_xy(body_x + 2.2, ty)
            self.cell(gutter_w, lh, f"{i:>3}")
            self.set_text_color(*BODY)
            shown = line if self.font_mono != "courier" else (
                line.replace("\u2026", "..'").replace("\u2588", "#"))
            self.set_xy(body_x + gutter_w + 2.4, ty)
            avail = body_w - gutter_w - 6
            while self.get_string_width(shown) > avail and len(shown) > 6:
                shown = shown[:-2] + ("\u2026" if self.font_mono != "courier" else "..'")
            self.cell(avail, lh, shown)
            ty += lh
        if omitted:
            self.sans("I", 6.8)
            self.set_text_color(*FAINT)
            self.set_xy(body_x + 2.2, ty + 0.4)
            self.cell(body_w - 4, 3.0, self._disp(f"+ {omitted} more line(s) not shown - "
                                                  f"see source location for full context"))
        self.set_y(inner_y + body_h + 3.0)

    def severity_chip(self, x: float, y: float, severity: str, score: int | None = None,
                      scale: float = 1.0) -> float:
        """Draw a labelled chip; returns its width. Greyscale-safe by design:
        rank is carried by the text label and score, colour only reinforces it."""
        color = SEVERITY_COLORS.get(severity, MUTED)
        tint = SEVERITY_TINTS.get(severity, SURFACE)
        text = severity.upper()
        h = 5.0 * scale
        self.sans("B", 6.8 * scale)
        label_w = self.get_string_width(text) + 1.2
        score_w = 8.6 * scale if score is not None else 0.0
        tw = 4.8 * scale + label_w + (score_w if score is not None else 0.0) + 1.4 * scale
        self.set_fill_color(*tint)
        self.set_draw_color(*color)
        self.set_line_width(0.22)
        self.rect(x, y, tw, h, "DF")
        # marker: filled square so severity rank also reads in greyscale
        m = 2.1 * scale
        self.set_fill_color(*color)
        self.rect(x + 1.7 * scale, y + h / 2 - m / 2, m, m, "F")
        self.set_text_color(*color)
        self.set_xy(x + 4.8 * scale, y)
        self.cell(label_w, h, self._disp(text))
        if score is not None:
            self.sans("B", 6.8 * scale)
            self.set_text_color(*color)
            self.set_xy(x + 4.8 * scale + label_w, y)
            self.cell(score_w, h, f"{score}/10", align="R")
        return tw

    def kpi_tiles(self, tiles: Sequence[tuple[str, str, str]], *, cols: int = 4,
                  tile_h: float = 17.5) -> None:
        """(label, big value, sub-label) KPI strip."""
        gap = 4.0
        tile_w = (PAGE_W - MARGIN_L - MARGIN_R - gap * (cols - 1)) / cols
        self.ensure_space(tile_h + 4)
        y = self.get_y()
        for i, (label, value, sub) in enumerate(tiles):
            tx = MARGIN_L + i * (tile_w + gap)
            self.set_fill_color(*SURFACE)
            self.set_draw_color(*HAIRLINE)
            self.rect(tx, y, tile_w, tile_h, "DF")
            self.set_fill_color(*NAVY)
            self.rect(tx, y, 0.9, tile_h, "F")
            self.sans("B", 6.4)
            self.set_text_color(*MUTED)
            self.set_xy(tx + 3.4, y + 2.4)
            self.cell(tile_w - 4, 3.2, self._disp(label).upper())
            vsize = 15 if len(str(value)) <= 4 else (12 if len(str(value)) <= 8 else 9)
            self.sans("B", vsize)
            self.set_text_color(*INK)
            self.set_xy(tx + 3.4, y + 5.8)
            self.cell(tile_w - 4, 7.2, self._disp(str(value)))
            self.sans("", 6.6)
            self.set_text_color(*MUTED)
            sub2 = sub
            trimmed = False
            while self.get_string_width(sub2) > tile_w - 5 and len(sub2) > 8:
                sub2 = sub2[:-2]
                trimmed = True
            if trimmed and not sub2.endswith("\u2026"):
                sub2 = sub2.rstrip() + "\u2026"
            self.set_xy(tx + 3.4, y + 13.2)
            self.cell(tile_w - 4, 3.4, self._disp(sub2))
        self.set_y(y + tile_h + 3.4)

    def data_table(self, headers: Sequence[str], rows: Sequence[Sequence[str]],
                   widths: Sequence[float], aligns: Sequence[str], *,
                   font_size: float = 8.0, heading_size: float | None = None) -> None:
        """Data table with repeated headers across pages and zebra striping.

        Cell fills are set explicitly: fpdf2 tables otherwise inherit the
        ambient document fill colour, which produced stray backgrounds when
        a chart had just drawn coloured elements.
        """
        if not rows:
            return
        self.ensure_space(24)
        self.sans("", font_size)
        self.set_draw_color(*HAIRLINE)
        self.set_line_width(0.15)
        # fpdf2 snapshots the ambient fill colour as the base cell style, so
        # reset it to white; zebra rows are applied explicitly below.
        self.set_fill_color(255, 255, 255)
        heading_style = FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=NAVY)
        with self.table(
            col_widths=tuple(widths),
            text_align=tuple(aligns),
            line_height=font_size * 0.52,
            headings_style=heading_style,
            repeat_headings=1,
            borders_layout="HORIZONTAL_LINES",
            padding=1.15,
            cell_fill_color=SURFACE2,
            cell_fill_mode="EVEN_ROWS",
        ) as t:
            hr = t.row()
            for htxt in headers:
                hr.cell(self._disp(htxt))
            for row in rows:
                r = t.row()
                for cellv in row:
                    r.cell(self._disp("" if cellv is None else str(cellv)))
        self.ln(2.4)

    def bullet_list(self, items: Iterable[str], *, size: float | None = None,
                    indent: float = 2.0) -> None:
        size = size or TYPE.body
        for item in items:
            self.ensure_space(size * 1.4)
            y = self.get_y()
            self.set_fill_color(*STEEL)
            self.rect(MARGIN_L + indent, y + size * 0.16, 1.6, 1.6, "F")
            self.para(item, size=size, indent=indent + 4.2)

    def _wrap(self, text: str, size: float, width: float) -> str:
        """Greedy wrap used to pre-measure component heights."""
        self.sans("", size)
        out_lines: list[str] = []
        for raw in str(text).split("\n"):
            words = raw.split(" ")
            line = ""
            for word in words:
                trial = word if not line else line + " " + word
                if self.get_string_width(trial) <= width or not line:
                    line = trial
                else:
                    out_lines.append(line)
                    line = word
            out_lines.append(line)
        return "\n".join(out_lines)

    def _estimate_height(self, text: str, size: float, width: float) -> float:
        wrapped = self._wrap(text, size, width)
        return len(wrapped.split("\n")) * size * 0.46

