"""
HTML to PDF Converter - Converts AI-generated HTML to print-quality PDF.
Uses weasyprint for high-fidelity rendering.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


def html_to_pdf(
    html_content: str,
    output_path: Path | str,
    *,
    css_path: Optional[Path | str] = None,
    base_url: Optional[str] = None,
) -> Path:
    """
    Convert HTML content to PDF.
    
    Args:
        html_content: Complete HTML document string
        output_path: Path to write the PDF
        css_path: Optional external CSS file to inject
        base_url: Base URL for resolving relative paths
        
    Returns:
        Path to the generated PDF
    """
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise RuntimeError(
            "weasyprint is required for HTML-to-PDF conversion. "
            "Install with: pip install weasyprint"
        )
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Inject CSS if provided and not already in the HTML
    if css_path and str(css_path) not in html_content:
        css_content = Path(css_path).read_text(encoding="utf-8")
        # Inject CSS before </head>
        if "</head>" in html_content:
            html_content = html_content.replace(
                "</head>",
                f"<style>\n{css_content}\n</style>\n</head>"
            )
    
    # Create weasyprint HTML object
    html = HTML(
        string=html_content,
        base_url=base_url or str(Path.cwd()),
    )
    
    # Generate PDF with page numbers
    from weasyprint import HTML, CSS
    
    # Add page number footer CSS
    footer_css = CSS(string="""
        @page {
            @bottom-center {
                content: counter(page) " / " counter(pages);
                font-size: 9pt;
                color: #666;
            }
        }
    """)
    
    html.write_pdf(
        str(output_path),
        stylesheets=[footer_css] if css_path is None else [CSS(filename=str(css_path)), footer_css]
    )
    
    return output_path


def validate_html(html_content: str) -> tuple[bool, list[str]]:
    """
    Validate HTML content for common issues.
    
    Returns:
        (is_valid, list_of_issues)
    """
    issues = []
    
    # Check for basic structure
    if "<!DOCTYPE html>" not in html_content and "<!doctype html>" not in html_content:
        issues.append("Missing DOCTYPE declaration")
    
    if "<html" not in html_content.lower():
        issues.append("Missing <html> tag")
    
    if "<head" not in html_content.lower():
        issues.append("Missing <head> section")
    
    if "<body" not in html_content.lower():
        issues.append("Missing <body> section")
    
    # Check for unclosed tags (basic check)
    open_tags = re.findall(r"<(\w+)[\s>]", html_content)
    close_tags = re.findall(r"</(\w+)>", html_content)
    
    # Count common tags
    for tag in ["div", "p", "section", "article", "header", "footer", "table", "tr", "td", "th"]:
        opens = len(re.findall(rf"<{tag}[\s>]", html_content, re.IGNORECASE))
        closes = len(re.findall(rf"</{tag}>", html_content, re.IGNORECASE))
        if opens != closes:
            issues.append(f"Mismatched <{tag}> tags: {opens} opens, {closes} closes")
    
    # Check for empty content
    if len(html_content.strip()) < 100:
        issues.append("HTML content appears too short")
    
    # Check for common CSS issues
    if "background:" in html_content and "color:" not in html_content:
        issues.append("Background set without text color (accessibility)")
    
    return len(issues) == 0, issues


def extract_text_from_html(html_content: str) -> str:
    """Extract plain text from HTML for validation/search."""
    # Remove script and style tags
    text = re.sub(r"<script[^>]*>.*?</script>", "", html_content, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    
    return text.strip()


def get_page_count_estimate(html_content: str) -> int:
    """Estimate page count based on content length."""
    text = extract_text_from_html(html_content)
    # Rough estimate: ~3000 characters per A4 page
    return max(1, len(text) // 3000 + 1)
