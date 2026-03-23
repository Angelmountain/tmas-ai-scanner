#!/usr/bin/env python3
"""
Generate PowerPoint report from security assessment Excel data.

Reads Excel files produced by the security assessment pipeline and embeds
chart data into a PowerPoint template, creating a branded Trend Micro
NDR Security Assessment report.

Usage (CLI):
    python generate_ppt_report.py \\
        --template templates/NDR_Security_Assessment.pptx \\
        --data-dir output_directory \\
        --output reports/final_report.pptx

Usage (module):
    from generate_ppt_report import generate_report
    path = generate_report(
        template_path="templates/NDR_Security_Assessment.pptx",
        data_dir="output_directory",
        output_path="reports/final_report.pptx",
    )
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import openpyxl
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Trend Micro brand colours
TREND_COLORS = {
    "red": RGBColor(0xD5, 0x2B, 0x1E),       # #D52B1E
    "dark_gray": RGBColor(0x4A, 0x4A, 0x4A),  # #4A4A4A
    "light_gray": RGBColor(0x9B, 0x9B, 0x9B),
    "blue": RGBColor(0x00, 0x7C, 0xB0),       # #007CB0
    "white": RGBColor(0xFF, 0xFF, 0xFF),
}

# Mapping from search/topic names to 1-indexed slide numbers in the
# 44-slide NDR Security Assessment template.  Slides with charts:
# 6-15, 17-18, 20-27, 29-31, 33-35, 37-39, (40-44 for newer searches).
# A value of None means the search has no corresponding slide and will
# only appear in the Excel export.
SLIDE_MAPPING: Dict[str, Optional[int]] = {
    "Network Detections": 6,
    "Top Accounts used": 7,
    "Server ports used": 8,
    "Unsuccessful logon": 9,
    "Top File used": 10,
    "Top File types used": 11,
    "Protocols used": 12,
    "Request methods": 13,
    "Response codes": 14,
    "SSL Cert Common Name": 15,
    "SSH Detections": 17,
    "SSH Versions": 18,
    "PUA AI Services": 20,
    "PUA Remote Access": 22,
    "PUA Cloud Storage": 23,
    "PUA VPN Services": 24,
    "PUA Pastebin": 25,
    "PUA Darknet links": 26,
    "PUA Administrator Usage": 27,
    "RDP User Usage": 29,
    "RDP Source IP": 30,
    "RDP Destination IP": 31,
    "Suspicious TLDs": 33,
    "Bad States": 34,
    "Russian IT-companies": 35,
    "Chinese IT-companies": 36,
    "EPP/EDR/XDR Vendors": 37,
    "Firewall Vendors": 38,
    "US Vendors": 39,
    "External Attacks": 40,
    "Web Rep RU": 41,
    "RDP Detections": 42,
    "Root Detections": 43,
    "DNS Dead IP": 44,
    # Searches without a dedicated slide
    "File Downloads": None,
    "Cert Downloads": None,
    "External RDP": None,
    "External SSH": None,
    "External Protocols": None,
}

# Maximum categories shown per chart / table for readability
MAX_CHART_CATEGORIES = 15
MAX_TABLE_ROWS = 10

# Default template location (relative to repository root)
DEFAULT_TEMPLATE = "templates/NDR_Security_Assessment.pptx"


# ---------------------------------------------------------------------------
# PowerPointReportGenerator
# ---------------------------------------------------------------------------

class PowerPointReportGenerator:
    """Load a .pptx template, inject chart data from Excel files, and save."""

    def __init__(self, template_path: Path, output_path: Path):
        self.template_path = template_path
        self.output_path = output_path
        self.prs: Optional[Presentation] = None
        self._stats: Dict[str, str] = {}  # search_name -> status string

    # -- lifecycle ----------------------------------------------------------

    def load_template(self) -> None:
        """Open the PowerPoint template."""
        if not self.template_path.exists():
            raise FileNotFoundError(f"Template not found: {self.template_path}")
        logger.info("Loading template: %s", self.template_path)
        self.prs = Presentation(str(self.template_path))
        logger.info("Template loaded with %d slides", len(self.prs.slides))

    def save(self) -> Path:
        """Write the updated presentation to *output_path*."""
        if self.prs is None:
            raise RuntimeError("No presentation loaded; call load_template() first")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.prs.save(str(self.output_path))
        logger.info("Report saved to: %s", self.output_path)
        return self.output_path

    # -- data ingestion -----------------------------------------------------

    @staticmethod
    def read_excel_data(excel_path: Path) -> List[Tuple[str, int]]:
        """Return up to *MAX_CHART_CATEGORIES* (category, count) pairs from *excel_path*.

        Expects two columns: Category (col A) and Count (col B), with a
        header row.  Rows with missing or non-positive counts are skipped.
        """
        try:
            wb = openpyxl.load_workbook(excel_path, data_only=True)
            ws = wb.active

            data: List[Tuple[str, int]] = []
            for row in ws.iter_rows(min_row=2, values_only=True):
                if row is None or len(row) < 2:
                    continue
                category = str(row[0]).strip() if row[0] else "Unknown"
                try:
                    value = int(row[1]) if row[1] is not None else 0
                except (ValueError, TypeError):
                    value = 0
                if category and value > 0:
                    data.append((category, value))

            wb.close()
            return data[:MAX_CHART_CATEGORIES]

        except Exception:
            logger.exception("Failed to read Excel file %s", excel_path)
            return []

    @staticmethod
    def find_excel_file(search_name: str, data_dir: Path) -> Optional[Path]:
        """Locate the Excel file for *search_name* inside *data_dir*.

        Tries exact-prefix glob patterns first (_horizontal, _vertical,
        generic), then falls back to a normalised substring match.
        """
        patterns = [
            f"{search_name}*_horizontal.xlsx",
            f"{search_name}*_vertical.xlsx",
            f"{search_name}*.xlsx",
        ]

        for pattern in patterns:
            matches = sorted(data_dir.glob(pattern))
            if matches:
                return matches[0]

        # Fuzzy fallback: strip spaces / underscores and compare lower-case
        clean = search_name.lower().replace(" ", "").replace("/", "").replace("\\", "")
        for xlsx_file in sorted(data_dir.glob("*.xlsx")):
            stem = xlsx_file.stem.lower().replace(" ", "").replace("_", "")
            if clean in stem:
                return xlsx_file

        return None

    # -- slide manipulation -------------------------------------------------

    def update_chart_on_slide(
        self, slide_num: int, data: List[Tuple[str, int]], title: str
    ) -> bool:
        """Replace chart data on slide *slide_num* (1-indexed).

        If the chart uses an unsupported type (e.g. 3-D) that cannot be
        updated via ``replace_data``, a data table is added instead.
        Returns True on success.
        """
        if self.prs is None:
            raise RuntimeError("No presentation loaded")

        total_slides = len(self.prs.slides)
        if slide_num < 1 or slide_num > total_slides:
            logger.warning(
                "Slide %d out of range (template has %d slides) for '%s'",
                slide_num,
                total_slides,
                title,
            )
            return False

        slide = self.prs.slides[slide_num - 1]

        # Locate the first chart shape on the slide
        chart_shape = None
        for shape in slide.shapes:
            if hasattr(shape, "has_chart") and shape.has_chart:
                chart_shape = shape
                break

        chart_updated = False

        if chart_shape is not None:
            try:
                chart = chart_shape.chart
                chart_data = CategoryChartData()
                chart_data.categories = [item[0] for item in data]
                chart_data.add_series("Count", [item[1] for item in data])
                chart.replace_data(chart_data)
                chart_updated = True
                logger.info(
                    "Updated chart on slide %d for '%s' (%d categories)",
                    slide_num,
                    title,
                    len(data),
                )
            except Exception:
                logger.warning(
                    "Cannot update chart on slide %d (likely 3D); "
                    "adding data table instead for '%s'",
                    slide_num,
                    title,
                    exc_info=True,
                )

        if not chart_updated:
            self._add_data_table(slide, data, title)

        return True

    # -- data table fallback ------------------------------------------------

    @staticmethod
    def _add_data_table(
        slide, data: List[Tuple[str, int]], title: str
    ) -> None:
        """Insert a small data table near the bottom of *slide*."""
        data = data[:MAX_TABLE_ROWS]
        if not data:
            logger.warning("No data to add table for '%s'", title)
            return

        rows = len(data) + 1  # +1 for header
        cols = 2
        left = Inches(0.5)
        top = Inches(4.5)
        width = Inches(5.0)
        height = Inches(0.3 * rows)

        # Clamp height so the table does not overflow the slide
        max_height = Inches(2.5)
        if height > max_height:
            height = max_height

        try:
            table_shape = slide.shapes.add_table(rows, cols, left, top, width, height)
            table = table_shape.table

            # Header row
            table.cell(0, 0).text = "Category"
            table.cell(0, 1).text = "Count"
            for col_idx in range(cols):
                cell = table.cell(0, col_idx)
                cell.fill.solid()
                cell.fill.fore_color.rgb = TREND_COLORS["red"]
                for paragraph in cell.text_frame.paragraphs:
                    paragraph.font.color.rgb = TREND_COLORS["white"]
                    paragraph.font.bold = True
                    paragraph.font.size = Pt(10)

            # Data rows
            for row_idx, (category, value) in enumerate(data, start=1):
                cat_text = (
                    str(category)[:40] + "..."
                    if len(str(category)) > 40
                    else str(category)
                )
                table.cell(row_idx, 0).text = cat_text
                table.cell(row_idx, 1).text = str(value)

                for col_idx in range(cols):
                    cell = table.cell(row_idx, col_idx)
                    for paragraph in cell.text_frame.paragraphs:
                        paragraph.font.size = Pt(9)
                        paragraph.font.color.rgb = TREND_COLORS["dark_gray"]

            # Column widths
            table.columns[0].width = Inches(3.5)
            table.columns[1].width = Inches(1.5)

            logger.info(
                "Added data table (%d rows) to slide for '%s'",
                len(data),
                title,
            )
        except Exception:
            logger.exception("Failed to add data table for '%s'", title)

    # -- orchestration ------------------------------------------------------

    def process_all(self, data_dir: Path) -> Dict[str, str]:
        """Walk *SLIDE_MAPPING* and update every slide that has a matching Excel file.

        The *data_dir* may contain a ``ppt/`` subdirectory; if present it is
        searched first.

        Returns a dict mapping search names to a status string (one of
        "updated", "table_added", "no_data", "no_file", "skipped").
        """
        results: Dict[str, str] = {}

        # Prefer a "ppt" sub-folder if it exists
        ppt_dir = data_dir / "ppt"
        if not ppt_dir.is_dir():
            ppt_dir = data_dir

        logger.info("Searching for Excel files in: %s", ppt_dir)

        for search_name, slide_num in SLIDE_MAPPING.items():
            # Locate Excel file (try ppt_dir first, then data_dir)
            excel_file = self.find_excel_file(search_name, ppt_dir)
            if excel_file is None and ppt_dir != data_dir:
                excel_file = self.find_excel_file(search_name, data_dir)

            if excel_file is None:
                logger.debug("No Excel file found for '%s'", search_name)
                results[search_name] = "no_file"
                continue

            logger.info(
                "Found '%s' -> %s", search_name, excel_file.name
            )

            data = self.read_excel_data(excel_file)
            if not data:
                logger.warning("Excel file for '%s' contains no usable data", search_name)
                results[search_name] = "no_data"
                continue

            if slide_num is None:
                logger.info(
                    "'%s' has no slide mapping; data available in Excel only",
                    search_name,
                )
                results[search_name] = "skipped"
                continue

            success = self.update_chart_on_slide(slide_num, data, search_name)
            results[search_name] = "updated" if success else "failed"

        self._stats = results
        return results


# ---------------------------------------------------------------------------
# Public API for module-level imports
# ---------------------------------------------------------------------------

def generate_report(
    template_path: str,
    data_dir: str,
    output_path: Optional[str] = None,
    *,
    log_level: str = "INFO",
) -> Optional[Path]:
    """High-level helper: generate a PowerPoint report in one call.

    Parameters
    ----------
    template_path:
        Path to the ``.pptx`` template.
    data_dir:
        Directory containing Excel files (may have a ``ppt/`` sub-folder).
    output_path:
        Destination ``.pptx`` file.  If *None* a timestamped file is
        written next to the template.
    log_level:
        Python log-level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).

    Returns
    -------
    pathlib.Path to the written report, or *None* on failure.
    """
    _configure_logging(log_level)

    template = Path(template_path)
    data = Path(data_dir)

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = template.parent / f"NDR_Security_Assessment_Report_{timestamp}.pptx"
    else:
        output = Path(output_path)

    try:
        gen = PowerPointReportGenerator(template, output)
        gen.load_template()
        results = gen.process_all(data)

        updated = sum(1 for v in results.values() if v == "updated")
        total_mapped = sum(1 for v in SLIDE_MAPPING.values() if v is not None)
        logger.info(
            "Charts updated: %d / %d mapped slides", updated, total_mapped
        )

        return gen.save()

    except Exception:
        logger.exception("Report generation failed")
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _configure_logging(level_name: str = "INFO") -> None:
    """Set up root logger with a consistent format."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a Trend Micro NDR Security Assessment PowerPoint report "
            "from Excel data files."
        ),
    )
    parser.add_argument(
        "--template",
        default=DEFAULT_TEMPLATE,
        help=(
            "Path to the .pptx template "
            f"(default: {DEFAULT_TEMPLATE})"
        ),
    )
    parser.add_argument(
        "--data-dir",
        required=True,
        help="Directory containing the Excel (.xlsx) files with assessment data.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Output .pptx file path.  Defaults to a timestamped file in "
            "the same directory as the template."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.  Returns 0 on success, 1 on failure."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    result = generate_report(
        template_path=args.template,
        data_dir=args.data_dir,
        output_path=args.output,
        log_level=args.log_level,
    )

    if result is None:
        logger.error("Report generation failed.")
        return 1

    print(f"Report written to: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
