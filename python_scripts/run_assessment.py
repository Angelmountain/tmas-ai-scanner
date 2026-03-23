#!/usr/bin/env python3
"""
run_assessment.py - Security Assessment Orchestrator

Reads a CSV of search definitions, queries the Trend Micro Vision One API for
network activities and detections, aggregates results, exports to Excel, and
optionally generates a PowerPoint report.

Progress and completion are emitted as JSON lines on stdout so a Node.js
backend can parse them. All human-readable logging goes to stderr.

Usage:
    python run_assessment.py --csv templates/input.csv --output results --time-interval 720

Environment variables:
    TREND_MICRO_API_KEY   - Vision One API token (required)
    TREND_MICRO_BASE_URL  - API base URL (default: https://api.eu.xdr.trendmicro.com)
"""

import argparse
import csv
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging - all log output goes to stderr so stdout stays clean for JSON lines
# ---------------------------------------------------------------------------
_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logging.root.addHandler(_log_handler)
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("run_assessment")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PAGE_SIZE = 5000  # Maximum records per API page
MAX_WORKERS = 3   # Concurrent search threads

# Thread-safe lock for writing JSON lines to stdout
_stdout_lock = threading.Lock()


# ---------------------------------------------------------------------------
# JSON line helpers (stdout, for the Node.js backend)
# ---------------------------------------------------------------------------
def emit_json(obj: dict) -> None:
    """Write a single JSON line to stdout, thread-safe."""
    line = json.dumps(obj, separators=(",", ":"))
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def emit_progress(current: int, total: int, name: str) -> None:
    emit_json({"type": "progress", "current": current, "total": total, "name": name})


def emit_error(message: str, name: Optional[str] = None) -> None:
    payload: dict = {"type": "error", "message": message}
    if name:
        payload["name"] = name
    emit_json(payload)


def emit_complete(
    status: str,
    files: List[str],
    summary: Dict[str, int],
    errors: Optional[List[str]] = None,
) -> None:
    payload: dict = {
        "type": "complete",
        "status": status,
        "files": files,
        "summary": summary,
    }
    if errors:
        payload["errors"] = errors
    emit_json(payload)


# ---------------------------------------------------------------------------
# HTTP session with retry logic
# ---------------------------------------------------------------------------
def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# API interaction
# ---------------------------------------------------------------------------
class VisionOneClient:
    """Thin wrapper around the Trend Micro Vision One search API."""

    ENDPOINTS = {
        "network": "/v3.0/search/networkActivities",
        "detections": "/v3.0/search/detections",
    }

    def __init__(self, api_key: str, base_url: str) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = _build_session()

    # ----- helpers -----
    @staticmethod
    def determine_log_type(query: str) -> str:
        """Heuristic: pick log type from query keywords."""
        q = query.lower()
        detection_keywords = [
            "pname:", "rulename:", "attachmentfilename:",
            "eventname:", "filterrisklevel:", "productcode:", "sensor",
        ]
        if any(kw in q for kw in detection_keywords):
            return "detections"
        return "network"

    # ----- single chunk search (paginated, up to API limit) -----
    def _search_chunk(
        self,
        log_type: str,
        start_time: str,
        end_time: str,
        query: Optional[str] = None,
        select: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search a single time chunk with pagination."""
        url = f"{self.base_url}{self.ENDPOINTS[log_type]}"
        headers: Dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if query:
            headers["TMV1-Query"] = query.strip()

        results: List[Dict[str, Any]] = []
        next_link: Optional[str] = None

        while True:
            if not next_link or not next_link.startswith("http"):
                params: Dict[str, Any] = {
                    "startDateTime": start_time,
                    "endDateTime": end_time,
                    "top": PAGE_SIZE,
                }
                if select:
                    params["select"] = select
                if next_link:
                    params["nextPageToken"] = next_link
                request_url = url
            else:
                params = {}
                request_url = next_link

            try:
                resp = self.session.get(
                    request_url, params=params, headers=headers, timeout=60
                )
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 60))
                    logger.warning("Rate-limited. Sleeping %ds ...", wait)
                    time.sleep(wait)
                    continue
            except requests.exceptions.RequestException as exc:
                logger.error("Request failed: %s", exc)
                break

            if resp.status_code == 200:
                body = resp.json()
                items = body.get("items", [])
                if items:
                    results.extend(items)
                next_link = body.get("nextPageToken") or body.get("nextLink")
                if not next_link:
                    break
            else:
                logger.error(
                    "API error: %s returned %d - %s",
                    log_type, resp.status_code, resp.text[:500],
                )
                break

        return results

    # ----- time-chunked search (bypasses 10K record limit) -----
    def search_logs(
        self,
        log_type: str,
        start_time: str,
        end_time: str,
        query: Optional[str] = None,
        sorting_field: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a search with time-chunking to bypass the 10K record limit.

        The Vision One API returns max ~10,000 records per search. To get
        the full dataset we split into 6-hour chunks and merge results.

        Uses ``select`` to request only the aggregation field, which makes
        records tiny and allows more to fit within the 10K-per-page limit.
        """
        if log_type not in ("network", "detections", "everything"):
            logger.error("Invalid log type '%s'.", log_type)
            return []

        log_types = (
            ["network", "detections"] if log_type == "everything" else [log_type]
        )

        # Build select parameter for network searches (detections API ignores it)
        select = None
        if sorting_field and log_type == "network":
            sf_lower = sorting_field.strip().lower()
            api_field = _FIELD_NAME_MAP.get(sf_lower, sorting_field.strip())
            if api_field:
                select = api_field

        # Calculate time chunks — 6-hour windows for maximum coverage
        start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%SZ")
        end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%SZ")
        duration_hours = (end_dt - start_dt).total_seconds() / 3600
        chunk_hours = 6
        num_chunks = max(1, int(duration_hours / chunk_hours) + 1)

        all_results: List[Dict[str, Any]] = []

        for lt in log_types:
            sel = select if lt == "network" else None
            logger.info(
                "Searching %s | %d chunks of %dh | select=%s | query: %s",
                lt, num_chunks, chunk_hours, sel, (query or "")[:80],
            )

            chunk_start = start_dt
            for chunk_idx in range(num_chunks):
                chunk_end = min(chunk_start + timedelta(hours=chunk_hours), end_dt)
                if chunk_start >= end_dt:
                    break
                cs = chunk_start.strftime("%Y-%m-%dT%H:%M:%SZ")
                ce = chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ")

                items = self._search_chunk(lt, cs, ce, query=query, select=sel)
                if items:
                    all_results.extend(items)
                    if chunk_idx % 10 == 0 or len(items) >= 9000:
                        logger.info(
                            "Chunk %d/%d: %d items (total: %d)",
                            chunk_idx + 1, num_chunks, len(items), len(all_results),
                        )

                chunk_start = chunk_end
                time.sleep(0.15)  # Rate limit friendly

            logger.info("Completed %s search. Total items: %d", lt, len(all_results))

        return all_results


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

# Map of (search_name_lower, sorting_field_lower) -> (label_col, count_col, item_key)
_AGGREGATION_RULES: Dict[Tuple[str, str], Tuple[str, str, str]] = {
    # Core network
    ("network detections", "rulename"): ("Rule Name", "Occurrences", "ruleName"),
    ("top accounts used", "suid"): ("Account Name", "Usage Count", "suid"),
    ("server ports used", "serverport"): ("Server Port", "Connection Count", "serverPort"),
    ("unsuccessful logon", "rulename"): ("Rule Name", "Failed Logon Attempts", "ruleName"),
    ("top file used", "filename"): ("File Name", "Access Count", "fileName"),
    ("top file types used", "filetype"): ("File Type", "Access Count", "fileType"),
    ("protocols used", "app"): ("Protocol", "Usage Count", "app"),
    ("request methods", "requestmethod"): ("Request Method", "Usage Count", "requestMethod"),
    ("response codes", "respcode"): ("Response Code", "Occurrences", "respCode"),
    ("ssl cert common name", "sslcertcommonname"): ("SSL Certificate", "Occurrences", "sslCertCommonName"),
    # SSH
    ("ssh detections", "rulename"): ("SSH Rule Name", "Detection Count", "ruleName"),
    ("ssh versions", "respappversion"): ("SSH Version", "Connection Count", "respAppVersion"),
    # PUA - all hostname based
    ("pua ai services", "hostname"): ("AI Service", "Access Count", "hostName"),
    ("pua remote access", "hostname"): ("Remote Access Tool", "Access Count", "hostName"),
    ("pua cloud storage", "hostname"): ("Cloud Storage Service", "Access Count", "hostName"),
    ("pua vpn services", "hostname"): ("VPN Service", "Access Count", "hostName"),
    ("pua pastebin", "hostname"): ("Pastebin Service", "Access Count", "hostName"),
    ("pua darknet links", "hostname"): ("Darknet Service", "Access Count", "hostName"),
    ("pua administrator usage", "app"): ("Application", "Administrator Usage Count", "app"),
    ("root detections", "rulename"): ("Rule Name", "Detection Count", "ruleName"),
    # RDP
    ("rdp user usage", "suid"): ("User Account", "RDP Connection Count", "suid"),
    ("rdp source ip", "clientip"): ("Source IP Address", "RDP Connection Count", "clientIp"),
    ("rdp destination ip", "serverip"): ("Destination IP Address", "RDP Connection Count", "serverIp"),
    # Geographic / Vendor
    ("bad states", "hostname"): ("Hostname", "Access Count", "hostName"),
    ("suspicious tlds", "hostname"): ("Hostname", "Access Count", "hostName"),
    ("russian it-companies", "hostname"): ("Russian Company", "Access Count", "hostName"),
    ("chinese it-companies", "hostname"): ("Chinese Company", "Access Count", "hostName"),
    ("epp/edr/xdr vendors", "hostname"): ("Security Vendor", "Access Count", "hostName"),
    ("firewall vendors", "hostname"): ("Firewall Vendor", "Access Count", "hostName"),
    ("us vendors", "hostname"): ("US Tech Company", "Access Count", "hostName"),
    # External threats
    ("external attacks", "rulename"): ("Rule Name", "Detection Count", "ruleName"),
    ("web rep ru", "rulename"): ("Rule Name", "Detection Count", "ruleName"),
    ("rdp detections", "rulename"): ("Rule Name", "Detection Count", "ruleName"),
    ("dns dead ip", "rulename"): ("Rule Name", "Detection Count", "ruleName"),
    # File/cert downloads
    ("file downloads", "request"): ("Download URL", "Download Count", "request"),
    ("cert downloads", "request"): ("Certificate URL", "Download Count", "request"),
    # External connections
    ("external rdp", "serverip"): ("External Server IP", "Connection Count", "serverIp"),
    ("external ssh", "serverip"): ("External Server IP", "Connection Count", "serverIp"),
    ("external protocols", "app"): ("Protocol", "Connection Count", "app"),
}

# Map sorting field names from CSV to actual API response field names
_FIELD_NAME_MAP: Dict[str, str] = {
    "hostname": "hostName",
    "hostnamedns": "hostName",
    "rulename": "ruleName",
    "serverport": "serverPort",
    "clientip": "clientIp",
    "serverip": "serverIp",
    "suid": "suid",
    "app": "app",
    "requestmethod": "requestMethod",
    "respcode": "respCode",
    "sslcertcommonname": "sslCertCommonName",
    "filename": "fileName",
    "filetype": "fileType",
    "respappversion": "respAppVersion",
    "request": "request",
}


def _aggregate_by_field(
    results: List[Dict[str, Any]],
    item_key: str,
    label_col: str,
    count_col: str,
) -> List[Dict[str, Any]]:
    """Count occurrences of *item_key* across results, return sorted desc.

    Skips records where the field is missing, None, or empty string.
    """
    counts: Dict[Any, int] = {}
    for item in results:
        val = item.get(item_key)
        if not val:  # Skip None, empty string, 0
            continue
        counts[val] = counts.get(val, 0) + 1
    return [
        {label_col: k, count_col: v}
        for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]


def aggregate_results(
    search_name: str,
    sorting_field: str,
    results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return aggregated rows if a rule matches, otherwise the raw results.

    For searches not covered by explicit rules but with a recognized sorting
    field present in the data, we do a generic count-by-field aggregation.
    """
    key = (search_name.strip().lower(), sorting_field.strip().lower())
    rule = _AGGREGATION_RULES.get(key)

    if rule:
        label_col, count_col, item_key = rule
        agg = _aggregate_by_field(results, item_key, label_col, count_col)
        logger.info(
            "Aggregated %d items into %d unique '%s' values",
            len(results), len(agg), item_key,
        )
        return agg

    # Generic aggregation: map the sorting field name to actual API field
    sf_raw = sorting_field.strip()
    sf_lower = sf_raw.lower()
    api_field = _FIELD_NAME_MAP.get(sf_lower, sf_raw)

    if api_field and results and api_field in results[0]:
        label = sf_raw.replace("_", " ").title()
        agg = _aggregate_by_field(results, api_field, label, "Count")
        logger.info(
            "Generic aggregation: %d items -> %d unique '%s' values",
            len(results), len(agg), api_field,
        )
        return agg

    # Try the raw field name directly
    if sf_raw and results and sf_raw in results[0]:
        agg = _aggregate_by_field(results, sf_raw, sf_raw, "Count")
        logger.info(
            "Direct field aggregation: %d items -> %d unique '%s' values",
            len(results), len(agg), sf_raw,
        )
        return agg

    # No aggregation possible - return raw results
    logger.warning(
        "No aggregation rule for '%s' with sorting='%s'. "
        "Available fields: %s. Exporting raw data.",
        search_name, sorting_field,
        list(results[0].keys())[:10] if results else "none",
    )
    return results


def _empty_placeholder(
    search_name: str, sorting_field: str
) -> List[Dict[str, Any]]:
    """Return a single-row placeholder for an empty search result."""
    key = (search_name.strip().lower(), sorting_field.strip().lower())
    rule = _AGGREGATION_RULES.get(key)
    if rule:
        label_col, count_col, _ = rule
        return [{label_col: "No results found", count_col: 0}]
    return [{"Message": "No results found for this query"}]


# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------
def export_to_excel(data: List[Dict[str, Any]], filepath: str) -> None:
    """Write *data* (list of dicts) to an Excel file with auto-sized columns."""
    if not data:
        df = pd.DataFrame({"Message": ["No detection results found for this query"]})
    else:
        df = pd.DataFrame(data)

    df = df.fillna("")

    with pd.ExcelWriter(filepath, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Search Results")

        ws = writer.sheets["Search Results"]
        for col_name in df.columns:
            max_len = max(df[col_name].astype(str).map(len).max(), len(str(col_name)))
            col_idx = df.columns.get_loc(col_name)
            if col_idx < 26:
                ws.column_dimensions[chr(65 + col_idx)].width = min(max_len + 2, 50)

    logger.info("Exported %d rows to %s", len(df), filepath)


# ---------------------------------------------------------------------------
# PowerPoint report (optional, best-effort)
# ---------------------------------------------------------------------------
def generate_ppt_report(excel_dir: str, output_path: str, template_path: Optional[str] = None) -> bool:
    """Generate a PowerPoint report by updating charts in the template.

    Uses the generate_ppt_report module which updates existing charts in the
    v2.0 NDR Security Assessment template, preserving all styling and 3D effects.
    """
    try:
        # Import the dedicated PPT generator module
        import importlib.util
        module_path = Path(__file__).parent / "generate_ppt_report.py"
        if module_path.exists():
            spec = importlib.util.spec_from_file_location("generate_ppt_report", module_path)
            ppt_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ppt_mod)
            result = ppt_mod.generate_report(
                template_path=template_path or str(Path(__file__).parent.parent / "templates" / "NDR_Security_Assessment.pptx"),
                data_dir=excel_dir,
                output_path=output_path,
            )
            if result:
                logger.info("PowerPoint report saved to %s (using template)", output_path)
                return True
            else:
                logger.warning("PowerPoint generation returned None - template may not exist")
                return False
        else:
            logger.warning("generate_ppt_report.py module not found at %s", module_path)
            return False
    except Exception as exc:
        logger.error("Failed to generate PowerPoint report: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Single search processor
# ---------------------------------------------------------------------------
def process_single_search(
    client: VisionOneClient,
    row: Dict[str, str],
    index: int,
    total: int,
    start_time: str,
    end_time: str,
    excel_dir: str,
) -> Dict[str, Any]:
    """Process one search row. Returns a result dict for the summary."""
    search_name = row.get("name", f"search_{index}").strip()
    sorting_field = row.get("sorting", "default").strip()
    orientation = row.get("orientation", "horizontal").strip().lower()
    query = row.get("query", "").strip()
    log_type = row.get("log_type", "").strip().lower()

    if not log_type:
        log_type = VisionOneClient.determine_log_type(query)

    emit_progress(index, total, search_name)

    result_info: Dict[str, Any] = {
        "name": search_name,
        "records": 0,
        "file": None,
        "error": None,
    }

    if not query:
        msg = f"Skipping '{search_name}': empty query."
        logger.warning(msg)
        result_info["error"] = msg
        return result_info

    logger.info(
        "Processing search %d/%d: %s [%s]", index, total, search_name, log_type
    )

    try:
        results = client.search_logs(
            log_type, start_time, end_time, query=query,
            sorting_field=sorting_field,
        )

        if results:
            rows_to_export = aggregate_results(search_name, sorting_field, results)
        else:
            logger.warning("No data returned for '%s'.", search_name)
            rows_to_export = _empty_placeholder(search_name, sorting_field)

        # Sanitise filename
        safe_name = "".join(
            c for c in search_name if c.isalnum() or c in (" ", "-", "_")
        ).rstrip()
        filename = f"{safe_name}_{sorting_field}_{orientation}.xlsx"
        filepath = os.path.join(excel_dir, filename)

        export_to_excel(rows_to_export, filepath)

        result_info["records"] = len(results)
        result_info["file"] = filepath

        # Include top chart data for frontend rendering
        if rows_to_export and isinstance(rows_to_export[0], dict):
            keys = list(rows_to_export[0].keys())
            if len(keys) >= 2:
                cat_key, val_key = keys[0], keys[1]
                chart_data = []
                for row in rows_to_export[:25]:  # Top 25 for charts
                    cat = str(row.get(cat_key, ""))[:60]
                    val = row.get(val_key, 0)
                    try:
                        val = int(val)
                    except (ValueError, TypeError):
                        val = 0
                    if cat and val > 0:
                        chart_data.append([cat, val])
                result_info["data"] = chart_data
                result_info["columns"] = [cat_key, val_key]

    except Exception as exc:
        msg = f"Failed to process '{search_name}': {exc}"
        logger.error(msg)
        result_info["error"] = msg
        emit_error(msg, name=search_name)

    return result_info


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def run_assessment(
    csv_path: str,
    output_dir: str,
    time_interval: int,
    api_key: str,
    base_url: str,
    template_path: Optional[str] = None,
) -> None:
    """Top-level orchestrator: CSV -> API -> Excel -> PowerPoint -> JSON."""

    excel_dir = os.path.join(output_dir, "excel")
    os.makedirs(excel_dir, exist_ok=True)

    client = VisionOneClient(api_key, base_url)

    # Time range
    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(hours=time_interval)
    start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.info(
        "Assessment window: %s -> %s (%d hours)", start_time, end_time, time_interval
    )

    # Read CSV
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        searches = list(reader)

    total = len(searches)
    if total == 0:
        emit_complete("success", [], {"total": 0, "with_data": 0, "records": 0})
        return

    logger.info("Loaded %d search definitions from %s", total, csv_path)

    # Run searches concurrently
    all_results: List[Dict[str, Any]] = [{}] * total  # preserve order
    errors: List[str] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_map = {}
        for idx, row in enumerate(searches, start=1):
            fut = pool.submit(
                process_single_search,
                client, row, idx, total, start_time, end_time, excel_dir,
            )
            future_map[fut] = idx - 1  # 0-based slot

        for future in as_completed(future_map):
            slot = future_map[future]
            try:
                info = future.result()
                all_results[slot] = info
                if info.get("error"):
                    errors.append(info["error"])
                    logger.error("Search failed: %s", info["error"])
                else:
                    logger.info(
                        "Completed: %s (%d records)", info["name"], info["records"]
                    )
            except Exception as exc:
                msg = f"Unexpected thread error for slot {slot}: {exc}"
                logger.error(msg)
                errors.append(msg)

    # Collect summary
    generated_files = [r["file"] for r in all_results if r.get("file")]
    with_data = sum(1 for r in all_results if r.get("records", 0) > 0)
    total_records = sum(r.get("records", 0) for r in all_results)

    # PowerPoint report (best-effort)
    pptx_path = os.path.join(output_dir, "report.pptx")
    ppt_ok = generate_ppt_report(excel_dir, pptx_path, template_path=template_path)
    if ppt_ok:
        generated_files.append(pptx_path)

    # Build search_results for frontend charts
    search_results = []
    for r in all_results:
        if not r.get("name"):
            continue
        entry = {
            "name": r["name"],
            "count": r.get("records", 0),
            "data": r.get("data", []),
            "columns": r.get("columns", []),
            "error": r.get("error"),
        }
        search_results.append(entry)

    # Save summary.json for the server to read
    summary_data = {
        "total": total,
        "with_data": with_data,
        "total_records": total_records,
        "search_results": search_results,
    }
    summary_path = os.path.join(output_dir, "summary.json")
    try:
        import json as _json
        with open(summary_path, "w") as sf:
            _json.dump(summary_data, sf, indent=2)
        logger.info("Summary saved to %s", summary_path)
    except Exception as exc:
        logger.warning("Could not save summary.json: %s", exc)

    # Final status
    status = "success" if not errors else ("partial" if with_data > 0 else "error")
    emit_complete(
        status=status,
        files=generated_files,
        summary=summary_data,
        errors=errors if errors else None,
    )

    logger.info(
        "Assessment complete. %d/%d searches returned data, %d total records.",
        with_data, total, total_records,
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a Trend Micro Vision One security assessment from a CSV of search definitions.",
    )
    parser.add_argument(
        "--csv", required=True, help="Path to the input CSV file with search definitions."
    )
    parser.add_argument(
        "--output", required=True, help="Output directory (Excel files go into <output>/excel/)."
    )
    parser.add_argument(
        "--time-interval",
        type=int,
        default=720,
        help="Lookback window in hours (default: 720 = 30 days).",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="Path to a PowerPoint template (.pptx) for report generation.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    args = parser.parse_args()

    logging.root.setLevel(getattr(logging, args.log_level))

    # Validate environment
    api_key = os.environ.get("TREND_MICRO_API_KEY", "")
    if not api_key:
        emit_error("TREND_MICRO_API_KEY environment variable is not set.")
        logger.error("TREND_MICRO_API_KEY environment variable is not set.")
        return 1

    base_url = os.environ.get(
        "TREND_MICRO_BASE_URL", "https://api.eu.xdr.trendmicro.com"
    )

    # Validate CSV exists
    if not os.path.isfile(args.csv):
        emit_error(f"CSV file not found: {args.csv}")
        logger.error("CSV file not found: %s", args.csv)
        return 1

    try:
        run_assessment(
            csv_path=args.csv,
            output_dir=args.output,
            time_interval=args.time_interval,
            api_key=api_key,
            base_url=base_url,
            template_path=args.template,
        )
    except Exception as exc:
        emit_error(f"Fatal error: {exc}")
        logger.exception("Fatal error during assessment.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
