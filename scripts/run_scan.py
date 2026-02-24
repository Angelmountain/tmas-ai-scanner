#!/usr/bin/env python3
"""
TMAS AI Scanner - Scan Runner & Report Generator

Runs `tmas aiscan llm` with the generated config, captures output,
produces JSON results and a styled HTML report.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_tmas_scan(
    config_path: str,
    region: str,
    tmas_api_key: str,
    verbose: bool = False,
) -> dict:
    """Execute tmas aiscan llm and capture results."""

    cmd = [
        "./tmas",
        "aiscan",
        "llm",
        "--config",
        config_path,
        "--region",
        region,
    ]
    if verbose:
        cmd.append("-vv")

    env = os.environ.copy()
    env["TMAS_API_KEY"] = tmas_api_key

    print(f"Running: {' '.join(cmd)}")
    print(f"Region:  {region}")
    print("-" * 60)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )

    stdout = result.stdout
    stderr = result.stderr
    full_output = stdout + "\n" + stderr

    print(full_output)

    scan_result = {
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Try to parse JSON from output (tmas outputs JSON results)
    json_match = re.search(r'(\{[\s\S]*\})\s*$', stdout)
    if json_match:
        try:
            scan_result["parsed_results"] = json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Parse structured data from output lines
    scan_result["findings"] = parse_findings(full_output)

    return scan_result


def parse_findings(output: str) -> list:
    """Parse scan findings from TMAS output."""
    findings = []

    # Parse attack results from output
    lines = output.split("\n")
    current_finding = {}

    for line in lines:
        line = line.strip()

        # Look for objective/attack result patterns
        if "objective" in line.lower() and ("pass" in line.lower() or "fail" in line.lower()):
            finding = {
                "raw": line,
                "status": "FAIL" if "fail" in line.lower() else "PASS",
            }
            findings.append(finding)

        # Look for attack attempt patterns
        if "attack" in line.lower() and ":" in line:
            current_finding = {"raw": line}

        if "result" in line.lower() and current_finding:
            current_finding["result"] = line
            findings.append(current_finding)
            current_finding = {}

        # Look for score patterns
        score_match = re.search(r'score[:\s]+(\d+(?:\.\d+)?)', line, re.IGNORECASE)
        if score_match:
            findings.append({
                "raw": line,
                "score": float(score_match.group(1)),
            })

    return findings


def generate_html_report(scan_result: dict, config: dict, output_path: str):
    """Generate a styled HTML report from scan results."""

    findings = scan_result.get("findings", [])
    parsed = scan_result.get("parsed_results", {})

    # Calculate summary stats
    total_findings = len(findings)
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    passed = sum(1 for f in findings if f.get("status") == "PASS")

    # Determine overall risk
    if failed > 5:
        risk_level = "CRITICAL"
        risk_color = "#dc3545"
        risk_icon = "!!!"
    elif failed > 2:
        risk_level = "HIGH"
        risk_color = "#fd7e14"
        risk_icon = "!!"
    elif failed > 0:
        risk_level = "MEDIUM"
        risk_color = "#ffc107"
        risk_icon = "!"
    else:
        risk_level = "LOW"
        risk_color = "#28a745"
        risk_icon = "OK"

    # Build findings table rows
    finding_rows = ""
    for i, f in enumerate(findings, 1):
        status = f.get("status", "INFO")
        status_color = "#dc3545" if status == "FAIL" else "#28a745" if status == "PASS" else "#6c757d"
        raw = f.get("raw", "").replace("<", "&lt;").replace(">", "&gt;")
        score = f.get("score", "")
        score_cell = f'<td>{score}</td>' if score else '<td>-</td>'

        finding_rows += f"""
        <tr>
            <td>{i}</td>
            <td style="color: {status_color}; font-weight: bold;">{status}</td>
            <td><code>{raw[:120]}</code></td>
            {score_cell}
        </tr>"""

    # Raw output (escaped)
    raw_stdout = scan_result.get("stdout", "").replace("<", "&lt;").replace(">", "&gt;")
    raw_stderr = scan_result.get("stderr", "").replace("<", "&lt;").replace(">", "&gt;")

    # Parsed JSON block
    parsed_json_block = ""
    if parsed:
        parsed_json_block = f"""
        <div class="section">
            <h2>Parsed Results (JSON)</h2>
            <pre class="json-block">{json.dumps(parsed, indent=2)}</pre>
        </div>"""

    endpoint = config.get("target", {}).get("endpoint", "N/A")
    model = config.get("target", {}).get("model", "N/A")
    preset = config.get("attack_preset", "N/A")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TMAS AI Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
        .header {{
            background: linear-gradient(135deg, #161b22 0%, #1a2332 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 28px;
            color: #58a6ff;
            margin-bottom: 8px;
        }}
        .header .subtitle {{
            color: #8b949e;
            font-size: 14px;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 24px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 18px;
            margin-top: 16px;
            background: {risk_color}22;
            color: {risk_color};
            border: 2px solid {risk_color};
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 36px;
            font-weight: 700;
            color: #58a6ff;
        }}
        .stat-card .label {{
            color: #8b949e;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }}
        .stat-card.fail .number {{ color: #f85149; }}
        .stat-card.pass .number {{ color: #3fb950; }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            color: #58a6ff;
            font-size: 18px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }}
        th {{
            background: #0d1117;
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        tr:hover {{ background: #1c2128; }}
        code {{
            background: #0d1117;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #c9d1d9;
        }}
        .config-grid {{
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 8px 16px;
        }}
        .config-grid .key {{
            color: #8b949e;
            font-weight: 600;
        }}
        .config-grid .value {{
            color: #c9d1d9;
            word-break: break-all;
        }}
        pre {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.5;
            max-height: 500px;
            overflow-y: auto;
        }}
        .json-block {{
            color: #7ee787;
        }}
        .footer {{
            text-align: center;
            color: #484f58;
            font-size: 12px;
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid #21262d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TMAS AI Security Scan Report</h1>
            <div class="subtitle">
                Trend Micro Artifact Scanner - LLM Endpoint Security Assessment
            </div>
            <div class="risk-badge">{risk_icon} Risk Level: {risk_level}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card fail">
                <div class="number">{failed}</div>
                <div class="label">Failed Checks</div>
            </div>
            <div class="stat-card pass">
                <div class="number">{passed}</div>
                <div class="label">Passed Checks</div>
            </div>
            <div class="stat-card">
                <div class="number">{scan_result.get('exit_code', 'N/A')}</div>
                <div class="label">Exit Code</div>
            </div>
        </div>

        <div class="section">
            <h2>Scan Configuration</h2>
            <div class="config-grid">
                <div class="key">Timestamp</div>
                <div class="value">{scan_result.get('timestamp', 'N/A')}</div>
                <div class="key">Endpoint</div>
                <div class="value"><code>{endpoint}</code></div>
                <div class="key">Model</div>
                <div class="value"><code>{model}</code></div>
                <div class="key">Attack Preset</div>
                <div class="value"><code>{preset}</code></div>
            </div>
        </div>

        {"" if not findings else f'''
        <div class="section">
            <h2>Findings Detail</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Status</th>
                        <th>Detail</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {finding_rows}
                </tbody>
            </table>
        </div>
        '''}

        {parsed_json_block}

        <div class="section">
            <h2>Raw Output</h2>
            <pre>{raw_stdout}</pre>
        </div>

        {"" if not raw_stderr.strip() else f'''
        <div class="section">
            <h2>Stderr / Debug Output</h2>
            <pre>{raw_stderr}</pre>
        </div>
        '''}

        <div class="footer">
            Generated by TMAS AI Scanner Pipeline | Trend Micro Vision One |
            {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"HTML report: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Run TMAS AI Scanner and generate reports"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to TMAS aiscan config YAML",
    )
    parser.add_argument(
        "--region",
        default=os.getenv("TMAS_REGION", "us-east-1"),
        help="Vision One region (default: us-east-1)",
    )
    parser.add_argument(
        "--tmas-api-key",
        default=os.getenv("TMAS_API_KEY", ""),
        help="Vision One API key",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose TMAS output",
    )

    args = parser.parse_args()

    if not args.tmas_api_key:
        print("ERROR: --tmas-api-key or TMAS_API_KEY env var is required", file=sys.stderr)
        sys.exit(1)

    # Load config for report metadata
    import yaml
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Run the scan
    print("=" * 60)
    print("TMAS AI SCANNER - LLM Endpoint Security Scan")
    print("=" * 60)

    scan_result = run_tmas_scan(
        config_path=args.config,
        region=args.region,
        tmas_api_key=args.tmas_api_key,
        verbose=args.verbose,
    )

    # Save JSON results
    json_path = os.path.join(args.output_dir, f"scan_results_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(scan_result, f, indent=2)
    print(f"JSON results: {json_path}")

    # Also save as latest.json for easy access
    latest_json = os.path.join(args.output_dir, "latest.json")
    with open(latest_json, "w") as f:
        json.dump(scan_result, f, indent=2)

    # Generate HTML report
    html_path = os.path.join(args.output_dir, f"scan_report_{timestamp}.html")
    generate_html_report(scan_result, config, html_path)

    # Also save as latest.html
    latest_html = os.path.join(args.output_dir, "latest.html")
    generate_html_report(scan_result, config, latest_html)

    # Print summary
    findings = scan_result.get("findings", [])
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"  Findings:  {len(findings)}")
    print(f"  Failed:    {failed}")
    print(f"  Exit Code: {scan_result['exit_code']}")
    print(f"  JSON:      {json_path}")
    print(f"  HTML:      {html_path}")
    print("=" * 60)

    return scan_result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
