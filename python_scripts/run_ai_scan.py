#!/usr/bin/env python3
"""
TMAS AI Scanner - Web Backend Wrapper

Wraps the existing TMAS AI scan pipeline (config generation, binary download,
scan execution, report generation) for use by a web backend. All progress and
results are emitted as structured JSON on stdout so the caller can parse them
reliably. Human-readable logging goes to stderr.

Usage:
    export TMAS_API_KEY="<vision-one-key>"
    export LLM_API_KEY="<llm-key>"
    python3 python_scripts/run_ai_scan.py \
        --provider openai --model gpt-4 --preset owasp \
        --region eu-central-1 --output results/ --timeout 3600
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TMAS_METADATA_URL = "https://ast-cli.xdr.trendmicro.com/tmas-cli/metadata.json"
TMAS_DOWNLOAD_BASE = "https://ast-cli.xdr.trendmicro.com/tmas-cli"

VALID_PRESETS = ["owasp", "mitre"]
VALID_PROVIDERS = ["openai", "anthropic", "ollama", "azure_openai", "custom"]

PROVIDER_DEFAULTS = {
    "openai": {
        "endpoint": "https://api.openai.com/v1",
        "model": "gpt-4",
    },
    "anthropic": {
        "endpoint": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-6",
    },
    "ollama": {
        "endpoint": "http://localhost:11434/v1",
        "model": "llama3",
    },
    "azure_openai": {
        "endpoint": "",
        "model": "gpt-4",
    },
    "custom": {
        "endpoint": "",
        "model": "",
    },
}

# ---------------------------------------------------------------------------
# Helpers: structured output
# ---------------------------------------------------------------------------


def emit_progress(step: str) -> None:
    """Write a progress JSON line to stdout for the caller to consume."""
    msg = json.dumps({"type": "progress", "step": step})
    print(msg, flush=True)


def emit_error(message: str) -> None:
    """Write an error JSON line to stdout for the caller to consume."""
    msg = json.dumps({"type": "error", "message": message})
    print(msg, flush=True)


def log(message: str) -> None:
    """Write a human-readable log line to stderr."""
    print(message, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Stage 1: Config generation (mirrors scripts/generate_config.py)
# ---------------------------------------------------------------------------


def generate_config(
    endpoint: str,
    model: str,
    api_key_env: str = "LLM_API_KEY",
    attack_preset: str = "owasp",
    system_prompt: str = "",
) -> dict:
    """Build the TMAS aiscan config dictionary.

    ``api_key_env`` is the *name* of the environment variable that holds the
    LLM API key -- the secret itself is never written to the config file.
    """
    config = {
        "version": "1.0",
        "target": {
            "name": model,
            "endpoint": endpoint,
            "api_key_env": api_key_env,
            "model": model,
        },
        "attack_preset": attack_preset,
    }
    if system_prompt:
        config["target"]["system_prompt"] = system_prompt
    return config


def write_config(config: dict, output_path: str) -> None:
    """Serialise *config* to a YAML file at *output_path*."""
    try:
        import yaml
    except ImportError:
        # Fallback: write YAML manually to avoid a hard dependency at import time.
        # The structure is simple enough that we can emit valid YAML by hand.
        lines = [
            f"version: '{config['version']}'",
            "target:",
            f"  name: {config['target']['name']}",
            f"  endpoint: {config['target']['endpoint']}",
            f"  api_key_env: {config['target']['api_key_env']}",
            f"  model: {config['target']['model']}",
        ]
        if "system_prompt" in config.get("target", {}):
            # Quote multi-line prompts safely.
            sp = config["target"]["system_prompt"].replace("'", "''")
            lines.append(f"  system_prompt: '{sp}'")
        lines.append(f"attack_preset: {config['attack_preset']}")
        with open(output_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return

    with open(output_path, "w") as fh:
        yaml.dump(config, fh, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Stage 2: TMAS binary download
# ---------------------------------------------------------------------------


def _detect_arch() -> str:
    """Return the architecture string expected in TMAS download URLs."""
    machine = platform.machine()
    if machine in ("x86_64", "AMD64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported architecture: {machine}")


def ensure_tmas_binary(project_root: str) -> str:
    """Download the TMAS CLI binary if it is not already present.

    Returns the absolute path to the ``tmas`` executable.
    """
    tmas_path = os.path.join(project_root, "tmas")
    if os.path.isfile(tmas_path) and os.access(tmas_path, os.X_OK):
        log(f"TMAS binary already present: {tmas_path}")
        return tmas_path

    log("Fetching TMAS CLI metadata...")
    try:
        with urllib.request.urlopen(TMAS_METADATA_URL, timeout=30) as resp:
            metadata = json.loads(resp.read().decode())
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch TMAS metadata from {TMAS_METADATA_URL}: {exc}") from exc

    version = metadata.get("latestVersion", "").lstrip("v")
    if not version:
        raise RuntimeError("Could not determine latest TMAS version from metadata")

    arch = _detect_arch()
    tarball_name = f"tmas-cli_Linux_{arch}.tar.gz"
    download_url = f"{TMAS_DOWNLOAD_BASE}/{version}/{tarball_name}"

    log(f"Downloading TMAS CLI v{version} for {arch} from {download_url}")
    tarball_path = os.path.join(project_root, tarball_name)
    try:
        urllib.request.urlretrieve(download_url, tarball_path)
    except Exception as exc:
        raise RuntimeError(f"Failed to download TMAS binary: {exc}") from exc

    try:
        with tarfile.open(tarball_path, "r:gz") as tf:
            # Extract only the 'tmas' member to avoid writing unexpected files.
            members = [m for m in tf.getmembers() if m.name == "tmas"]
            if not members:
                raise RuntimeError("'tmas' not found inside downloaded tarball")
            tf.extractall(path=project_root, members=members)
    finally:
        try:
            os.remove(tarball_path)
        except OSError:
            pass

    os.chmod(tmas_path, 0o755)
    log(f"TMAS binary installed: {tmas_path}")
    return tmas_path


# ---------------------------------------------------------------------------
# Stage 3: Scan execution (mirrors scripts/run_scan.py)
# ---------------------------------------------------------------------------


def parse_findings(output: str) -> list:
    """Extract structured findings from raw TMAS output."""
    findings: list[dict] = []
    current_finding: dict = {}

    for line in output.split("\n"):
        line = line.strip()

        # Objective pass/fail lines
        if "objective" in line.lower() and ("pass" in line.lower() or "fail" in line.lower()):
            findings.append({
                "raw": line,
                "status": "FAIL" if "fail" in line.lower() else "PASS",
            })

        # Attack attempt patterns
        if "attack" in line.lower() and ":" in line:
            current_finding = {"raw": line}

        if "result" in line.lower() and current_finding:
            current_finding["result"] = line
            findings.append(current_finding)
            current_finding = {}

        # Score patterns
        score_match = re.search(r"score[:\s]+(\d+(?:\.\d+)?)", line, re.IGNORECASE)
        if score_match:
            findings.append({
                "raw": line,
                "score": float(score_match.group(1)),
            })

    return findings


def determine_risk(findings: list) -> dict:
    """Compute summary statistics and risk level from findings."""
    total = len(findings)
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    passed = sum(1 for f in findings if f.get("status") == "PASS")

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

    return {
        "total_findings": total,
        "failed": failed,
        "passed": passed,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "risk_icon": risk_icon,
    }


def run_tmas_scan(
    tmas_path: str,
    config_path: str,
    region: str,
    tmas_api_key: str,
    timeout: int = 3600,
) -> dict:
    """Execute ``tmas aiscan llm`` and return structured results."""
    cmd = [
        tmas_path,
        "aiscan",
        "llm",
        "--config",
        config_path,
        "--region",
        region,
    ]

    env = os.environ.copy()
    env["TMAS_API_KEY"] = tmas_api_key

    log(f"Running: {' '.join(cmd)}")
    log(f"Region:  {region}")
    log(f"Timeout: {timeout}s")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Scan timed out after {timeout} seconds",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "error": f"Scan timed out after {timeout} seconds",
        }
    except FileNotFoundError:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"TMAS binary not found at {tmas_path}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "error": f"TMAS binary not found at {tmas_path}",
        }

    stdout = result.stdout
    stderr = result.stderr
    full_output = stdout + "\n" + stderr

    log(full_output)

    scan_result: dict = {
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Try to extract JSON blob that TMAS may emit at the end of stdout.
    json_match = re.search(r"(\{[\s\S]*\})\s*$", stdout)
    if json_match:
        try:
            scan_result["parsed_results"] = json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    scan_result["findings"] = parse_findings(full_output)
    return scan_result


# ---------------------------------------------------------------------------
# Stage 4: Report generation (mirrors scripts/run_scan.py)
# ---------------------------------------------------------------------------


def generate_html_report(scan_result: dict, config: dict, output_path: str) -> None:
    """Produce a styled HTML report identical to scripts/run_scan.py output."""
    findings = scan_result.get("findings", [])
    parsed = scan_result.get("parsed_results", {})
    risk = determine_risk(findings)

    risk_level = risk["risk_level"]
    risk_color = risk["risk_color"]
    risk_icon = risk["risk_icon"]
    total_findings = risk["total_findings"]
    failed = risk["failed"]
    passed = risk["passed"]

    # Build findings table rows
    finding_rows = ""
    for i, f in enumerate(findings, 1):
        status = f.get("status", "INFO")
        if status == "FAIL":
            status_color = "#dc3545"
        elif status == "PASS":
            status_color = "#28a745"
        else:
            status_color = "#6c757d"
        raw = f.get("raw", "").replace("<", "&lt;").replace(">", "&gt;")
        score = f.get("score", "")
        score_cell = f"<td>{score}</td>" if score else "<td>-</td>"

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

    with open(output_path, "w") as fh:
        fh.write(html)

    log(f"HTML report written: {output_path}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def resolve_endpoint_and_model(
    provider: str,
    endpoint: str | None,
    model: str | None,
) -> tuple[str, str]:
    """Apply provider defaults and validate that endpoint/model are set."""
    defaults = PROVIDER_DEFAULTS.get(provider, {})

    resolved_endpoint = endpoint or defaults.get("endpoint", "")
    resolved_model = model or defaults.get("model", "") or "gpt-4"

    if not resolved_endpoint:
        if provider == "azure_openai":
            raise ValueError(
                "Azure OpenAI requires --endpoint (e.g. https://<resource>.openai.azure.com/openai/deployments/<deployment>)"
            )
        if provider == "custom":
            raise ValueError("Custom provider requires --endpoint")
        raise ValueError(f"No endpoint could be determined for provider '{provider}'")

    return resolved_endpoint, resolved_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TMAS AI Scanner - Web backend wrapper"
    )
    parser.add_argument(
        "--provider",
        required=True,
        choices=VALID_PROVIDERS,
        help="LLM provider",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name (default: derived from provider)",
    )
    parser.add_argument(
        "--preset",
        default="owasp",
        choices=VALID_PRESETS,
        help="Attack preset (default: owasp)",
    )
    parser.add_argument(
        "--region",
        default="eu-central-1",
        help="Vision One region (default: eu-central-1)",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory for results (default: results)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Scan timeout in seconds (default: 3600)",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Custom endpoint URL (overrides provider default)",
    )
    parser.add_argument(
        "--system-prompt",
        default="",
        help="Optional system prompt to include in scan config",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validate environment variables
    # ------------------------------------------------------------------
    tmas_api_key = os.environ.get("TMAS_API_KEY", "")
    if not tmas_api_key:
        emit_error("TMAS_API_KEY environment variable is not set")
        log("ERROR: TMAS_API_KEY environment variable is required")
        return 1

    llm_api_key = os.environ.get("LLM_API_KEY", "")
    if not llm_api_key and args.provider != "ollama":
        emit_error("LLM_API_KEY environment variable is not set")
        log("ERROR: LLM_API_KEY environment variable is required (unless provider is ollama)")
        return 1

    # For ollama, set a dummy key if none was provided.
    if args.provider == "ollama" and not llm_api_key:
        os.environ["LLM_API_KEY"] = "not-needed"

    # ------------------------------------------------------------------
    # Resolve endpoint and model
    # ------------------------------------------------------------------
    try:
        endpoint, model = resolve_endpoint_and_model(
            args.provider, args.endpoint, args.model
        )
    except ValueError as exc:
        emit_error(str(exc))
        log(f"ERROR: {exc}")
        return 1

    # Anthropic note: TMAS requires an OpenAI-compatible endpoint. When
    # using Anthropic you should run a LiteLLM proxy and point --endpoint
    # at it (e.g. http://localhost:4000/v1).  We log a reminder.
    if args.provider == "anthropic" and "anthropic.com" in endpoint:
        log(
            "NOTE: Anthropic endpoints require a LiteLLM proxy for "
            "OpenAI-compatible translation. Make sure a proxy is running "
            "and pass its URL via --endpoint."
        )

    # Determine project root (one level up from this script's directory)
    project_root = str(Path(__file__).resolve().parent.parent)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Stage 1: Generate config
    # ------------------------------------------------------------------
    emit_progress("Generating config...")
    log(f"Provider: {args.provider}")
    log(f"Endpoint: {endpoint}")
    log(f"Model:    {model}")
    log(f"Preset:   {args.preset}")

    config = generate_config(
        endpoint=endpoint,
        model=model,
        api_key_env="LLM_API_KEY",
        attack_preset=args.preset,
        system_prompt=args.system_prompt,
    )

    config_path = os.path.join(output_dir, "config.yaml")
    try:
        write_config(config, config_path)
    except Exception as exc:
        emit_error(f"Failed to write config: {exc}")
        log(f"ERROR: Failed to write config: {exc}")
        return 1

    log(f"Config written: {config_path}")

    # ------------------------------------------------------------------
    # Stage 2: Ensure TMAS binary
    # ------------------------------------------------------------------
    emit_progress("Downloading TMAS CLI...")
    try:
        tmas_path = ensure_tmas_binary(project_root)
    except RuntimeError as exc:
        emit_error(f"Failed to obtain TMAS binary: {exc}")
        log(f"ERROR: {exc}")
        return 1

    # ------------------------------------------------------------------
    # Stage 3: Run the scan
    # ------------------------------------------------------------------
    emit_progress("Running scan...")
    scan_result = run_tmas_scan(
        tmas_path=tmas_path,
        config_path=config_path,
        region=args.region,
        tmas_api_key=tmas_api_key,
        timeout=args.timeout,
    )

    # Check for hard errors from the scan itself.
    if scan_result.get("error"):
        emit_error(scan_result["error"])

    # ------------------------------------------------------------------
    # Stage 4: Save results and generate reports
    # ------------------------------------------------------------------
    emit_progress("Generating reports...")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    findings = scan_result.get("findings", [])
    risk = determine_risk(findings)

    # Build the final results payload.
    results_payload = {
        "timestamp": scan_result.get("timestamp"),
        "provider": args.provider,
        "model": model,
        "endpoint": endpoint,
        "preset": args.preset,
        "region": args.region,
        "exit_code": scan_result.get("exit_code"),
        "risk_level": risk["risk_level"],
        "total_findings": risk["total_findings"],
        "failed": risk["failed"],
        "passed": risk["passed"],
        "findings": findings,
    }
    if scan_result.get("parsed_results"):
        results_payload["parsed_results"] = scan_result["parsed_results"]
    if scan_result.get("error"):
        results_payload["error"] = scan_result["error"]

    # Write scan_results.json
    json_path = os.path.join(output_dir, "scan_results.json")
    try:
        with open(json_path, "w") as fh:
            json.dump(results_payload, fh, indent=2)
        log(f"JSON results: {json_path}")
    except Exception as exc:
        emit_error(f"Failed to write JSON results: {exc}")
        log(f"ERROR: {exc}")

    # Also save a timestamped copy
    json_ts_path = os.path.join(output_dir, f"scan_results_{timestamp}.json")
    try:
        with open(json_ts_path, "w") as fh:
            json.dump(results_payload, fh, indent=2)
    except Exception:
        pass  # Non-critical

    # Write scan_report.html
    html_path = os.path.join(output_dir, "scan_report.html")
    try:
        generate_html_report(scan_result, config, html_path)
    except Exception as exc:
        emit_error(f"Failed to write HTML report: {exc}")
        log(f"ERROR: {exc}")

    # Also save a timestamped copy
    html_ts_path = os.path.join(output_dir, f"scan_report_{timestamp}.html")
    try:
        generate_html_report(scan_result, config, html_ts_path)
    except Exception:
        pass  # Non-critical

    # ------------------------------------------------------------------
    # Emit final results via markers
    # ------------------------------------------------------------------
    print("---JSON_START---", flush=True)
    print(json.dumps(results_payload, indent=2), flush=True)
    print("---JSON_END---", flush=True)

    log("Scan complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
