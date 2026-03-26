# QA Report -- TMAS AI Scanner Codebase

**Date:** 2026-03-26
**Reviewer:** Quality Checker Agent
**Scope:** All Python scripts, Node.js server, configuration files, templates

---

## Critical Issues (Must Fix)

### C1. Code Injection via `/api/agents/validate` Endpoint

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 719-786)

The `/api/agents/validate` endpoint builds a Python script by string-interpolating user-supplied `apiKey` and `baseUrl` values directly into Python source code. Although double-quotes are escaped, an attacker can inject arbitrary Python code via single quotes, backslashes, or newline sequences in the `apiKey` or `baseUrl` fields.

Example: `apiKey = "legit_key\nimport os; os.system('rm -rf /')\n#"` would break out of the string assignment.

**Impact:** Remote code execution on the server.

**Recommendation:** Never build Python source from user input. Instead, pass `apiKey` and `baseUrl` as environment variables to a fixed Python script (the same pattern used by `spawnPython` for assessment/aiscan runs).

---

### C2. Path Traversal on `jobId` Parameters

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 479-630, 806-924)

The `req.params.jobId` value is used directly in `path.join(JOBS_DIR, req.params.jobId, ...)` without sanitization. While `filename` parameters use `path.basename()`, `jobId` does not. A crafted `jobId` like `../../etc` could allow reading or deleting files outside the jobs directory.

Affected routes: `/api/assessment/status/:jobId`, `/api/assessment/results/:jobId`, `/api/assessment/download/:jobId`, `/api/assessment/excel/:jobId/:filename`, `/api/assessment/ppt/:jobId`, `/api/aiscan/status/:jobId`, `/api/aiscan/results/:jobId`, `/api/aiscan/report/:jobId`, `/api/agents/analyze/:jobId`, `/api/agents/qa/:jobId`, `/api/jobs/:jobId/stop`, `DELETE /api/jobs/:jobId`.

**Impact:** Arbitrary file read/delete. The `DELETE /api/jobs/:jobId` route calls `fs.rmSync(jobDir, { recursive: true, force: true })` which is especially dangerous.

**Recommendation:** Sanitize `jobId` at the route level: `const jobId = path.basename(req.params.jobId);` or validate it matches UUID/hex pattern before use.

---

### C3. No Authentication on Any API Endpoint

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js`

All API endpoints (including job deletion, workflow dispatch, config changes, file writes to `searches.csv` and domain files) are open without any authentication. Rate limiting is the only protection.

**Impact:** Anyone with network access can run scans, delete jobs, modify search configurations, trigger GitHub Actions workflows, and access all assessment data.

**Recommendation:** Add at minimum API key authentication or session-based auth. The `POST /api/config`, `PUT /api/searches/raw`, `PUT /api/searches/domains/:file`, `POST /api/github/dispatch/:workflow`, and `DELETE /api/jobs/:jobId` routes are particularly sensitive.

---

### C4. `select` Parameter Sent to Non-Network Endpoints with Incorrect Field Names

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_assessment.py` (lines 286-287, 297, 369)

When `log_type='everything'`, the `select` parameter is set to the aggregation field (e.g., `suid`, `hostName`). This same field name is then sent to all endpoints including `endpointActivities`, `emailActivities`, etc., where those field names may not exist. The API returns 400 for invalid `select` values. While there is a retry-without-select fallback (line 227-231), this fallback only triggers per-chunk, meaning:

1. The first chunk wastes a request + gets a 400.
2. `select` is set to `None` inside `_search_chunk`, but `search_and_aggregate` passes the original `sel` again for the next chunk, so the 400 error repeats on every single chunk.

**Impact:** Every chunk for non-NDR endpoints wastes a request on a 400 error before the fallback kicks in. For a 30-day window with 15-minute chunks, that is ~2880 wasted API calls per endpoint.

**Recommendation:** Reset `select` at the `search_and_aggregate` level when the endpoint is not `network`, or maintain a set of valid `select` fields per endpoint type.

---

## Medium Issues (Should Fix)

### M1. Naming Mismatch Between `searches.csv` and `_AGGREGATION_RULES`

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_assessment.py` (lines 410-458) vs `/home/ubuntu/projects/tmas-ai-scanner/templates/searches.csv`

The `searches.csv` uses new-format names (e.g., `"Top Accounts"`, `"Server Ports"`, `"Protocols"`, `"PUA Darknet"`, `"PUA Admin Usage"`, `"RDP Users"`, `"RDP Source IPs"`, `"RDP Dest IPs"`, `"Russian IT"`, `"Chinese IT"`, `"Security Vendors"`), but `_AGGREGATION_RULES` uses legacy names (e.g., `"top accounts used"`, `"server ports used"`, `"protocols used"`, `"pua darknet links"`, `"pua administrator usage"`, `"rdp user usage"`, `"rdp source ip"`, `"rdp destination ip"`, `"russian it-companies"`, `"chinese it-companies"`, `"epp/edr/xdr vendors"`).

When the new-format CSV is used, the lookup key `(search_name.lower(), sorting_field.lower())` will not match the `_AGGREGATION_RULES` keys. This means the explicit column labels (e.g., "Rule Name" / "Occurrences") are never used; instead the generic fallback runs, producing less descriptive column headers.

**Impact:** Excel reports have generic column names instead of descriptive ones. PPT chart data labels are less meaningful.

**Recommendation:** Either add new-format name entries to `_AGGREGATION_RULES`, or normalize the lookup to handle both naming conventions.

---

### M2. `run_scan.py` Missing Error Handling for `subprocess.run`

**File:** `/home/ubuntu/projects/tmas-ai-scanner/scripts/run_scan.py` (lines 47-53)

The `run_tmas_scan` function calls `subprocess.run()` without a try/except. If the `tmas` binary is not found or the process times out, the script crashes with an unhandled exception. Compare with `python_scripts/run_ai_scan.py` (lines 308-333) which properly catches `TimeoutExpired` and `FileNotFoundError`.

**Impact:** The CLI-based scan runner (`scripts/run_scan.py`) will crash with a raw traceback instead of a user-friendly error message.

**Recommendation:** Wrap in try/except like the `run_ai_scan.py` version does.

---

### M3. Validate Endpoint Skips `domains` and `tlds` Query Types

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 756-759)

The inline Python script in the validate endpoint only handles `base`, `filter`, and `raw` query types. It falls through to `query = base_q` for `domains` and `tlds` types, which means it validates against the unfiltered base query -- giving misleadingly high record counts for those searches. Of the 39 searches in `searches.csv`, 10 use `domains` type and 2 use `tlds` type.

**Impact:** The validation probe reports inaccurate counts for 12 out of 39 searches (~31%), making the validate feature unreliable.

**Recommendation:** Implement `domains` and `tlds` query building in the validate script (load domain files and TLD lists the same way `run_assessment.py` does), or call out to the existing Python query builder instead of duplicating the logic inline.

---

### M4. In-Memory Job Map Grows Unbounded

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 58-69, 90-111)

The `jobs` Map is populated on startup from all disk jobs (line 112: `restoreJobsFromDisk()`) and grows with each new job. Completed/failed jobs are never removed from the Map. Each job stores a `console` array that can grow large (all stdout/stderr output from the Python process).

**Impact:** Memory usage grows over time with no upper bound. On a long-running server processing many assessments, this could lead to OOM.

**Recommendation:** Implement a TTL or max-size policy. Remove completed jobs from the in-memory Map after a configurable time (e.g., 1 hour), or cap the `console` array at a fixed size (it is already sliced to the last 50-100 entries on read, but the full array is retained in memory).

---

### M5. `run_scan.py` Default Region Inconsistency

**File:** `/home/ubuntu/projects/tmas-ai-scanner/scripts/run_scan.py` (line 431)

The `--region` default is `os.getenv("TMAS_REGION", "us-east-1")`, but `CLAUDE.md`, the GitHub Actions workflow, and `run_ai_scan.py` all default to `"eu-central-1"`. This silent inconsistency means a user running `run_scan.py` without `--region` gets a different region than documented.

**Impact:** Scans may fail or use wrong region if user follows documentation but runs the CLI script.

**Recommendation:** Change the default in `run_scan.py` to `"eu-central-1"` to match all other components.

---

### M6. XSS Vulnerability in HTML Report Generation

**Files:** `/home/ubuntu/projects/tmas-ai-scanner/scripts/run_scan.py` (line 177), `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_ai_scan.py` (line 410)

The `parsed_results` JSON object is embedded in the HTML report via `json.dumps(parsed, indent=2)` inside a `<pre>` tag without HTML-escaping. If the TMAS CLI output or LLM response contains HTML/JavaScript in field values (e.g., `<script>alert(1)</script>`), it will be rendered as HTML when the report is opened in a browser.

**Impact:** Stored XSS if a scan target returns malicious content that ends up in the parsed results.

**Recommendation:** HTML-escape the `json.dumps` output before embedding it in the report, similar to how `raw_stdout` and `raw_stderr` are escaped.

---

### M7. Race Condition in Job Status After `POST /api/assessment/run`

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 398-476, 599)

The route sends `res.json({ jobId: job.id })` at line 440, then awaits the Python process. At line 472, `addHistoryEntry` reads `job.status`, but this reads the status *before* `updateJob` at lines 468-470 has been called (the `updateJob` at 468 sets the new status, then `addHistoryEntry` at 472 reads it -- this is fine within the same `await`). However, if the `spawnPython` promise rejects (line 473 catch block), the history entry is never written.

Similarly, at line 599 (aiscan run), the same pattern occurs: `addHistoryEntry` reads `job.status` but the `updateJob` that sets the status happens on line 595. In the aiscan case, `job.status` is read after `updateJob` updates the local object, so this is actually correct.

**Impact:** History entries for failed assessments (thrown exceptions) are silently lost.

**Recommendation:** Move `addHistoryEntry` inside the status update blocks so it is always called regardless of success or failure.

---

## Low Issues (Nice to Fix)

### L1. Duplicate Code Between `scripts/run_scan.py` and `python_scripts/run_ai_scan.py`

The HTML report generation, findings parsing, and risk determination logic is copy-pasted across both files (nearly identical ~300 lines). Any bug fix applied to one must be manually applied to the other.

**Recommendation:** Extract shared logic into a common module (e.g., `python_scripts/report_utils.py`).

---

### L2. `generate_config.py` Has Unguarded `import yaml` at Module Level

**File:** `/home/ubuntu/projects/tmas-ai-scanner/scripts/generate_config.py` (line 19)

If `pyyaml` is not installed, the script fails at import time with an unhelpful error. Compare with `run_ai_scan.py` which has a try/except around the yaml import with a manual YAML fallback.

**Recommendation:** Add a try/except import like the web backend wrapper does, or document the dependency clearly.

---

### L3. `Web Rep RU` Search Missing from `_AGGREGATION_RULES`

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_assessment.py`

The search `"Web Rep RU"` exists in `searches.csv` (with `ppt_slide=41`) and in `SLIDE_MAPPING` in `generate_ppt_report.py`, but its new-format name is not in `_AGGREGATION_RULES`. It does have a legacy entry `("web rep ru", "rulename")` which will match since the CSV uses `sorting=ruleName`. This one actually works, but is fragile.

---

### L4. `_search_chunk` Re-Request Loop When `progressRate < 100`

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_assessment.py` (lines 218-226)

When `progressRate < 100` and no `nextLink` is returned, the code sleeps 2s and re-requests from the beginning with `next_link = None`. This restarts the entire chunk query, which will re-fetch already-seen records. There is no deduplication, so the same records can be counted multiple times in the aggregation.

**Impact:** Potential double-counting of records in edge cases where the API takes multiple passes to complete.

**Recommendation:** Track seen record IDs or use a different retry strategy.

---

### L5. Column Width Calculation Limited to 26 Columns

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_assessment.py` (line 589)

`if col_idx < 26:` limits auto-column-width to columns A-Z. If data has more than 26 columns (unlikely for aggregated data, but possible for raw exports), columns beyond Z get default width.

---

### L6. `tarfile.extractall()` Without Filter

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_ai_scan.py` (line 198)

`tf.extractall(path=project_root, members=members)` uses `extractall` without the `filter` parameter. While the code filters members to only extract `"tmas"`, in Python 3.12+ a deprecation warning is emitted recommending `filter='data'` or `filter='fully_trusted'`.

**Recommendation:** Add `filter='data'` for Python 3.12+ compatibility.

---

### L7. History File Capped at 200 Entries Without Notification

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (line 150)

`saveHistory(history.slice(-200))` silently drops old entries. Users are not informed that history is being truncated.

---

### L8. Temporary Script File Not Cleaned on Crash

**File:** `/home/ubuntu/projects/tmas-ai-scanner/web/server.js` (lines 788-802)

In the validate endpoint, the temporary Python script file is created at line 789 and deleted at line 800 on success or in the catch block. However, if the Node.js process crashes between creation and deletion, the file persists. Since it contains the user's API key in plaintext, this is a minor security concern.

**Recommendation:** Use a proper temp file with automatic cleanup, or use environment variables to pass secrets.

---

### L9. `SLIDE_MAPPING` Has Duplicate Entries for Same Slides

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/generate_ppt_report.py` (lines 76-133)

Both new-format names and legacy names map to the same slide numbers. If both a new-format and legacy-format Excel file exist in the data directory, the same slide could be updated twice (last write wins). Not currently a bug since only one format is used at a time, but fragile.

---

### L10. `run_ai_scan.py` Uses `str | None` Union Syntax

**File:** `/home/ubuntu/projects/tmas-ai-scanner/python_scripts/run_ai_scan.py` (lines 658-661)

Uses Python 3.10+ syntax `str | None` and `tuple[str, str]`. If deployed on Python 3.9 (common on older Ubuntu LTS), this will fail at function definition time.

**Recommendation:** Use `Optional[str]` and `Tuple[str, str]` from `typing`, or declare minimum Python version.

---

## Recommendations

1. **Highest priority:** Fix the code injection vulnerability in `/api/agents/validate` (C1) and the path traversal issue (C2). These are exploitable security bugs.

2. **Add authentication** to the web server (C3). Even a simple shared-secret API key would be a significant improvement.

3. **Unify the `select` parameter logic** (C4) so it is not re-sent on every chunk after a 400 error.

4. **Update `_AGGREGATION_RULES`** to include new-format search names (M1) so Excel reports have proper column labels.

5. **Add a job cleanup mechanism** (M4) to prevent unbounded memory growth.

6. **Refactor shared code** (L1) between `scripts/run_scan.py` and `python_scripts/run_ai_scan.py` into a common module.

7. **Standardize the default region** to `eu-central-1` everywhere (M5).
