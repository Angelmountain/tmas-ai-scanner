Run the full POC (Proof of Concept) security assessment pipeline.

This command orchestrates the entire assessment workflow using the poc-orchestrator agent. It runs through 5 phases: validation, data collection, analysis, quality assurance, and report generation.

## Arguments

The user may provide arguments as `$ARGUMENTS`. Parse them for:
- `--api-key <key>` or `TREND_MICRO_API_KEY` - Vision One API token
- `--region <region>` or `--base-url <url>` - API region/base URL
- `--time-interval <hours>` - Hours of data to query (default: 720 = 30 days)
- `--skip-validation` - Skip the search validation phase
- `--skip-qa` - Skip the quality assurance phase
- `--data-only` - Only collect data, skip analysis and reports
- `--report-only` - Only generate reports from existing data

## Workflow

### Phase 1: Pre-flight Checks
1. Verify `TREND_MICRO_API_KEY` is set (from args or environment)
2. Verify API connectivity by making a test call
3. Check that required files exist:
   - `templates/searches.csv`
   - `templates/config.json`
   - `templates/domains/*.txt`
   - `python_scripts/run_assessment.py`
   - `python_scripts/generate_ppt_report.py`

### Phase 2: Search Validation (search-validator agent)
- Test all 39 searches using countOnly mode
- Report which searches are working and which have issues
- Decide whether to proceed based on results

### Phase 3: Data Collection (data-collector agent)
- Run the full assessment via `python_scripts/run_assessment.py`
- Collect data from all enabled searches
- Monitor progress and handle errors
- Output: Excel workbook in `data/`

### Phase 4: Data Analysis (data-analyzer agent)
- Analyze collected data for security insights
- Generate executive summary
- Identify critical findings
- Output: Analysis files in `.claude/memory/data-analyzer/`

### Phase 5: Quality Assurance (quality-checker agent)
- Validate data completeness
- Cross-reference counts
- Check for anomalies
- Output: QA scorecard in `.claude/memory/quality-checker/`

### Phase 6: Report Generation (report-builder agent)
- Generate PowerPoint presentation
- Generate Excel summary
- Generate HTML dashboard
- Package into ZIP
- Output: Reports in `reports/output/`

### Phase 7: Final Summary
- Compile all results
- Print executive summary
- List all deliverable files
- Report total execution time

## Environment Setup

If the API key is not provided as an argument, check these sources in order:
1. `$TREND_MICRO_API_KEY` environment variable
2. Ask the user interactively

Default API base URL by region:
- `eu-central-1`: `https://api.eu.xdr.trendmicro.com`
- `us-east-1`: `https://api.xdr.trendmicro.com`
- `ap-southeast-1`: `https://api.sg.xdr.trendmicro.com`
- `ap-southeast-2`: `https://api.au.xdr.trendmicro.com`
- `ap-northeast-1`: `https://api.co.jp.xdr.trendmicro.com`
- `ap-south-1`: `https://api.in.xdr.trendmicro.com`

## Security

- Never store or log API keys in files, memory, or output
- Never commit API keys to git
- API keys should only exist as environment variables during execution

## Output Location

All deliverables are placed in `reports/output/`:
- `NDR_Security_Assessment_YYYYMMDD.pptx`
- `assessment_summary_YYYYMMDD.xlsx`
- `dashboard_YYYYMMDD.html`
- `poc_report_YYYYMMDD.zip`

Pipeline status is tracked in `.claude/memory/poc-orchestrator/`.
