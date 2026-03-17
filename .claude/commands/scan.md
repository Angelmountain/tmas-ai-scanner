Trigger TMAS AI security scans via GitHub Actions.

Ask the user for the required API keys if not provided as arguments:
1. **Vision One API key** (TMAS authentication)
2. **LLM API key** (for whichever provider is being scanned)

Never store or log API keys in files, memory, or commits.

Then trigger the full scan matrix using `gh workflow run` against the `ai-security-scan.yml` workflow.

Default scan matrix (providers x presets):
- **OpenAI**: models `gpt-4` and `gpt-4o`, presets `owasp` and `mitre` (4 runs)
- **Anthropic**: model `claude-sonnet-4-6`, presets `owasp` and `mitre` (2 runs)
- Total: 6 runs

The user can specify which providers/models/presets to scan. If not specified, run the full matrix.

```
gh workflow run ai-security-scan.yml \
  -f vision_one_api_key="<V1_KEY>" \
  -f vision_one_region="eu-central-1" \
  -f llm_provider="<PROVIDER>" \
  -f llm_api_key="<LLM_KEY>" \
  -f llm_model="<MODEL>" \
  -f attack_preset="<PRESET>"
```

Notes:
- When `llm_provider` is set, `llm_endpoint` and `llm_model` can be omitted (provider defaults apply)
- Anthropic provider requires an OpenAI-compatible proxy (like LiteLLM) — TMAS calls /chat/completions
- Launch all runs in parallel using separate `gh workflow run` calls

After triggering, monitor all runs with `gh run list --workflow=ai-security-scan.yml` and report their status. Once complete, download artifacts with `gh run download <run_id>` and summarize the results.

If the user provides arguments like `$ARGUMENTS`, parse them for API keys or overrides to the defaults.
