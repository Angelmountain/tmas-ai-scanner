#!/usr/bin/env python3
"""
TMAS AI Scanner - Config Generator

Generates the YAML configuration file required by `tmas aiscan llm`.
Supports dynamic endpoint selection for any OpenAI-compatible LLM API.

Supported providers (any OpenAI-compatible endpoint works):
  - OpenAI:    https://api.openai.com/v1/chat/completions
  - Azure:     https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-02-01
  - Anthropic: (via proxy/adapter)
  - Ollama:    http://localhost:11434/v1/chat/completions
  - Custom:    Any endpoint that accepts OpenAI chat completion format
"""

import argparse
import os
import sys
import yaml


VALID_PRESETS = ["owasp", "mitre"]

VALID_REGIONS = [
    "ap-southeast-2",
    "eu-central-1",
    "ap-south-1",
    "ap-northeast-1",
    "ap-southeast-1",
    "us-east-1",
    "me-central-1",
]

PROVIDER_DEFAULTS = {
    "openai": {
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4",
    },
    "azure_openai": {
        "endpoint": "",  # user must provide full Azure endpoint
        "model": "gpt-4",
    },
    "ollama": {
        "endpoint": "http://localhost:11434/v1/chat/completions",
        "model": "llama3",
    },
    "custom": {
        "endpoint": "",
        "model": "",
    },
}


def generate_config(
    endpoint: str,
    llm_api_key: str,
    model: str,
    attack_preset: str = "owasp",
    system_prompt: str = "",
) -> dict:
    """Generate TMAS aiscan config dictionary."""

    config = {
        "version": "1.0",
        "target": {
            "endpoint": endpoint,
            "api_key": llm_api_key,
            "model": model,
        },
        "attack_preset": attack_preset,
    }

    if system_prompt:
        config["target"]["system_prompt"] = system_prompt

    return config


def main():
    parser = argparse.ArgumentParser(
        description="Generate TMAS AI Scanner configuration file"
    )
    parser.add_argument(
        "--endpoint",
        default=os.getenv("LLM_ENDPOINT", ""),
        help="LLM API endpoint URL",
    )
    parser.add_argument(
        "--llm-api-key",
        default=os.getenv("LLM_API_KEY", ""),
        help="API key for the LLM endpoint",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("LLM_MODEL", "gpt-4"),
        help="Model name (default: gpt-4)",
    )
    parser.add_argument(
        "--preset",
        default=os.getenv("ATTACK_PRESET", "owasp"),
        choices=VALID_PRESETS,
        help="Attack preset: owasp or mitre (default: owasp)",
    )
    parser.add_argument(
        "--provider",
        default=os.getenv("LLM_PROVIDER", ""),
        choices=list(PROVIDER_DEFAULTS.keys()),
        help="LLM provider for default endpoint/model",
    )
    parser.add_argument(
        "--system-prompt",
        default=os.getenv("SYSTEM_PROMPT", ""),
        help="Optional system prompt to include in scan config",
    )
    parser.add_argument(
        "--output",
        default="config.yaml",
        help="Output config file path (default: config.yaml)",
    )

    args = parser.parse_args()

    # Apply provider defaults if set
    if args.provider and args.provider in PROVIDER_DEFAULTS:
        defaults = PROVIDER_DEFAULTS[args.provider]
        if not args.endpoint and defaults["endpoint"]:
            args.endpoint = defaults["endpoint"]
        if args.model == "gpt-4" and defaults["model"]:
            args.model = defaults["model"]

    # Validate required fields
    if not args.endpoint:
        print("ERROR: --endpoint or LLM_ENDPOINT env var is required", file=sys.stderr)
        sys.exit(1)
    if not args.llm_api_key:
        print(
            "ERROR: --llm-api-key or LLM_API_KEY env var is required", file=sys.stderr
        )
        sys.exit(1)

    config = generate_config(
        endpoint=args.endpoint,
        llm_api_key=args.llm_api_key,
        model=args.model,
        attack_preset=args.preset,
        system_prompt=args.system_prompt,
    )

    with open(args.output, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Config generated: {args.output}")
    print(f"  Endpoint: {args.endpoint}")
    print(f"  Model:    {args.model}")
    print(f"  Preset:   {args.preset}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
