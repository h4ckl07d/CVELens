
#!/usr/bin/env python3
import argparse
import sys
from groq import Groq

from config import GROQ_API_KEY, GROQ_MODEL
from fetcher import fetch_nvd, check_cisa_kev, extract_summary
from prompt_builder import build_system_prompt, build_user_prompt
from report import (
    print_banner, print_header, print_status,
    print_error, render_sections, print_done
)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="cvelens",
        description="CVELens — Vulnerability Intelligence Engine"
    )
    parser.add_argument("cve_id", help="CVE ID to analyze (e.g. CVE-2021-44228)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Deep technical detail")
    parser.add_argument("--short",         action="store_true", help="Executive briefing only")
    parser.add_argument("--code",          action="store_true", help="Include exploit pseudocode")
    parser.add_argument("--deep",          action="store_true", help="Full intelligence dump")
    return parser.parse_args()


def main():
    print_banner()                          # ← banner on every run

    args = parse_args()
    cve_id = args.cve_id.upper().strip()

    flags = {
        "verbose": args.verbose,
        "short":   args.short,
        "code":    args.code,
        "deep":    args.deep,
    }

    # 1. Fetch NVD data
    print_status(f"Fetching NVD data for [bold]{cve_id}[/bold]...")
    try:
        raw = fetch_nvd(cve_id)
        summary = extract_summary(raw)
    except Exception as e:
        print_error(f"Failed to fetch CVE data: {e}")
        sys.exit(1)

    # 2. CISA KEV check
    print_status("Checking CISA Known Exploited Vulnerabilities catalog...")
    exploited = check_cisa_kev(cve_id)

    # 3. Header card
    print_header(
        cve_id,
        summary["cvss_score"],
        summary["cvss_severity"] or "UNKNOWN",
        exploited,
        summary.get("published", "")
    )

    # 4. Generate report
    print_status("Generating intelligence report via GPT-OSS-120B...\n")

    client = Groq(api_key=GROQ_API_KEY)
    system     = build_system_prompt()
    user_prompt = build_user_prompt(summary, flags, exploited)

    stream = client.chat.completions.create(
        model=GROQ_MODEL,
        max_tokens=2048,
        messages=[
            {"role": "system",  "content": system},
            {"role": "user",    "content": user_prompt}
        ],
        stream=True
    )

    # Buffer the stream — render sections after full response
    full_response = ""
    for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            full_response += delta

    # 5. Render structured output
    render_sections(full_response)
    print_done(cve_id)


if __name__ == "__main__":
    main()