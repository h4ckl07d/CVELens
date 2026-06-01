import argparse
import sys
import anthropic

from config import ANTHROPIC_API_KEY, CLAUDE_MODEL
from fetcher import fetch_nvd, check_cisa_kev, extract_summary
from prompt_builder import build_system_prompt, build_user_prompt
from report import print_header, print_report, print_error


def parse_args():
    parser = argparse.ArgumentParser(
        prog="cvelens",
        description="CVELens — Vulnerability Intelligence Engine"
    )
    parser.add_argument("cve_id", help="CVE ID to analyze (e.g. CVE-2021-44228)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Deep technical detail")
    parser.add_argument("--short", action="store_true", help="Executive briefing only")
    parser.add_argument("--code", action="store_true", help="Include exploit pseudocode")
    parser.add_argument("--deep", action="store_true", help="Full intelligence dump")
    return parser.parse_args()


def main():
    args = parse_args()
    cve_id = args.cve_id.upper().strip()

    flags = {
        "verbose": args.verbose,
        "short": args.short,
        "code": args.code,
        "deep": args.deep,
    }

    # 1. Fetch data
    try:
        print(f"\n🔍 Fetching data for {cve_id}...")
        raw = fetch_nvd(cve_id)
        summary = extract_summary(raw)
    except Exception as e:
        print_error(f"Failed to fetch CVE data: {e}")
        sys.exit(1)

    # 2. Check CISA KEV
    print("🛡  Checking CISA KEV catalog...")
    exploited = check_cisa_kev(cve_id)

    # 3. Print header
    print_header(cve_id, summary["cvss_score"], summary["cvss_severity"] or "UNKNOWN", exploited)

    # 4. Build prompt + call Claude (streaming)
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    system = build_system_prompt()
    user_prompt = build_user_prompt(summary, flags, exploited)

    print("⚙  Generating intelligence report...\n")

    full_response = ""
    with client.messages.stream(
        model=CLAUDE_MODEL,
        max_tokens=2048,
        system=system,
        messages=[{"role": "user", "content": user_prompt}]
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
            full_response += text

    print("\n")  # spacing after streamed output


if __name__ == "__main__":
    main()