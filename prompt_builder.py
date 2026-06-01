def build_system_prompt() -> str:
    return (
        "You are CVELens, a cybersecurity vulnerability intelligence engine. "
        "You produce structured, high-fidelity security briefings for defensive research, "
        "threat modeling, and secure engineering education. "
        "Be precise. Use security engineering terminology. "
        "Never speculate unless clearly labelled as hypothetical. "
        "Prioritize defensive understanding."
    )


def build_user_prompt(summary: dict, flags: dict, exploited: bool) -> str:
    cve_id = summary["id"]
    description = summary["description"]
    cvss_score = summary["cvss_score"]
    cvss_severity = summary["cvss_severity"]
    cvss_vector = summary["cvss_vector"]
    cwes = ", ".join(summary["cwes"]) or "Unknown"
    references = "\n".join(summary["references"])
    kev_status = "YES — actively exploited in the wild (CISA KEV)" if exploited else "No known active exploitation"

    depth_instruction = ""
    if flags.get("short"):
        depth_instruction = (
            "Produce a compressed executive briefing only. "
            "Max 250 words total. Skip deep technical breakdowns. "
            "Focus on: what it is, who is affected, severity, and fix."
        )
    elif flags.get("verbose"):
        depth_instruction = (
            "Expand every section with deep technical detail. "
            "Include real-world attack chains where publicly documented. "
            "Include threat actor attribution if publicly known."
        )
    else:
        depth_instruction = "Produce the standard structured report at normal depth."

    code_instruction = ""
    if flags.get("code"):
        code_instruction = (
            "\n\nAfter the Exploit Mechanics section, add a block titled "
            "'## Exploit Logic' containing annotated pseudocode or exploit structure. "
            "Label it clearly as educational/defensive reference only."
        )

    deep_instruction = ""
    if flags.get("deep"):
        deep_instruction = (
            "\n\nAt the end, add:\n"
            "- Known exploitation in the wild: Yes/No + context\n"
            "- Associated threat groups (if publicly documented)\n"
            "- Timeline: disclosure date, patch date, first known exploitation\n"
            "- MITRE ATT&CK TTP mappings if applicable"
        )

    prompt = f"""Analyze the following CVE and produce a CVELens intelligence report.

CVE ID: {cve_id}
NVD Description: {description}
CVSS Score: {cvss_score} ({cvss_severity})
CVSS Vector: {cvss_vector}
CWE(s): {cwes}
CISA KEV Status: {kev_status}
References: {references}

{depth_instruction}
{code_instruction}
{deep_instruction}

Structure your report with these sections in order:
1. Executive Summary
2. Technical Classification (Product, Vendor, Vulnerability Type, Root Cause)
3. CVSS Interpretation (score meaning in practical risk terms)
4. Affected Surface (products, versions, config dependencies)
5. Attack Preconditions (network access, privileges, user interaction)
6. Exploit Mechanics (attack flow, entry point, execution chain)
7. Impact Analysis (confidentiality, integrity, availability)
8. Mitigation & Remediation (patch guidance, workarounds)
"""
    return prompt