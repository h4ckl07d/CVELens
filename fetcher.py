import requests
from config import NVD_BASE_URL, CISA_KEV_URL

def fetch_nvd(cve_id: str) -> dict:
    """Fetch raw CVE data from NVD API."""
    response = requests.get(
        NVD_BASE_URL,
        params={"cveId": cve_id},
        headers={"User-Agent": "CVELens/1.0"},
        timeout=10
    )
    response.raise_for_status()
    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"CVE {cve_id} not found in NVD.")

    return vulns[0]["cve"]  # return the core CVE object


def check_cisa_kev(cve_id: str) -> bool:
    """Check if CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        kev_list = response.json().get("vulnerabilities", [])
        return any(v["cveID"] == cve_id for v in kev_list)
    except Exception:
        return False  # fail silently, don't block the report


def extract_summary(cve_data: dict) -> dict:
    """Pull key fields from raw NVD JSON into a clean dict."""
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"), "No description available."
    )

    # CVSS v3.1 preferred, fall back to v3.0 or v2
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    cvss_vector = None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_severity = m.get("baseSeverity")
            cvss_vector = m.get("vectorString")
            break

    weaknesses = cve_data.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc["value"] != "NVD-CWE-Other":
                cwes.append(desc["value"])

    references = [r["url"] for r in cve_data.get("references", [])[:5]]

    return {
        "id": cve_data.get("id"),
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwes": cwes,
        "published": cve_data.get("published", ""),
        "last_modified": cve_data.get("lastModified", ""),
        "references": references,
    }   