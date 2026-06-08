import requests
import socket
from requests.adapters import HTTPAdapter
from urllib3.util.connection import create_connection
from config import NVD_BASE_URL, CISA_KEV_URL


# Force IPv4 — fixes "Network is unreachable" on machines with broken IPv6
class IPv4Adapter(HTTPAdapter):
    def send(self, *args, **kwargs):
        old_create = socket.create_connection
        def ipv4_create(address, *a, **kw):
            kw['family'] = socket.AF_INET
            return old_create(address, *a, **kw)
        socket.create_connection = ipv4_create
        try:
            return super().send(*args, **kwargs)
        finally:
            socket.create_connection = old_create


def _session():
    """Returns a requests session with IPv4 forced and retries enabled."""
    from urllib3.util.retry import Retry
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1)
    adapter = IPv4Adapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_nvd(cve_id: str) -> dict:
    response = _session().get(
        NVD_BASE_URL,
        params={"cveId": cve_id},
        headers={"User-Agent": "CVELens/1.0"},
        timeout=15
    )
    response.raise_for_status()
    data = response.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"CVE {cve_id} not found in NVD.")
    return vulns[0]["cve"]


def check_cisa_kev(cve_id: str) -> bool:
    try:
        response = _session().get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        kev_list = response.json().get("vulnerabilities", [])
        return any(v["cveID"] == cve_id for v in kev_list)
    except Exception:
        return False


def extract_summary(cve_data: dict) -> dict:
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"), "No description available."
    )

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
        "id":           cve_data.get("id"),
        "description":  description,
        "cvss_score":   cvss_score,
        "cvss_severity":cvss_severity,
        "cvss_vector":  cvss_vector,
        "cwes":         cwes,
        "published":    cve_data.get("published", ""),
        "last_modified":cve_data.get("lastModified", ""),
        "references":   references,
    }