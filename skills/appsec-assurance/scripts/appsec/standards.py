"""Standards mappings. Used to enrich findings (e.g. from external tools) that
carry a CWE but no OWASP category, and to render the coverage matrix."""

from typing import Dict, List

OWASP_TOP10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

OWASP_API_2023 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Coarse CWE -> OWASP Top 10 2021 mapping for common weaknesses.
CWE_TO_OWASP_2021 = {
    "CWE-22": "A01:2021", "CWE-284": "A01:2021", "CWE-285": "A01:2021", "CWE-352": "A01:2021",
    "CWE-601": "A01:2021", "CWE-639": "A01:2021", "CWE-862": "A01:2021", "CWE-863": "A01:2021",
    "CWE-915": "A01:2021", "CWE-269": "A01:2021", "CWE-200": "A01:2021", "CWE-538": "A01:2021",
    "CWE-261": "A02:2021", "CWE-295": "A02:2021", "CWE-310": "A02:2021", "CWE-311": "A02:2021",
    "CWE-312": "A02:2021", "CWE-319": "A02:2021", "CWE-321": "A02:2021", "CWE-326": "A02:2021",
    "CWE-327": "A02:2021", "CWE-328": "A02:2021", "CWE-329": "A02:2021", "CWE-330": "A02:2021",
    "CWE-338": "A02:2021", "CWE-916": "A02:2021", "CWE-347": "A02:2021",
    "CWE-20": "A03:2021", "CWE-74": "A03:2021", "CWE-77": "A03:2021", "CWE-78": "A03:2021",
    "CWE-79": "A03:2021", "CWE-89": "A03:2021", "CWE-90": "A03:2021", "CWE-94": "A03:2021",
    "CWE-95": "A03:2021", "CWE-98": "A03:2021", "CWE-113": "A03:2021", "CWE-643": "A03:2021",
    "CWE-917": "A03:2021", "CWE-943": "A03:2021", "CWE-1336": "A03:2021",
    "CWE-209": "A04:2021", "CWE-256": "A04:2021", "CWE-362": "A04:2021", "CWE-367": "A04:2021",
    "CWE-434": "A04:2021", "CWE-840": "A04:2021",
    "CWE-16": "A05:2021", "CWE-611": "A05:2021", "CWE-614": "A05:2021", "CWE-942": "A05:2021",
    "CWE-1004": "A05:2021", "CWE-489": "A05:2021", "CWE-215": "A05:2021", "CWE-250": "A05:2021",
    "CWE-548": "A05:2021", "CWE-693": "A05:2021", "CWE-1188": "A05:2021", "CWE-183": "A05:2021",
    "CWE-937": "A06:2021", "CWE-1035": "A06:2021", "CWE-1104": "A06:2021", "CWE-1395": "A06:2021",
    "CWE-287": "A07:2021", "CWE-307": "A07:2021", "CWE-384": "A07:2021", "CWE-521": "A07:2021",
    "CWE-613": "A07:2021", "CWE-798": "A07:2021", "CWE-208": "A07:2021", "CWE-640": "A07:2021",
    "CWE-345": "A08:2021", "CWE-494": "A08:2021", "CWE-502": "A08:2021", "CWE-506": "A08:2021",
    "CWE-829": "A08:2021", "CWE-1321": "A08:2021", "CWE-427": "A08:2021", "CWE-1357": "A08:2021",
    "CWE-117": "A09:2021", "CWE-223": "A09:2021", "CWE-532": "A09:2021", "CWE-778": "A09:2021",
    "CWE-918": "A10:2021",
}

# Category used when a finding has neither a CWE nor a category from its source.
CATEGORY_BY_CWE_PREFIX = {"A01": "authorization", "A02": "crypto", "A03": "injection",
                          "A04": "design", "A05": "misconfiguration", "A06": "vulnerable-dependency",
                          "A07": "authentication", "A08": "supply-chain", "A09": "logging",
                          "A10": "ssrf"}


def owasp_for_cwes(cwes: List[str]) -> List[str]:
    return sorted({CWE_TO_OWASP_2021[c] for c in cwes if c in CWE_TO_OWASP_2021})


def coverage_matrix(findings, coverage_entries) -> Dict[str, Dict]:
    """Per OWASP Top 10 category: open findings and whether any check targeted it."""
    from .findings import OPEN_STATUSES
    m = {k: {"name": v, "open_findings": 0} for k, v in OWASP_TOP10_2021.items()}
    for f in findings:
        if f.status in OPEN_STATUSES:
            for o in f.owasp:
                if o in m:
                    m[o]["open_findings"] += 1
    return m
