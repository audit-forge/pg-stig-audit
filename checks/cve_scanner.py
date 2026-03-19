"""CVE/KEV vulnerability scanning module for pg-stig-audit.

Fetches CVE data from NVD API v2 and CISA KEV catalog, caches results
locally, and produces CheckResult objects for integration into audit output.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timezone, timedelta
from typing import Optional

from checks.base import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_redis_version(runner) -> Optional[str]:
    """Run `redis-cli INFO server` via the runner and parse redis_version.

    Works for all three runner modes (docker / kubectl / direct).
    Returns the version string (e.g. "7.2.4") or None on failure.
    """
    try:
        info = runner.info("server")
        version = info.get("redis_version") or info.get("Redis Version")
        if version:
            return version.strip()
    except Exception as exc:
        warnings.warn(f"[cve] detect_redis_version error: {exc}")
    return None


def detect_pg_version(runner) -> Optional[str]:
    """Run `SELECT version();` via the runner and parse major.minor.

    Returns e.g. "16.2" or None on failure.
    """
    try:
        rows = runner.query_with_cols("SELECT version();", ["version"])
        if not rows:
            return None
        raw = rows[0].get("version", "")
        # Typical: "PostgreSQL 16.2 on x86_64-pc-linux-gnu, ..."
        import re
        m = re.search(r"PostgreSQL\s+(\d+\.\d+)", raw, re.IGNORECASE)
        if m:
            return m.group(1)
        # Fallback: grab first two numeric segments
        m2 = re.search(r"(\d+\.\d+)", raw)
        if m2:
            return m2.group(1)
    except Exception as exc:
        warnings.warn(f"[cve] detect_pg_version error: {exc}")
    return None


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_TTL_HOURS = 24


def _cache_path(cache_dir: str, filename: str) -> str:
    return os.path.join(cache_dir, filename)


def _load_cache(path: str) -> Optional[dict]:
    """Load a JSON cache file. Returns None if missing, expired, or corrupt."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cached_at_str = data.get("cached_at", "")
        if not cached_at_str:
            return None
        cached_at = datetime.fromisoformat(cached_at_str)
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - cached_at
        if age > timedelta(hours=_CACHE_TTL_HOURS):
            return None  # expired
        return data
    except Exception:
        return None


def _save_cache(path: str, payload) -> None:
    """Write payload to cache file with a timestamp."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"cached_at": datetime.now(timezone.utc).isoformat(), "data": payload},
                f,
                indent=2,
            )
    except Exception as exc:
        warnings.warn(f"[cve] cache write error ({path}): {exc}")


# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RATE_SLEEP = 6  # seconds between requests without API key


def fetch_cve_data(product: str, version: str, cache_dir: str) -> list[dict]:
    """Query NVD API v2 for CVEs matching product+version.

    Results are cached in data/cve_cache.json (keyed by product+version).
    Cache is valid for 24 hours.
    On network failure or rate-limit, returns cached data or [].

    Reads optional NVD_API_KEY env var for higher rate limits.
    """
    cache_file = _cache_path(cache_dir, "cve_cache.json")

    # Load whole-file cache dict
    try:
        if os.path.exists(cache_file):
            with open(cache_file, "r", encoding="utf-8") as f:
                full_cache = json.load(f)
        else:
            full_cache = {}
    except Exception:
        full_cache = {}

    cache_key = f"{product}:{version}"
    entry = full_cache.get(cache_key)
    if entry:
        try:
            cached_at = datetime.fromisoformat(entry.get("cached_at", ""))
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - cached_at
            if age <= timedelta(hours=_CACHE_TTL_HOURS):
                return entry.get("data", [])
        except Exception:
            pass

    # Fetch from NVD
    keyword = f"{product} {version}"
    params = {"keywordSearch": keyword, "resultsPerPage": "100"}
    url = _NVD_BASE + "?" + urllib.parse.urlencode(params)

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"User-Agent": "pg-stig-audit/cve-scanner"}
    if api_key:
        headers["apiKey"] = api_key
    else:
        # Respect rate limit: 5 requests per 30 seconds without key
        time.sleep(_NVD_RATE_SLEEP)

    cves: list[dict] = []
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        vulnerabilities = raw.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "")

            # Filter: description must mention the product name
            descriptions = cve_obj.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang", "en") == "en":
                    desc_text = d.get("value", "")
                    break
            if not desc_text and descriptions:
                desc_text = descriptions[0].get("value", "")

            if product.lower() not in desc_text.lower():
                continue

            # Extract CVSS score (prefer v3.1, fall back to v3.0, v2)
            cvss_score: Optional[float] = None
            metrics = cve_obj.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    try:
                        cvss_score = float(
                            metric_list[0].get("cvssData", {}).get("baseScore", 0)
                        )
                    except (TypeError, ValueError):
                        cvss_score = None
                    break

            cves.append(
                {
                    "cve_id": cve_id,
                    "description": desc_text,
                    "cvss_score": cvss_score,
                    "published": cve_obj.get("published", ""),
                }
            )
    except urllib.error.HTTPError as exc:
        warnings.warn(f"[cve] NVD API HTTP error {exc.code} for {product} {version}: {exc.reason}")
        # Return stale cache if available
        if entry:
            return entry.get("data", [])
        return []
    except Exception as exc:
        warnings.warn(f"[cve] NVD API error for {product} {version}: {exc}")
        if entry:
            return entry.get("data", [])
        return []

    # Persist to cache
    full_cache[cache_key] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "data": cves,
    }
    try:
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(full_cache, f, indent=2)
    except Exception as exc:
        warnings.warn(f"[cve] cve_cache write error: {exc}")

    return cves


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev_catalog(cache_dir: str) -> dict:
    """Download CISA KEV catalog and cache as data/kev_cache.json (refreshed daily).

    Returns a dict keyed by CVE ID, value is the KEV entry dict.
    On network failure, returns cached data or {}.
    """
    cache_file = _cache_path(cache_dir, "kev_cache.json")
    cached = _load_cache(cache_file)
    if cached is not None:
        raw_list = cached.get("data", [])
        return {item["cveID"]: item for item in raw_list if "cveID" in item}

    try:
        req = urllib.request.Request(
            _KEV_URL, headers={"User-Agent": "pg-stig-audit/cve-scanner"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        vulnerabilities = raw.get("vulnerabilities", [])
        _save_cache(cache_file, vulnerabilities)
        return {item["cveID"]: item for item in vulnerabilities if "cveID" in item}
    except Exception as exc:
        warnings.warn(f"[cve] KEV catalog fetch error: {exc}")
        # Try returning stale cache even if expired
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                stale = json.load(f)
            raw_list = stale.get("data", [])
            return {item["cveID"]: item for item in raw_list if "cveID" in item}
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Build CheckResult
# ---------------------------------------------------------------------------

def cve_to_check_result(
    cves: list[dict],
    kev: dict,
    product: str,
    version: str,
    local_path: str,
) -> CheckResult:
    """Build a CheckResult for the version/CVE check.

    check_id: RD-VER-001 (redis) or PG-VER-001 (postgres).
    status: FAIL if CVEs found, PASS if none, SKIP if version not detected.
    severity: CRITICAL if any CVSS >= 9.0 or KEV hit; HIGH if CVSS >= 7.0; MEDIUM otherwise.
    """
    if product.lower() in ("redis", "redis-server"):
        check_id = "RD-VER-001"
        product_label = "Redis"
    else:
        check_id = "PG-VER-001"
        product_label = "PostgreSQL"

    title = f"{product_label} version {version} — CVE/KEV vulnerability scan"

    if not cves:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=Status.PASS,
            severity=Severity.INFO,
            description=(
                f"No known CVEs found in NVD for {product_label} {version}."
            ),
            actual=f"version={version}, cves=0",
            expected="No CVEs matching this version",
            remediation="",
            category="vulnerability-management",
            cve_ids=[],
            kev_score="",
            cve_remediation="",
            local_path=local_path,
        )

    cve_ids = [c["cve_id"] for c in cves]
    kev_hits = {cid: kev[cid] for cid in cve_ids if cid in kev}

    # Determine severity
    max_cvss = max(
        (c.get("cvss_score") or 0.0 for c in cves), default=0.0
    )
    if kev_hits or max_cvss >= 9.0:
        severity = Severity.CRITICAL
    elif max_cvss >= 7.0:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    # KEV score string
    if kev_hits:
        first_kev = next(iter(kev_hits.values()))
        date_added = first_kev.get("dateAdded", "unknown")
        kev_score = f"HIGH_PRIORITY (CISA KEV - Added: {date_added})"
    else:
        kev_score = ""

    # Build remediation text
    remediation_parts = [
        f"Upgrade {product_label} to a patched version. "
        f"Currently running: {version}. "
        f"See NVD for affected version ranges."
    ]
    for cid, kev_entry in kev_hits.items():
        required_action = kev_entry.get("requiredAction", "")
        if required_action:
            remediation_parts.append(f"CISA KEV required action for {cid}: {required_action}")

    cve_remediation = " | ".join(remediation_parts)

    # Description
    cve_summary = "; ".join(
        f"{c['cve_id']} (CVSS: {c.get('cvss_score', 'N/A')})" for c in cves[:10]
    )
    if len(cves) > 10:
        cve_summary += f" ... and {len(cves) - 10} more"

    description = (
        f"{product_label} {version} has {len(cves)} known CVE(s): {cve_summary}. "
        f"KEV hits: {len(kev_hits)}."
    )

    references = ["https://nvd.nist.gov/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
    for cid in list(cve_ids)[:5]:
        references.append(f"https://nvd.nist.gov/vuln/detail/{cid}")

    return CheckResult(
        check_id=check_id,
        title=title,
        status=Status.FAIL,
        severity=severity,
        description=description,
        actual=f"version={version}, cves={len(cves)}, kev_hits={len(kev_hits)}",
        expected=f"No CVEs for {product_label} {version}",
        remediation=cve_remediation,
        references=references,
        category="vulnerability-management",
        cve_ids=cve_ids,
        kev_score=kev_score,
        cve_remediation=cve_remediation,
        local_path=local_path,
    )
