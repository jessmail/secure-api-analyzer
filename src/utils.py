"""JWT manipulation utilities and HTTP helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import jwt


@dataclass
class Finding:
    """Represents a single security finding."""

    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    owasp_category: str
    description: str
    endpoint: str
    method: str = "GET"
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    request_data: Optional[dict[str, Any]] = None
    response_status: Optional[int] = None
    response_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity,
            "owasp_category": self.owasp_category,
            "description": self.description,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "response_status": self.response_status,
            "response_snippet": self.response_snippet[:500],
        }


@dataclass
class ScanResult:
    """Aggregated results from a scan."""

    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    endpoints_tested: int = 0
    suite_name: str = ""

    @property
    def duration(self) -> float:
        """Scan duration in seconds."""
        return self.end_time - self.start_time

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    def to_dict(self) -> dict[str, Any]:
        """Serialize scan result."""
        return {
            "target": self.target,
            "suite_name": self.suite_name,
            "duration_seconds": round(self.duration, 2),
            "endpoints_tested": self.endpoints_tested,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# JWT Utilities
# ---------------------------------------------------------------------------

def create_none_alg_token(payload: dict[str, Any]) -> str:
    """Create a JWT with algorithm set to 'none' (alg:none attack).

    This forges a token without any signature, exploiting servers
    that accept the 'none' algorithm.

    Args:
        payload: JWT payload claims.

    Returns:
        Forged JWT string with no signature.
    """
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header).encode())
    payload_b64 = _base64url_encode(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}."


def create_expired_token(
    payload: dict[str, Any],
    secret: str = "test-secret",
    expired_at: int = 1704067200,  # 2024-01-01T00:00:00Z
) -> str:
    """Create a JWT that is already expired.

    Args:
        payload: Base JWT payload claims.
        secret: Signing secret.
        expired_at: Unix timestamp for the exp claim.

    Returns:
        Expired JWT string.
    """
    payload_copy = dict(payload)
    payload_copy["exp"] = expired_at
    payload_copy["iat"] = expired_at - 3600
    return jwt.encode(payload_copy, secret, algorithm="HS256")


def create_malformed_token() -> str:
    """Create a structurally malformed JWT.

    Returns:
        A string that looks like a JWT but has invalid structure.
    """
    return "eyJhbGciOiJub25lIn0.INVALID_PAYLOAD_HERE.INVALID_SIG"


def create_wrong_key_token(
    payload: dict[str, Any],
    wrong_secret: str = "wrong-secret-key-12345",
) -> str:
    """Create a JWT signed with the wrong secret key.

    Args:
        payload: JWT payload claims.
        wrong_secret: An incorrect signing secret.

    Returns:
        JWT string signed with the wrong key.
    """
    payload_copy = dict(payload)
    payload_copy["iat"] = int(time.time())
    payload_copy["exp"] = int(time.time()) + 3600
    return jwt.encode(payload_copy, wrong_secret, algorithm="HS256")


def decode_jwt_unsafe(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a JWT without verification (for inspection only).

    Args:
        token: JWT string.

    Returns:
        Tuple of (header, payload) dictionaries.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}

    try:
        header = json.loads(_base64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception):
        header = {}

    try:
        payload = json.loads(_base64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception):
        payload = {}

    return header, payload


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ---------------------------------------------------------------------------
# HTTP Helpers
# ---------------------------------------------------------------------------

def build_url(base: str, path: str) -> str:
    """Safely join base URL and path.

    Args:
        base: Base URL (e.g., https://api.example.com).
        path: API path (e.g., /api/v1/users).

    Returns:
        Full URL string.
    """
    if not base.endswith("/"):
        base += "/"
    if path.startswith("/"):
        path = path[1:]
    return urljoin(base, path)


def normalize_url(url: str) -> str:
    """Normalize a URL by ensuring scheme is present."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url.rstrip("/")


async def make_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: Optional[dict[str, str]] = None,
    data: Optional[Any] = None,
    json_body: Optional[Any] = None,
    timeout: int = 30,
) -> tuple[int, str, dict[str, str]]:
    """Execute an HTTP request and return status, body, response headers.

    Args:
        session: aiohttp client session.
        method: HTTP method (GET, POST, etc.).
        url: Target URL.
        headers: Request headers.
        data: Form data.
        json_body: JSON request body.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (status_code, response_body, response_headers).
    """
    request_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=data,
            json=json_body,
            timeout=request_timeout,
            ssl=False,
        ) as resp:
            body = await resp.text()
            resp_headers = {k: v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except aiohttp.ClientError as exc:
        return 0, str(exc), {}
    except Exception as exc:
        return 0, f"Request failed: {exc}", {}


def get_severity_weight(severity: str) -> int:
    """Map severity string to numeric weight for sorting."""
    weights = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }
    return weights.get(severity.upper(), 0)


def calculate_cvss_base(
    attack_vector: str = "network",
    attack_complexity: str = "low",
    privileges_required: str = "none",
    user_interaction: str = "none",
    confidentiality: str = "high",
    integrity: str = "low",
    availability: str = "none",
) -> float:
    """Simplified CVSS v3.1 base score estimation.

    This is a simplified calculation for quick scoring. For production
    use, a full CVSS calculator should be used.

    Returns:
        Estimated CVSS score (0.0 - 10.0).
    """
    av_scores = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
    ac_scores = {"low": 0.77, "high": 0.44}
    pr_scores = {"none": 0.85, "low": 0.62, "high": 0.27}
    ui_scores = {"none": 0.85, "required": 0.62}
    impact_scores = {"none": 0.0, "low": 0.22, "high": 0.56}

    exploitability = (
        8.22
        * av_scores.get(attack_vector, 0.85)
        * ac_scores.get(attack_complexity, 0.77)
        * pr_scores.get(privileges_required, 0.85)
        * ui_scores.get(user_interaction, 0.85)
    )

    conf_impact = impact_scores.get(confidentiality, 0.0)
    intg_impact = impact_scores.get(integrity, 0.0)
    avail_impact = impact_scores.get(availability, 0.0)

    iss = 1.0 - ((1.0 - conf_impact) * (1.0 - intg_impact) * (1.0 - avail_impact))

    if iss <= 0:
        return 0.0

    impact = 6.42 * iss
    base = min(exploitability + impact, 10.0)
    return round(base, 1)
