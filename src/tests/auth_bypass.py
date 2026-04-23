"""Authentication bypass test suite.

Tests for OWASP API2:2023 - Broken Authentication vulnerabilities
including missing auth headers, JWT manipulation, and token validation flaws.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import aiohttp

from src.utils import (
    Finding,
    ScanResult,
    build_url,
    create_expired_token,
    create_malformed_token,
    create_none_alg_token,
    create_wrong_key_token,
    make_request,
)


class AuthBypassTester:
    """Tests for authentication bypass vulnerabilities."""

    OWASP_CATEGORY = "API2:2023 - Broken Authentication"

    def __init__(
        self,
        base_url: str,
        valid_token: Optional[str] = None,
        timeout: int = 30,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        self.base_url = base_url
        self.valid_token = valid_token
        self.timeout = timeout
        self.options = options or {}
        self.jwt_payload = {
            "sub": "test-user-001",
            "role": "user",
            "iss": "secure-api-analyzer",
        }

    async def run(
        self,
        session: aiohttp.ClientSession,
        endpoints: list[dict[str, str]],
    ) -> ScanResult:
        """Execute all authentication bypass tests against given endpoints.

        Args:
            session: aiohttp client session for making requests.
            endpoints: List of endpoint dicts with 'path' and 'method' keys.

        Returns:
            ScanResult containing all findings from this suite.
        """
        result = ScanResult(target=self.base_url, suite_name="auth_bypass")
        result.start_time = time.time()

        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            url = build_url(self.base_url, path)

            findings = await self._test_endpoint(session, url, method)
            result.findings.extend(findings)
            result.endpoints_tested += 1

        result.end_time = time.time()
        return result

    async def _test_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> list[Finding]:
        """Run all auth bypass tests against a single endpoint."""
        findings: list[Finding] = []

        tests = [
            self._test_missing_auth,
            self._test_empty_token,
            self._test_malformed_jwt,
            self._test_expired_token,
            self._test_alg_none_attack,
            self._test_wrong_key,
        ]

        for test_fn in tests:
            try:
                finding = await test_fn(session, url, method)
                if finding is not None:
                    findings.append(finding)
            except Exception as exc:
                findings.append(
                    Finding(
                        title=f"Test error: {test_fn.__name__}",
                        severity="INFO",
                        owasp_category=self.OWASP_CATEGORY,
                        description=f"Test encountered an error: {exc}",
                        endpoint=url,
                        method=method,
                    )
                )

        return findings

    async def _test_missing_auth(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test access without any authentication header.

        A protected endpoint should return 401 Unauthorized when no
        authentication credentials are provided.
        """
        headers = {"Content-Type": "application/json"}
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="Missing authentication header accepted",
                severity="CRITICAL",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} returned {status} without any "
                    f"authentication header. Protected resources must require "
                    f"valid credentials."
                ),
                endpoint=url,
                method=method,
                evidence=f"Status {status} returned without Authorization header",
                remediation=(
                    "Enforce authentication on all protected endpoints. "
                    "Return 401 Unauthorized when no valid credentials are provided."
                ),
                cvss_score=9.8,
                response_status=status,
                response_snippet=body[:200],
            )
        return None

    async def _test_empty_token(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test with an empty Authorization header value.

        The server should reject requests where the token is empty or blank.
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": "",
        }
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="Empty authentication token accepted",
                severity="CRITICAL",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} accepted an empty Authorization "
                    f"header and returned {status}."
                ),
                endpoint=url,
                method=method,
                evidence="Empty Authorization header returned success status",
                remediation=(
                    "Validate that the Authorization header contains a non-empty, "
                    "properly formatted token before processing the request."
                ),
                cvss_score=9.8,
                response_status=status,
                response_snippet=body[:200],
            )
        return None

    async def _test_malformed_jwt(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test with a structurally malformed JWT.

        The server should detect and reject tokens with invalid structure.
        """
        malformed = create_malformed_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {malformed}",
        }
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="Malformed JWT accepted",
                severity="HIGH",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} accepted a structurally malformed "
                    f"JWT and returned {status}. The token had invalid Base64 "
                    f"segments."
                ),
                endpoint=url,
                method=method,
                evidence=f"Malformed token '{malformed[:50]}...' accepted",
                remediation=(
                    "Implement strict JWT structure validation. Reject tokens "
                    "that cannot be properly decoded before processing claims."
                ),
                cvss_score=8.6,
                response_status=status,
                response_snippet=body[:200],
            )
        return None

    async def _test_expired_token(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test with an expired JWT.

        The server must check the 'exp' claim and reject expired tokens.
        """
        expired = create_expired_token(self.jwt_payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {expired}",
        }
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="Expired JWT accepted",
                severity="MEDIUM",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} accepted an expired JWT token "
                    f"(exp: 2024-01-01) and returned {status}."
                ),
                endpoint=url,
                method=method,
                evidence="Token with past expiration claim was accepted",
                remediation=(
                    "Always validate the 'exp' claim in JWT tokens. Reject "
                    "tokens where the current time exceeds the expiration timestamp."
                ),
                cvss_score=6.5,
                response_status=status,
                response_snippet=body[:200],
            )
        return None

    async def _test_alg_none_attack(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test JWT algorithm 'none' attack.

        The 'none' algorithm attack exploits servers that accept unsigned
        tokens. This is a well-known JWT vulnerability where an attacker
        changes the algorithm header to 'none' and strips the signature.
        """
        none_token = create_none_alg_token(self.jwt_payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {none_token}",
        }
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="JWT algorithm 'none' attack successful",
                severity="CRITICAL",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} accepted a JWT with algorithm "
                    f"set to 'none' (no signature). This allows any attacker "
                    f"to forge valid tokens without knowing the signing key."
                ),
                endpoint=url,
                method=method,
                evidence="Token with alg:none and empty signature was accepted",
                remediation=(
                    "Explicitly whitelist allowed JWT algorithms on the server side. "
                    "Never accept 'none' as a valid algorithm. Use a library that "
                    "rejects unsigned tokens by default."
                ),
                cvss_score=9.8,
                response_status=status,
                response_snippet=body[:200],
            )
        return None

    async def _test_wrong_key(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
    ) -> Optional[Finding]:
        """Test JWT signed with incorrect secret key.

        The server must verify the token signature against the correct key.
        """
        wrong_key_token = create_wrong_key_token(self.jwt_payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {wrong_key_token}",
        }
        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            return Finding(
                title="JWT signed with wrong key accepted",
                severity="HIGH",
                owasp_category=self.OWASP_CATEGORY,
                description=(
                    f"Endpoint {method} {url} accepted a JWT signed with an "
                    f"incorrect secret key. This indicates the server may not "
                    f"be verifying token signatures properly."
                ),
                endpoint=url,
                method=method,
                evidence="Token signed with arbitrary key was accepted",
                remediation=(
                    "Ensure the server verifies JWT signatures against the "
                    "correct secret or public key. Never skip signature verification."
                ),
                cvss_score=9.1,
                response_status=status,
                response_snippet=body[:200],
            )
        return None
