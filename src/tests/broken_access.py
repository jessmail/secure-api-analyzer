"""Broken access control test suite.

Tests for OWASP API1:2023 - Broken Object Level Authorization and
API5:2023 - Broken Function Level Authorization vulnerabilities,
including IDOR, privilege escalation, and method tampering.
"""

from __future__ import annotations

import re
import time
from typing import Any, Optional

import aiohttp

from src.utils import (
    Finding,
    ScanResult,
    build_url,
    make_request,
)


class BrokenAccessTester:
    """Tests for authorization and access control vulnerabilities."""

    OWASP_BOLA = "API1:2023 - Broken Object Level Authorization"
    OWASP_BFLA = "API5:2023 - Broken Function Level Authorization"

    # Common admin-only endpoints to probe
    ADMIN_PATHS = [
        "/admin",
        "/api/admin",
        "/api/v1/admin",
        "/api/v1/admin/users",
        "/api/v1/admin/settings",
        "/api/v1/admin/config",
        "/api/v1/users",
        "/api/internal",
        "/management",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
    ]

    # HTTP methods to test for method tampering
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    def __init__(
        self,
        base_url: str,
        user_token: Optional[str] = None,
        admin_token: Optional[str] = None,
        timeout: int = 30,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        self.base_url = base_url
        self.user_token = user_token
        self.admin_token = admin_token
        self.timeout = timeout
        self.options = options or {}
        self.user_a_id = self.options.get("user_a_id", "user_001")
        self.user_b_id = self.options.get("user_b_id", "user_002")

    async def run(
        self,
        session: aiohttp.ClientSession,
        endpoints: list[dict[str, str]],
    ) -> ScanResult:
        """Execute all broken access control tests.

        Args:
            session: aiohttp client session.
            endpoints: List of endpoint dicts with 'path' and 'method' keys.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=self.base_url, suite_name="broken_access")
        result.start_time = time.time()

        # Test each provided endpoint
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")

            # IDOR / horizontal escalation tests
            idor_findings = await self._test_idor(session, path, method)
            result.findings.extend(idor_findings)

            # Method tampering
            tampering_findings = await self._test_method_tampering(session, path)
            result.findings.extend(tampering_findings)

            # Parameter pollution
            pollution_findings = await self._test_parameter_pollution(
                session, path, method
            )
            result.findings.extend(pollution_findings)

            result.endpoints_tested += 1

        # Vertical escalation: probe admin endpoints with user token
        escalation_findings = await self._test_vertical_escalation(session)
        result.findings.extend(escalation_findings)

        # Path traversal in API routes
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            traversal_findings = await self._test_path_traversal(session, path)
            result.findings.extend(traversal_findings)

        result.end_time = time.time()
        return result

    async def _test_idor(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
    ) -> list[Finding]:
        """Test for Insecure Direct Object Reference (IDOR).

        Attempts to access resources belonging to user B using user A's
        credentials by replacing identifiers in the URL path.
        """
        findings: list[Finding] = []

        # Look for ID patterns in the path: /users/123, /users/{id}, etc.
        id_pattern = re.compile(r"(/\w+/)(\{?\w*id\w*\}?|\d+)", re.IGNORECASE)
        match = id_pattern.search(path)

        if not match and self.user_a_id not in path:
            return findings

        # Build the altered path with a different user ID
        if match:
            altered_path = path[: match.start(2)] + self.user_b_id + path[match.end(2):]
        else:
            altered_path = path.replace(self.user_a_id, self.user_b_id)

        url = build_url(self.base_url, altered_path)
        headers = {"Content-Type": "application/json"}
        if self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"

        status, body, _ = await make_request(
            session, method, url, headers=headers, timeout=self.timeout
        )

        if status in (200, 201, 204):
            findings.append(
                Finding(
                    title="Horizontal privilege escalation (IDOR)",
                    severity="HIGH",
                    owasp_category=self.OWASP_BOLA,
                    description=(
                        f"User A ({self.user_a_id}) can access resources belonging "
                        f"to User B ({self.user_b_id}) via {method} {altered_path}. "
                        f"Server returned {status}."
                    ),
                    endpoint=url,
                    method=method,
                    evidence=(
                        f"Accessed {altered_path} with user A token, got {status}"
                    ),
                    remediation=(
                        "Implement object-level authorization checks. Verify that "
                        "the authenticated user has permission to access the specific "
                        "resource identified in the request."
                    ),
                    cvss_score=8.6,
                    response_status=status,
                    response_snippet=body[:200],
                )
            )

        return findings

    async def _test_vertical_escalation(
        self,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        """Test for vertical privilege escalation.

        Attempts to access admin-only endpoints using a regular user token.
        """
        findings: list[Finding] = []

        if not self.user_token:
            return findings

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.user_token}",
        }

        for admin_path in self.ADMIN_PATHS:
            url = build_url(self.base_url, admin_path)
            status, body, _ = await make_request(
                session, "GET", url, headers=headers, timeout=self.timeout
            )

            if status in (200, 201, 204):
                findings.append(
                    Finding(
                        title="Vertical privilege escalation",
                        severity="HIGH",
                        owasp_category=self.OWASP_BFLA,
                        description=(
                            f"Regular user token was accepted at admin endpoint "
                            f"GET {admin_path} with status {status}."
                        ),
                        endpoint=url,
                        method="GET",
                        evidence=f"User token accepted at {admin_path} ({status})",
                        remediation=(
                            "Implement role-based access control (RBAC). Admin "
                            "endpoints must verify the user has an admin role before "
                            "processing the request."
                        ),
                        cvss_score=8.2,
                        response_status=status,
                        response_snippet=body[:200],
                    )
                )

        return findings

    async def _test_method_tampering(
        self,
        session: aiohttp.ClientSession,
        path: str,
    ) -> list[Finding]:
        """Test for HTTP method tampering.

        Tries different HTTP methods on an endpoint to discover unintended
        method handling (e.g., DELETE working where only GET is expected).
        """
        findings: list[Finding] = []
        url = build_url(self.base_url, path)
        headers = {"Content-Type": "application/json"}
        if self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"

        # First, find which methods are explicitly allowed
        _, _, options_headers = await make_request(
            session, "OPTIONS", url, headers=headers, timeout=self.timeout
        )
        allowed = options_headers.get("Allow", "").upper()

        # Test dangerous methods that might not be intended
        dangerous_methods = ["DELETE", "PUT", "PATCH"]
        for method in dangerous_methods:
            if allowed and method in allowed:
                continue  # Skip if explicitly allowed via OPTIONS

            status, body, _ = await make_request(
                session, method, url, headers=headers, timeout=self.timeout
            )

            # If a destructive method returns success without being in Allow header
            if status in (200, 201, 204):
                findings.append(
                    Finding(
                        title=f"HTTP method tampering: {method} accepted",
                        severity="HIGH",
                        owasp_category=self.OWASP_BFLA,
                        description=(
                            f"Endpoint {path} accepted {method} request with "
                            f"status {status}. Destructive HTTP methods should "
                            f"be restricted to authorized operations only."
                        ),
                        endpoint=url,
                        method=method,
                        evidence=f"{method} {path} returned {status}",
                        remediation=(
                            "Explicitly define allowed HTTP methods for each "
                            "endpoint. Return 405 Method Not Allowed for methods "
                            "that are not supported."
                        ),
                        cvss_score=7.5,
                        response_status=status,
                        response_snippet=body[:200],
                    )
                )

        return findings

    async def _test_parameter_pollution(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
    ) -> list[Finding]:
        """Test for HTTP parameter pollution.

        Sends duplicate parameters to test if the server processes them
        inconsistently, potentially bypassing access controls.
        """
        findings: list[Finding] = []
        base_url = build_url(self.base_url, path)
        headers = {"Content-Type": "application/json"}
        if self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"

        # Duplicate parameter test via query string
        pollution_urls = [
            f"{base_url}?role=user&role=admin",
            f"{base_url}?admin=true&admin=false",
            f"{base_url}?id={self.user_a_id}&id={self.user_b_id}",
        ]

        for poll_url in pollution_urls:
            status, body, _ = await make_request(
                session, method, poll_url, headers=headers, timeout=self.timeout
            )

            # Check if parameter pollution leads to privilege escalation
            if status in (200, 201, 204) and (
                "admin" in body.lower() or self.user_b_id in body
            ):
                findings.append(
                    Finding(
                        title="Parameter pollution may bypass access control",
                        severity="MEDIUM",
                        owasp_category=self.OWASP_BOLA,
                        description=(
                            f"Duplicate parameters in {method} {poll_url} returned "
                            f"data suggesting access control bypass. The server may "
                            f"process duplicate parameters inconsistently."
                        ),
                        endpoint=poll_url,
                        method=method,
                        evidence=f"Duplicate params accepted, status {status}",
                        remediation=(
                            "Ensure the server handles duplicate parameters "
                            "consistently. Use the first occurrence or reject "
                            "requests with duplicate parameters."
                        ),
                        cvss_score=5.3,
                        response_status=status,
                        response_snippet=body[:200],
                    )
                )
                break  # One finding is enough

        return findings

    async def _test_path_traversal(
        self,
        session: aiohttp.ClientSession,
        path: str,
    ) -> list[Finding]:
        """Test for path traversal in API routes.

        Attempts directory traversal sequences in API path segments to
        access resources outside the intended scope.
        """
        findings: list[Finding] = []
        headers = {"Content-Type": "application/json"}
        if self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"

        traversal_payloads = [
            "../",
            "../../",
            "../../../etc/passwd",
            "..%2f",
            "..%252f",
            "%2e%2e/",
            "..\\",
        ]

        for payload in traversal_payloads:
            # Inject traversal in the last path segment
            segments = path.rstrip("/").split("/")
            if len(segments) > 1:
                traversal_path = "/".join(segments[:-1]) + "/" + payload
            else:
                traversal_path = path + "/" + payload

            url = build_url(self.base_url, traversal_path)
            status, body, _ = await make_request(
                session, "GET", url, headers=headers, timeout=self.timeout
            )

            # Detect signs of successful traversal
            traversal_indicators = [
                "root:",
                "/etc/",
                "C:\\",
                "win.ini",
                "boot.ini",
            ]
            if status == 200 and any(ind in body for ind in traversal_indicators):
                findings.append(
                    Finding(
                        title="Path traversal in API route",
                        severity="CRITICAL",
                        owasp_category=self.OWASP_BOLA,
                        description=(
                            f"Path traversal payload '{payload}' in {path} returned "
                            f"content suggesting file system access."
                        ),
                        endpoint=url,
                        method="GET",
                        evidence=f"Traversal payload returned system content",
                        remediation=(
                            "Sanitize and validate all path parameters. Use "
                            "allowlists for valid path segments. Never construct "
                            "file paths directly from user input."
                        ),
                        cvss_score=9.1,
                        response_status=status,
                        response_snippet=body[:200],
                    )
                )
                break  # One finding per endpoint is sufficient

        return findings
