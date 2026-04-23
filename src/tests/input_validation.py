"""Input validation test suite.

Tests for OWASP API3:2023 injection vulnerabilities including SQL injection,
XSS, command injection, and NoSQL injection.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

import aiohttp

from src.config import load_payloads
from src.utils import (
    Finding,
    ScanResult,
    build_url,
    make_request,
)


class InputValidationTester:
    """Tests for input validation and injection vulnerabilities."""

    OWASP_CATEGORY = "API3:2023 - Broken Object Property Level Authorization"
    OWASP_INJECTION = "API8:2023 - Security Misconfiguration"

    # Default SQL injection payloads if no payload file is loaded
    DEFAULT_SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1",
        "1 OR 1=1",
        "' OR ''='",
        "admin'--",
        "1; WAITFOR DELAY '0:0:5'--",
    ]

    DEFAULT_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "<svg/onload=alert(1)>",
        "{{7*7}}",
        "${7*7}",
    ]

    DEFAULT_CMDI_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "& dir",
        "| ping -c 3 127.0.0.1",
        "; sleep 5",
        "$(sleep 5)",
    ]

    DEFAULT_NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        "true, $where: '1 == 1'",
        '{"$nin": []}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    ]

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: int = 30,
        payloads_path: Optional[str] = None,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        self.base_url = base_url
        self.token = token
        self.timeout = timeout
        self.options = options or {}

        # Load custom payloads or use defaults
        if payloads_path:
            custom = load_payloads(payloads_path)
            self.sqli_payloads = custom.get("sqli", self.DEFAULT_SQLI_PAYLOADS)
            self.xss_payloads = custom.get("xss", self.DEFAULT_XSS_PAYLOADS)
            self.cmdi_payloads = custom.get("cmdi", self.DEFAULT_CMDI_PAYLOADS)
            self.nosql_payloads = custom.get("nosql", self.DEFAULT_NOSQL_PAYLOADS)
        else:
            self.sqli_payloads = self.DEFAULT_SQLI_PAYLOADS
            self.xss_payloads = self.DEFAULT_XSS_PAYLOADS
            self.cmdi_payloads = self.DEFAULT_CMDI_PAYLOADS
            self.nosql_payloads = self.DEFAULT_NOSQL_PAYLOADS

    async def run(
        self,
        session: aiohttp.ClientSession,
        endpoints: list[dict[str, str]],
    ) -> ScanResult:
        """Execute all input validation tests.

        Args:
            session: aiohttp client session.
            endpoints: List of endpoint dicts with 'path', 'method', and
                       optional 'params' keys.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=self.base_url, suite_name="input_validation")
        result.start_time = time.time()

        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", ["q", "search", "id", "name"])

            if isinstance(params, str):
                params = [params]

            sqli_findings = await self._test_sql_injection(
                session, path, method, params
            )
            result.findings.extend(sqli_findings)

            xss_findings = await self._test_xss(session, path, method, params)
            result.findings.extend(xss_findings)

            cmdi_findings = await self._test_command_injection(
                session, path, method, params
            )
            result.findings.extend(cmdi_findings)

            nosql_findings = await self._test_nosql_injection(
                session, path, method, params
            )
            result.findings.extend(nosql_findings)

            result.endpoints_tested += 1

        result.end_time = time.time()
        return result

    def _build_headers(self) -> dict[str, str]:
        """Build request headers with optional auth token."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _test_sql_injection(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
        params: list[str],
    ) -> list[Finding]:
        """Test for SQL injection in query parameters and request body.

        Sends known SQL injection payloads and analyzes responses for
        indicators of successful injection (error messages, data leaks,
        timing anomalies).
        """
        findings: list[Finding] = []
        headers = self._build_headers()

        # SQL error patterns that indicate injection
        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysqli?_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"sqlite3\.OperationalError",
            r"pg_query\(\).*failed",
            r"System\.Data\.SqlClient",
        ]

        for param in params:
            for payload in self.sqli_payloads:
                if method.upper() == "GET":
                    url = build_url(self.base_url, f"{path}?{param}={payload}")
                    status, body, _ = await make_request(
                        session, "GET", url, headers=headers, timeout=self.timeout
                    )
                else:
                    url = build_url(self.base_url, path)
                    json_body = {param: payload}
                    status, body, _ = await make_request(
                        session, method, url, headers=headers,
                        json_body=json_body, timeout=self.timeout,
                    )

                # Check for SQL error patterns in response
                for pattern in sql_error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(
                            Finding(
                                title=f"SQL injection in parameter '{param}'",
                                severity="CRITICAL",
                                owasp_category=self.OWASP_INJECTION,
                                description=(
                                    f"SQL injection payload in '{param}' parameter "
                                    f"caused a database error at {method} {path}. "
                                    f"Payload: {payload}"
                                ),
                                endpoint=url,
                                method=method,
                                evidence=f"SQL error pattern matched: {pattern}",
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL queries. "
                                    "Implement input validation and output encoding."
                                ),
                                cvss_score=9.8,
                                response_status=status,
                                response_snippet=body[:300],
                            )
                        )
                        return findings  # One SQLi finding per endpoint

                # Check for data leak (response significantly larger than expected)
                if status == 200 and len(body) > 5000 and "' OR " in payload:
                    findings.append(
                        Finding(
                            title=f"Possible SQL injection data leak via '{param}'",
                            severity="HIGH",
                            owasp_category=self.OWASP_INJECTION,
                            description=(
                                f"Boolean-based SQL injection payload in '{param}' "
                                f"returned a large response ({len(body)} bytes) at "
                                f"{method} {path}. Payload: {payload}"
                            ),
                            endpoint=url,
                            method=method,
                            evidence=f"Large response ({len(body)} bytes) with OR payload",
                            remediation=(
                                "Use parameterized queries. Validate and sanitize "
                                "all user input. Implement proper error handling "
                                "that does not leak data."
                            ),
                            cvss_score=8.6,
                            response_status=status,
                            response_snippet=body[:300],
                        )
                    )
                    return findings

        return findings

    async def _test_xss(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
        params: list[str],
    ) -> list[Finding]:
        """Test for Cross-Site Scripting (XSS) in API responses.

        Sends XSS payloads and checks if they are reflected unencoded
        in the response body.
        """
        findings: list[Finding] = []
        headers = self._build_headers()

        for param in params:
            for payload in self.xss_payloads:
                if method.upper() == "GET":
                    url = build_url(self.base_url, f"{path}?{param}={payload}")
                    status, body, resp_headers = await make_request(
                        session, "GET", url, headers=headers, timeout=self.timeout
                    )
                else:
                    url = build_url(self.base_url, path)
                    json_body = {param: payload}
                    status, body, resp_headers = await make_request(
                        session, method, url, headers=headers,
                        json_body=json_body, timeout=self.timeout,
                    )

                # Check if payload is reflected unencoded
                if payload in body:
                    # Check content type - XSS is most relevant for HTML responses
                    content_type = resp_headers.get("Content-Type", "").lower()
                    severity = "HIGH" if "html" in content_type else "MEDIUM"

                    findings.append(
                        Finding(
                            title=f"Reflected XSS in parameter '{param}'",
                            severity=severity,
                            owasp_category=self.OWASP_INJECTION,
                            description=(
                                f"XSS payload in '{param}' is reflected unencoded "
                                f"in the response from {method} {path}. "
                                f"Content-Type: {content_type or 'not set'}"
                            ),
                            endpoint=url,
                            method=method,
                            evidence=f"Payload reflected: {payload[:80]}",
                            remediation=(
                                "Encode all output. Set Content-Type to "
                                "application/json for API responses. Implement "
                                "Content-Security-Policy headers."
                            ),
                            cvss_score=6.1 if severity == "MEDIUM" else 7.5,
                            response_status=status,
                            response_snippet=body[:300],
                        )
                    )
                    return findings  # One XSS finding per endpoint

        return findings

    async def _test_command_injection(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
        params: list[str],
    ) -> list[Finding]:
        """Test for OS command injection.

        Sends command injection payloads and looks for indicators of
        command execution in the response.
        """
        findings: list[Finding] = []
        headers = self._build_headers()

        # Patterns indicating command execution
        cmd_output_patterns = [
            r"uid=\d+\(.*?\)\s+gid=",       # id command output
            r"root:.*:0:0:",                   # /etc/passwd content
            r"total \d+\s+drw",                # ls -la output
            r"Directory of",                   # Windows dir output
            r"Volume Serial Number",
            r"PING.*bytes of data",
        ]

        for param in params:
            for payload in self.cmdi_payloads:
                if method.upper() == "GET":
                    url = build_url(self.base_url, f"{path}?{param}={payload}")
                    status, body, _ = await make_request(
                        session, "GET", url, headers=headers, timeout=self.timeout
                    )
                else:
                    url = build_url(self.base_url, path)
                    json_body = {param: payload}
                    status, body, _ = await make_request(
                        session, method, url, headers=headers,
                        json_body=json_body, timeout=self.timeout,
                    )

                for pattern in cmd_output_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(
                            Finding(
                                title=f"Command injection in parameter '{param}'",
                                severity="CRITICAL",
                                owasp_category=self.OWASP_INJECTION,
                                description=(
                                    f"OS command injection payload in '{param}' "
                                    f"caused command execution at {method} {path}. "
                                    f"Payload: {payload}"
                                ),
                                endpoint=url,
                                method=method,
                                evidence=f"Command output pattern matched: {pattern}",
                                remediation=(
                                    "Never pass user input to OS commands. Use "
                                    "language-specific APIs instead of shell commands. "
                                    "If unavoidable, use strict allowlists for input."
                                ),
                                cvss_score=9.8,
                                response_status=status,
                                response_snippet=body[:300],
                            )
                        )
                        return findings

        return findings

    async def _test_nosql_injection(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
        params: list[str],
    ) -> list[Finding]:
        """Test for NoSQL injection (MongoDB, CouchDB, etc.).

        Sends NoSQL operator payloads to check if the server processes
        them as database operators instead of literal values.
        """
        findings: list[Finding] = []
        headers = self._build_headers()

        for param in params:
            for payload in self.nosql_payloads:
                url = build_url(self.base_url, path)

                # Try to inject NoSQL operators in JSON body
                try:
                    parsed_payload = json.loads(payload)
                except json.JSONDecodeError:
                    parsed_payload = payload

                json_body = {param: parsed_payload}
                status, body, _ = await make_request(
                    session, "POST", url, headers=headers,
                    json_body=json_body, timeout=self.timeout,
                )

                # Indicators of NoSQL injection
                nosql_indicators = [
                    status == 200 and len(body) > 1000,  # Data dump
                    "MongoError" in body,
                    "CastError" in body,
                    "ValidationError" in body and "mongo" in body.lower(),
                ]

                if any(nosql_indicators):
                    findings.append(
                        Finding(
                            title=f"Possible NoSQL injection in parameter '{param}'",
                            severity="HIGH",
                            owasp_category=self.OWASP_INJECTION,
                            description=(
                                f"NoSQL operator payload in '{param}' was processed "
                                f"at {method} {path}. The server may be interpreting "
                                f"query operators from user input."
                            ),
                            endpoint=url,
                            method="POST",
                            evidence=f"NoSQL payload returned {status}, body size {len(body)}",
                            remediation=(
                                "Sanitize all user input before using in database "
                                "queries. Reject objects and operators in user input. "
                                "Use an ORM or query builder that escapes operators."
                            ),
                            cvss_score=8.6,
                            response_status=status,
                            response_snippet=body[:300],
                        )
                    )
                    return findings

        return findings
