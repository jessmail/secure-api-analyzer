"""Rate limiting test suite.

Tests for OWASP API4:2023 - Unrestricted Resource Consumption
including brute force detection, rate limit verification, and account lockout.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

import aiohttp

from src.utils import (
    Finding,
    ScanResult,
    build_url,
    make_request,
)


class RateLimitTester:
    """Tests for rate limiting and brute force protection."""

    OWASP_CATEGORY = "API4:2023 - Unrestricted Resource Consumption"

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.options = options or {}
        self.burst_count = self.options.get("burst_count", 50)
        self.burst_window = self.options.get("burst_window", 5.0)
        self.lockout_attempts = self.options.get("lockout_attempts", 10)

    async def run(
        self,
        session: aiohttp.ClientSession,
        endpoints: list[dict[str, str]],
    ) -> ScanResult:
        """Execute all rate limiting tests.

        Args:
            session: aiohttp client session.
            endpoints: List of endpoint dicts with 'path' and 'method' keys.

        Returns:
            ScanResult with all findings.
        """
        result = ScanResult(target=self.base_url, suite_name="rate_limiting")
        result.start_time = time.time()

        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            is_login = self._is_login_endpoint(path, method)

            # General rate limit test
            rate_findings = await self._test_rate_limit(session, path, method)
            result.findings.extend(rate_findings)
            result.endpoints_tested += 1

            # Login-specific tests
            if is_login:
                brute_findings = await self._test_brute_force(session, path)
                result.findings.extend(brute_findings)

                lockout_findings = await self._test_account_lockout(session, path)
                result.findings.extend(lockout_findings)

        result.end_time = time.time()
        return result

    def _is_login_endpoint(self, path: str, method: str) -> bool:
        """Determine if an endpoint is likely a login/auth endpoint."""
        login_keywords = ["login", "auth", "signin", "sign-in", "token", "session"]
        path_lower = path.lower()
        return method.upper() == "POST" and any(
            kw in path_lower for kw in login_keywords
        )

    async def _test_rate_limit(
        self,
        session: aiohttp.ClientSession,
        path: str,
        method: str,
    ) -> list[Finding]:
        """Test if the endpoint enforces rate limiting.

        Sends a burst of requests in a short window and checks whether
        the server starts returning 429 Too Many Requests.
        """
        findings: list[Finding] = []
        url = build_url(self.base_url, path)
        headers = {"Content-Type": "application/json"}

        statuses: list[int] = []
        start = time.time()

        # Send burst of requests
        tasks = []
        for _ in range(self.burst_count):
            tasks.append(
                make_request(session, method, url, headers=headers, timeout=self.timeout)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start

        for res in results:
            if isinstance(res, tuple):
                statuses.append(res[0])
            # Exceptions are counted as failed requests (not rate-limited)

        rate_limited = sum(1 for s in statuses if s == 429)
        successful = sum(1 for s in statuses if s in (200, 201, 204))
        total_sent = len(statuses)

        if rate_limited == 0 and successful > 0:
            findings.append(
                Finding(
                    title="No rate limiting detected",
                    severity="MEDIUM",
                    owasp_category=self.OWASP_CATEGORY,
                    description=(
                        f"Sent {total_sent} requests to {method} {path} in "
                        f"{elapsed:.1f}s without receiving a 429 response. "
                        f"{successful} requests returned success status."
                    ),
                    endpoint=url,
                    method=method,
                    evidence=(
                        f"{total_sent} requests in {elapsed:.1f}s, "
                        f"0 rate-limited, {successful} successful"
                    ),
                    remediation=(
                        "Implement rate limiting using token bucket or sliding "
                        "window algorithms. Return 429 Too Many Requests with "
                        "Retry-After header when limits are exceeded."
                    ),
                    cvss_score=5.3,
                    response_status=200,
                )
            )

        # Check for missing rate limit headers
        if total_sent > 0:
            last_result = None
            for res in reversed(results):
                if isinstance(res, tuple):
                    last_result = res
                    break

            if last_result:
                _, _, resp_headers = last_result
                rate_headers = [
                    "X-RateLimit-Limit",
                    "X-RateLimit-Remaining",
                    "X-Rate-Limit-Limit",
                    "RateLimit-Limit",
                    "Retry-After",
                ]
                has_rate_header = any(
                    h.lower() in {k.lower() for k in resp_headers}
                    for h in rate_headers
                )

                if not has_rate_header and rate_limited == 0:
                    findings.append(
                        Finding(
                            title="Missing rate limit response headers",
                            severity="LOW",
                            owasp_category=self.OWASP_CATEGORY,
                            description=(
                                f"Endpoint {method} {path} does not return "
                                f"rate limit headers (X-RateLimit-Limit, etc.). "
                                f"Clients cannot implement proper backoff."
                            ),
                            endpoint=url,
                            method=method,
                            evidence="No X-RateLimit-* or Retry-After headers found",
                            remediation=(
                                "Include rate limit headers in API responses: "
                                "X-RateLimit-Limit, X-RateLimit-Remaining, "
                                "X-RateLimit-Reset."
                            ),
                            cvss_score=2.0,
                        )
                    )

        return findings

    async def _test_brute_force(
        self,
        session: aiohttp.ClientSession,
        path: str,
    ) -> list[Finding]:
        """Test brute force protection on login endpoints.

        Sends multiple login attempts with invalid credentials to check
        if the server detects and blocks brute force attacks.
        """
        findings: list[Finding] = []
        url = build_url(self.base_url, path)
        headers = {"Content-Type": "application/json"}

        credentials = [
            {"username": "admin", "password": f"wrong_pass_{i}"}
            for i in range(self.lockout_attempts)
        ]

        statuses: list[int] = []
        for cred in credentials:
            status, body, resp_headers = await make_request(
                session, "POST", url, headers=headers, json_body=cred,
                timeout=self.timeout,
            )
            statuses.append(status)

            # If we get rate-limited or locked out, brute force protection works
            if status == 429 or status == 423:
                return findings  # Protection detected, no finding

            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.1)

        # Check if all attempts were allowed
        failed_logins = sum(1 for s in statuses if s in (401, 403))
        blocked = sum(1 for s in statuses if s in (429, 423))

        if blocked == 0 and failed_logins == len(statuses):
            findings.append(
                Finding(
                    title="No brute force protection on login endpoint",
                    severity="HIGH",
                    owasp_category=self.OWASP_CATEGORY,
                    description=(
                        f"Login endpoint POST {path} accepted {len(statuses)} "
                        f"consecutive failed login attempts without blocking "
                        f"or rate limiting the attacker."
                    ),
                    endpoint=url,
                    method="POST",
                    evidence=(
                        f"{len(statuses)} failed logins without block/rate-limit"
                    ),
                    remediation=(
                        "Implement progressive delays or account lockout after "
                        "a threshold of failed login attempts. Consider CAPTCHA "
                        "after 3-5 failures."
                    ),
                    cvss_score=7.5,
                )
            )

        return findings

    async def _test_account_lockout(
        self,
        session: aiohttp.ClientSession,
        path: str,
    ) -> list[Finding]:
        """Test account lockout mechanism.

        Verifies that the account lockout policy exists and is properly
        configured (not too aggressive and not too lenient).
        """
        findings: list[Finding] = []
        url = build_url(self.base_url, path)
        headers = {"Content-Type": "application/json"}

        # Send many failed attempts for a specific user
        test_user = "lockout_test_user"
        attempts = self.lockout_attempts * 2  # Double the threshold

        locked_at: Optional[int] = None
        for i in range(attempts):
            cred = {"username": test_user, "password": f"bad_pass_{i}"}
            status, body, _ = await make_request(
                session, "POST", url, headers=headers, json_body=cred,
                timeout=self.timeout,
            )

            if status in (423, 429):
                locked_at = i + 1
                break

            await asyncio.sleep(0.05)

        if locked_at is None:
            findings.append(
                Finding(
                    title="No account lockout after excessive failed attempts",
                    severity="MEDIUM",
                    owasp_category=self.OWASP_CATEGORY,
                    description=(
                        f"Account '{test_user}' was not locked after {attempts} "
                        f"failed login attempts at POST {path}."
                    ),
                    endpoint=url,
                    method="POST",
                    evidence=f"{attempts} failed attempts without lockout",
                    remediation=(
                        "Implement account lockout or progressive delay after "
                        "5-10 consecutive failed login attempts. Provide a "
                        "time-based unlock mechanism (e.g., 15-minute lockout)."
                    ),
                    cvss_score=5.3,
                )
            )

        return findings
