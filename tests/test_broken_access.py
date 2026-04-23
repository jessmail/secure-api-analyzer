"""Unit tests for the broken access control test suite.

Tests IDOR detection, vertical escalation probing, and method tampering
detection with mocked HTTP responses.
"""

from __future__ import annotations

from unittest.mock import patch

import aiohttp
import pytest

from src.tests.broken_access import BrokenAccessTester


class TestBrokenAccessTester:
    """Test BrokenAccessTester detection logic."""

    @pytest.fixture
    def endpoints(self) -> list[dict[str, str]]:
        return [
            {"path": "/api/v1/users/user_001/profile", "method": "GET"},
        ]

    @pytest.fixture
    def endpoints_with_id(self) -> list[dict[str, str]]:
        return [
            {"path": "/api/v1/users/123/data", "method": "GET"},
        ]

    @pytest.mark.asyncio
    async def test_detects_idor(self, endpoints: list) -> None:
        """Should detect horizontal privilege escalation (IDOR)."""
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="valid-user-token",
            options={"user_a_id": "user_001", "user_b_id": "user_002"},
        )

        async def mock_request(*args, **kwargs):
            url = args[2] if len(args) > 2 else kwargs.get("url", "")
            # Return success even when accessing another user's data
            if "user_002" in str(url):
                return (200, '{"profile": {"name": "Other User"}}', {})
            return (200, '{"profile": {"name": "My Profile"}}', {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        idor_findings = [
            f for f in result.findings
            if "idor" in f.title.lower() or "horizontal" in f.title.lower()
        ]
        assert len(idor_findings) >= 1
        assert idor_findings[0].severity == "HIGH"
        assert "API1:2023" in idor_findings[0].owasp_category

    @pytest.mark.asyncio
    async def test_detects_idor_numeric_ids(self, endpoints_with_id: list) -> None:
        """Should detect IDOR with numeric ID substitution."""
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="valid-user-token",
            options={"user_a_id": "123", "user_b_id": "456"},
        )

        async def mock_request(*args, **kwargs):
            return (200, '{"data": "sensitive"}', {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints_with_id)

        # Should find IDOR since we can access user 456 data with user 123 token
        idor_findings = [
            f for f in result.findings
            if "idor" in f.title.lower() or "horizontal" in f.title.lower()
        ]
        assert len(idor_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_idor_when_forbidden(self, endpoints: list) -> None:
        """Should not report IDOR when server rejects cross-user access."""
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="valid-user-token",
            options={"user_a_id": "user_001", "user_b_id": "user_002"},
        )

        async def mock_request(*args, **kwargs):
            url = args[2] if len(args) > 2 else kwargs.get("url", "")
            if "user_002" in str(url):
                return (403, '{"error": "Forbidden"}', {})
            return (200, '{"profile": {"name": "My Profile"}}', {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        idor_findings = [
            f for f in result.findings
            if "idor" in f.title.lower() or "horizontal" in f.title.lower()
        ]
        assert len(idor_findings) == 0

    @pytest.mark.asyncio
    async def test_detects_vertical_escalation(self) -> None:
        """Should detect when user token accesses admin endpoints."""
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="regular-user-token",
        )

        async def mock_request(*args, **kwargs):
            url = args[2] if len(args) > 2 else kwargs.get("url", "")
            # Admin panel accessible with user token
            if "admin" in str(url):
                return (200, '{"admin_panel": true}', {})
            return (403, '{"error": "Forbidden"}', {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, [])

        escalation_findings = [
            f for f in result.findings
            if "vertical" in f.title.lower() or "privilege" in f.title.lower()
        ]
        assert len(escalation_findings) >= 1
        assert "API5:2023" in escalation_findings[0].owasp_category

    @pytest.mark.asyncio
    async def test_detects_method_tampering(self) -> None:
        """Should detect when dangerous HTTP methods are accepted."""
        endpoints = [{"path": "/api/v1/users/1", "method": "GET"}]
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="regular-user-token",
        )

        async def mock_request(*args, **kwargs):
            method = args[1] if len(args) > 1 else kwargs.get("method", "GET")
            # Accept DELETE even though it should be restricted
            if method.upper() == "DELETE":
                return (200, '{"deleted": true}', {})
            if method.upper() == "OPTIONS":
                return (200, "", {"Allow": "GET, POST"})
            return (200, '{"data": "ok"}', {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        tamper_findings = [
            f for f in result.findings
            if "method" in f.title.lower() and "tamper" in f.title.lower()
        ]
        assert len(tamper_findings) >= 1
        # DELETE should be flagged
        assert any("DELETE" in f.title for f in tamper_findings)

    @pytest.mark.asyncio
    async def test_path_traversal_detection(self) -> None:
        """Should detect path traversal attempts that succeed."""
        endpoints = [{"path": "/api/v1/files/document.txt", "method": "GET"}]
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
            user_token="regular-user-token",
        )

        async def mock_request(*args, **kwargs):
            url = args[2] if len(args) > 2 else kwargs.get("url", "")
            if "../" in str(url) or "%2e" in str(url).lower():
                return (200, "root:x:0:0:root:/root:/bin/bash\n", {})
            return (200, "normal file content", {})

        with patch("src.tests.broken_access.make_request", side_effect=mock_request):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        traversal_findings = [
            f for f in result.findings if "traversal" in f.title.lower()
        ]
        assert len(traversal_findings) >= 1
        assert traversal_findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_result_counts(self) -> None:
        """ScanResult should track endpoint counts correctly."""
        endpoints = [
            {"path": "/api/v1/users/1", "method": "GET"},
            {"path": "/api/v1/orders/1", "method": "GET"},
        ]
        tester = BrokenAccessTester(
            base_url="http://localhost:8080",
        )

        with patch("src.tests.broken_access.make_request") as mock_req:
            mock_req.return_value = (403, '{"error": "Forbidden"}', {})

            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        assert result.endpoints_tested == len(endpoints)
        assert result.suite_name == "broken_access"
