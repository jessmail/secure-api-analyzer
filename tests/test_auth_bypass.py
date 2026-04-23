"""Unit tests for the authentication bypass test suite.

Uses aiohttp test utilities and mocked HTTP responses to validate
detection logic without making real network requests.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from src.tests.auth_bypass import AuthBypassTester
from src.utils import (
    create_expired_token,
    create_malformed_token,
    create_none_alg_token,
    create_wrong_key_token,
    decode_jwt_unsafe,
)


# ---------------------------------------------------------------------------
# JWT utility tests
# ---------------------------------------------------------------------------

class TestJWTUtils:
    """Test JWT manipulation utilities."""

    def test_create_none_alg_token(self) -> None:
        """Token with alg:none should have no signature segment."""
        payload = {"sub": "user_001", "role": "admin"}
        token = create_none_alg_token(payload)

        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # Empty signature

        header, decoded_payload = decode_jwt_unsafe(token)
        assert header["alg"] == "none"
        assert decoded_payload["sub"] == "user_001"
        assert decoded_payload["role"] == "admin"

    def test_create_expired_token(self) -> None:
        """Expired token should have an exp claim in the past."""
        payload = {"sub": "user_001"}
        token = create_expired_token(payload)

        _, decoded = decode_jwt_unsafe(token)
        assert "exp" in decoded
        assert decoded["exp"] < 1700000000  # Before 2024

    def test_create_malformed_token(self) -> None:
        """Malformed token should have three parts but invalid content."""
        token = create_malformed_token()
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 3

    def test_create_wrong_key_token(self) -> None:
        """Token signed with wrong key should be a valid JWT structure."""
        payload = {"sub": "user_001", "role": "user"}
        token = create_wrong_key_token(payload)

        parts = token.split(".")
        assert len(parts) == 3
        assert all(len(p) > 0 for p in parts)

        _, decoded = decode_jwt_unsafe(token)
        assert decoded["sub"] == "user_001"

    def test_decode_jwt_unsafe_invalid(self) -> None:
        """Decoding garbage should return empty dicts, not crash."""
        header, payload = decode_jwt_unsafe("not-a-jwt")
        assert header == {}
        assert payload == {}

    def test_decode_jwt_unsafe_empty(self) -> None:
        """Decoding empty string should return empty dicts."""
        header, payload = decode_jwt_unsafe("")
        assert header == {}
        assert payload == {}


# ---------------------------------------------------------------------------
# Auth bypass tester with mocked HTTP
# ---------------------------------------------------------------------------

class TestAuthBypassTester:
    """Test AuthBypassTester detection logic with mocked HTTP."""

    @pytest.fixture
    def endpoints(self) -> list[dict[str, str]]:
        return [
            {"path": "/api/v1/users", "method": "GET"},
        ]

    @pytest.mark.asyncio
    async def test_detects_missing_auth_bypass(self, endpoints: list) -> None:
        """Should report CRITICAL when endpoint allows unauthenticated access."""
        tester = AuthBypassTester(base_url="http://localhost:8080")

        with patch("src.tests.auth_bypass.make_request") as mock_req:
            # Simulate server accepting request without auth
            mock_req.return_value = (200, '{"users": []}', {})

            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        critical_findings = [
            f for f in result.findings if f.severity == "CRITICAL"
        ]
        assert len(critical_findings) >= 1
        assert any("missing" in f.title.lower() for f in critical_findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_auth_required(self, endpoints: list) -> None:
        """Should report nothing when endpoint properly rejects unauthorized requests."""
        tester = AuthBypassTester(base_url="http://localhost:8080")

        with patch("src.tests.auth_bypass.make_request") as mock_req:
            # Simulate server rejecting all unauthorized requests
            mock_req.return_value = (401, '{"error": "Unauthorized"}', {})

            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        # Should have no critical/high findings (only possible INFO for test errors)
        serious_findings = [
            f for f in result.findings
            if f.severity in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        assert len(serious_findings) == 0

    @pytest.mark.asyncio
    async def test_detects_alg_none_bypass(self, endpoints: list) -> None:
        """Should detect when server accepts JWT with alg:none."""
        tester = AuthBypassTester(base_url="http://localhost:8080")

        call_count = 0

        async def mock_request_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            headers = kwargs.get("headers", {}) or (args[2] if len(args) > 2 else {})

            auth_header = ""
            if isinstance(headers, dict):
                auth_header = headers.get("Authorization", "")

            # Only accept the alg:none token
            if auth_header and auth_header.endswith("."):
                return (200, '{"data": "secret"}', {})
            return (401, '{"error": "Unauthorized"}', {})

        with patch("src.tests.auth_bypass.make_request", side_effect=mock_request_side_effect):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        alg_none_findings = [
            f for f in result.findings if "none" in f.title.lower()
        ]
        assert len(alg_none_findings) >= 1
        assert alg_none_findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_detects_expired_token_accepted(self, endpoints: list) -> None:
        """Should detect when server accepts expired JWT."""
        tester = AuthBypassTester(base_url="http://localhost:8080")

        async def mock_request_side_effect(*args, **kwargs):
            headers = kwargs.get("headers", {}) or {}
            auth = headers.get("Authorization", "")

            # Accept any Bearer token (simulates server not checking expiry)
            if "Bearer " in auth and len(auth) > 20:
                return (200, '{"data": "ok"}', {})
            return (401, '{"error": "Unauthorized"}', {})

        with patch("src.tests.auth_bypass.make_request", side_effect=mock_request_side_effect):
            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        expired_findings = [
            f for f in result.findings if "expired" in f.title.lower()
        ]
        assert len(expired_findings) >= 1

    @pytest.mark.asyncio
    async def test_result_metadata(self, endpoints: list) -> None:
        """ScanResult should contain correct metadata."""
        tester = AuthBypassTester(base_url="http://localhost:8080", timeout=10)

        with patch("src.tests.auth_bypass.make_request") as mock_req:
            mock_req.return_value = (401, '{"error": "Unauthorized"}', {})

            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        assert result.target == "http://localhost:8080"
        assert result.suite_name == "auth_bypass"
        assert result.endpoints_tested == len(endpoints)
        assert result.duration >= 0

    @pytest.mark.asyncio
    async def test_handles_connection_error(self, endpoints: list) -> None:
        """Should handle connection errors gracefully."""
        tester = AuthBypassTester(base_url="http://localhost:8080")

        with patch("src.tests.auth_bypass.make_request") as mock_req:
            mock_req.return_value = (0, "Connection refused", {})

            async with aiohttp.ClientSession() as session:
                result = await tester.run(session, endpoints)

        # Should not crash, findings may include INFO-level test errors
        assert result.endpoints_tested == len(endpoints)
