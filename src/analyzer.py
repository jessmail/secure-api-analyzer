"""Core analyzer engine for orchestrating security test suites.

Handles OpenAPI/Swagger spec parsing, endpoint discovery, and test suite
execution with async HTTP requests.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Optional

import aiohttp
import yaml

from src.config import Config
from src.tests.auth_bypass import AuthBypassTester
from src.tests.broken_access import BrokenAccessTester
from src.tests.input_validation import InputValidationTester
from src.tests.rate_limiting import RateLimitTester
from src.utils import Finding, ScanResult, normalize_url


class Analyzer:
    """Main security analyzer that orchestrates all test suites.

    Usage:
        config = Config.from_yaml("configs/default.yaml")
        analyzer = Analyzer(config)
        results = await analyzer.run()
    """

    AVAILABLE_SUITES = [
        "auth_bypass",
        "broken_access",
        "rate_limiting",
        "input_validation",
    ]

    def __init__(self, config: Config) -> None:
        self.config = config
        self.target = normalize_url(config.target) if config.target else ""
        self.endpoints: list[dict[str, Any]] = []
        self.results: list[ScanResult] = []

    async def run(
        self,
        suites: Optional[list[str]] = None,
    ) -> list[ScanResult]:
        """Execute the security analysis.

        Args:
            suites: Optional list of suite names to run. If None, runs all
                    enabled suites from config.

        Returns:
            List of ScanResult objects, one per executed suite.
        """
        if not self.target:
            raise ValueError("No target URL configured")

        # Discover endpoints
        if self.config.spec_path:
            self.endpoints = self._parse_openapi_spec(self.config.spec_path)
        if not self.endpoints:
            self.endpoints = self._default_endpoints()

        # Determine which suites to run
        active_suites = suites or self._get_enabled_suites()

        # Create aiohttp session with configured settings
        connector = aiohttp.TCPConnector(
            limit=self.config.scan.max_concurrent,
            ssl=self.config.scan.verify_ssl,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.scan.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": self.config.scan.user_agent},
        ) as session:
            for suite_name in active_suites:
                if suite_name not in self.AVAILABLE_SUITES:
                    continue

                result = await self._run_suite(session, suite_name)
                self.results.append(result)

        return self.results

    async def _run_suite(
        self,
        session: aiohttp.ClientSession,
        suite_name: str,
    ) -> ScanResult:
        """Execute a single test suite.

        Args:
            session: aiohttp client session.
            suite_name: Name of the suite to execute.

        Returns:
            ScanResult from the executed suite.
        """
        suite_config = self.config.get_suite_config(suite_name)
        user_token = self._get_user_token()
        admin_token = self._get_admin_token()

        if suite_name == "auth_bypass":
            tester = AuthBypassTester(
                base_url=self.target,
                valid_token=user_token,
                timeout=self.config.scan.timeout,
                options=suite_config.options,
            )
            return await tester.run(session, self.endpoints)

        elif suite_name == "broken_access":
            tester = BrokenAccessTester(
                base_url=self.target,
                user_token=user_token,
                admin_token=admin_token,
                timeout=self.config.scan.timeout,
                options=suite_config.options,
            )
            return await tester.run(session, self.endpoints)

        elif suite_name == "rate_limiting":
            tester = RateLimitTester(
                base_url=self.target,
                timeout=self.config.scan.timeout,
                options=suite_config.options,
            )
            return await tester.run(session, self.endpoints)

        elif suite_name == "input_validation":
            tester = InputValidationTester(
                base_url=self.target,
                token=user_token,
                timeout=self.config.scan.timeout,
                payloads_path=self.config.payloads_path,
                options=suite_config.options,
            )
            return await tester.run(session, self.endpoints)

        else:
            return ScanResult(target=self.target, suite_name=suite_name)

    def _get_enabled_suites(self) -> list[str]:
        """Get list of enabled suite names from config."""
        if not self.config.suites:
            return self.AVAILABLE_SUITES

        return [
            name for name, suite in self.config.suites.items()
            if suite.enabled and name in self.AVAILABLE_SUITES
        ]

    def _get_user_token(self) -> Optional[str]:
        """Extract regular user token from config."""
        for user in self.config.users:
            if user.role in ("user", "regular"):
                return user.token
        if self.config.users:
            return self.config.users[0].token
        return None

    def _get_admin_token(self) -> Optional[str]:
        """Extract admin token from config."""
        for user in self.config.users:
            if user.role == "admin":
                return user.token
        return None

    def _parse_openapi_spec(self, spec_path: str) -> list[dict[str, Any]]:
        """Parse an OpenAPI/Swagger specification to extract endpoints.

        Supports both JSON and YAML spec formats, and OpenAPI 2.0 (Swagger)
        and 3.0+ specifications.

        Args:
            spec_path: Path to the OpenAPI spec file.

        Returns:
            List of endpoint dicts with 'path', 'method', and 'params' keys.
        """
        path = Path(spec_path)
        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()

        try:
            if path.suffix in (".yaml", ".yml"):
                spec = yaml.safe_load(content)
            else:
                spec = json.loads(content)
        except (yaml.YAMLError, json.JSONDecodeError):
            return []

        if not isinstance(spec, dict):
            return []

        endpoints: list[dict[str, Any]] = []
        paths = spec.get("paths", {})

        for api_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, details in methods.items():
                method_upper = method.upper()
                if method_upper not in (
                    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
                ):
                    continue

                # Extract parameter names
                params: list[str] = []
                if isinstance(details, dict):
                    for param in details.get("parameters", []):
                        if isinstance(param, dict):
                            param_name = param.get("name")
                            if param_name:
                                params.append(param_name)

                    # Also check requestBody for OpenAPI 3.0+
                    request_body = details.get("requestBody", {})
                    if isinstance(request_body, dict):
                        content = request_body.get("content", {})
                        for media_type, media_details in content.items():
                            if isinstance(media_details, dict):
                                schema = media_details.get("schema", {})
                                if isinstance(schema, dict):
                                    props = schema.get("properties", {})
                                    params.extend(props.keys())

                endpoints.append({
                    "path": api_path,
                    "method": method_upper,
                    "params": params or ["q", "id", "search"],
                })

        return endpoints

    def _default_endpoints(self) -> list[dict[str, Any]]:
        """Generate default endpoint list for common API patterns."""
        return [
            {"path": "/api/v1/login", "method": "POST", "params": ["username", "password"]},
            {"path": "/api/v1/users", "method": "GET", "params": ["id", "search"]},
            {"path": "/api/v1/users/1", "method": "GET", "params": ["id"]},
            {"path": "/api/v1/users/1", "method": "PUT", "params": ["name", "email", "role"]},
            {"path": "/api/v1/users/1", "method": "DELETE", "params": []},
            {"path": "/api/v1/profile", "method": "GET", "params": ["user_id"]},
            {"path": "/api/v1/search", "method": "GET", "params": ["q", "page", "limit"]},
            {"path": "/api/v1/data", "method": "POST", "params": ["query", "filter"]},
        ]

    def get_all_findings(self) -> list[Finding]:
        """Aggregate all findings across all suite results."""
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        """Generate scan summary with counts and timing."""
        all_findings = self.get_all_findings()
        total_endpoints = sum(r.endpoints_tested for r in self.results)
        total_duration = sum(r.duration for r in self.results)

        return {
            "target": self.target,
            "suites_executed": len(self.results),
            "endpoints_tested": total_endpoints,
            "total_duration_seconds": round(total_duration, 2),
            "findings": {
                "critical": sum(1 for f in all_findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in all_findings if f.severity == "HIGH"),
                "medium": sum(1 for f in all_findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in all_findings if f.severity == "LOW"),
                "info": sum(1 for f in all_findings if f.severity == "INFO"),
                "total": len(all_findings),
            },
        }

    def save_results(self, output_dir: str = "results") -> str:
        """Save scan results to a JSON file.

        Args:
            output_dir: Directory to save results in.

        Returns:
            Path to the saved results file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d_%H%M%S")
        filename = f"scan_{timestamp}.json"
        filepath = output_path / filename

        data = {
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results],
        }

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

        return str(filepath)
