"""Configuration loader with YAML support."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class SuiteConfig:
    """Configuration for a single test suite."""

    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class UserCredential:
    """Represents a test user credential."""

    role: str
    token: str
    user_id: Optional[str] = None


@dataclass
class ScanConfig:
    """Top-level scan configuration."""

    timeout: int = 30
    max_concurrent: int = 10
    follow_redirects: bool = False
    verify_ssl: bool = True
    user_agent: str = "SecureAPI-Analyzer/1.0"
    delay_between_requests: float = 0.0
    proxy: Optional[str] = None


@dataclass
class Config:
    """Main configuration container."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    suites: dict[str, SuiteConfig] = field(default_factory=dict)
    users: list[UserCredential] = field(default_factory=list)
    target: Optional[str] = None
    spec_path: Optional[str] = None
    output_dir: str = "results"
    payloads_path: str = "configs/owasp_payloads.yaml"

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            Populated Config instance.

        Raises:
            FileNotFoundError: If the config file does not exist.
            yaml.YAMLError: If the YAML is malformed.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(config_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        return cls._parse_raw(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Config:
        """Create configuration from a dictionary."""
        return cls._parse_raw(raw)

    @classmethod
    def _parse_raw(cls, raw: dict[str, Any]) -> Config:
        """Parse raw dictionary into Config."""
        scan_raw = raw.get("scan", {})
        scan = ScanConfig(
            timeout=scan_raw.get("timeout", 30),
            max_concurrent=scan_raw.get("max_concurrent", 10),
            follow_redirects=scan_raw.get("follow_redirects", False),
            verify_ssl=scan_raw.get("verify_ssl", True),
            user_agent=scan_raw.get("user_agent", "SecureAPI-Analyzer/1.0"),
            delay_between_requests=scan_raw.get("delay_between_requests", 0.0),
            proxy=scan_raw.get("proxy"),
        )

        suites: dict[str, SuiteConfig] = {}
        for name, suite_raw in raw.get("suites", {}).items():
            if isinstance(suite_raw, dict):
                enabled = suite_raw.pop("enabled", True)
                suites[name] = SuiteConfig(enabled=enabled, options=suite_raw)
            else:
                suites[name] = SuiteConfig(enabled=bool(suite_raw))

        users: list[UserCredential] = []
        for user_raw in raw.get("users", []):
            users.append(
                UserCredential(
                    role=user_raw.get("role", "user"),
                    token=user_raw.get("token", ""),
                    user_id=user_raw.get("user_id"),
                )
            )

        return cls(
            scan=scan,
            suites=suites,
            users=users,
            target=raw.get("target"),
            spec_path=raw.get("spec_path"),
            output_dir=raw.get("output_dir", "results"),
            payloads_path=raw.get("payloads_path", "configs/owasp_payloads.yaml"),
        )

    def get_suite_config(self, suite_name: str) -> SuiteConfig:
        """Retrieve config for a specific suite, with defaults."""
        return self.suites.get(suite_name, SuiteConfig())

    def merge_cli_args(
        self,
        target: Optional[str] = None,
        token: Optional[str] = None,
        spec: Optional[str] = None,
        timeout: Optional[int] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        """Override config values with CLI arguments."""
        if target:
            self.target = target
        if spec:
            self.spec_path = spec
        if timeout is not None:
            self.scan.timeout = timeout
        if output_dir:
            self.output_dir = output_dir
        if token:
            # Add or update the primary user token
            if self.users:
                self.users[0].token = token
            else:
                self.users.append(UserCredential(role="user", token=token))


def load_payloads(path: str | Path) -> dict[str, list[str]]:
    """Load attack payloads from a YAML file.

    Args:
        path: Path to the payloads YAML file.

    Returns:
        Dictionary mapping payload category to list of payload strings.
    """
    payload_path = Path(path)
    if not payload_path.exists():
        return {}

    with open(payload_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    payloads: dict[str, list[str]] = {}
    for category, items in raw.items():
        if isinstance(items, list):
            payloads[category] = [str(item) for item in items]

    return payloads
