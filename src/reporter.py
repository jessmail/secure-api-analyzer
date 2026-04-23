"""Report generator with JSON, HTML, and Markdown output.

Generates structured security reports with OWASP Top 10 mapping,
CVSS scoring, and remediation recommendations.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.utils import Finding, ScanResult, get_severity_weight


# OWASP API Security Top 10 (2023) reference data
OWASP_CATEGORIES = {
    "API1:2023": {
        "name": "Broken Object Level Authorization",
        "description": (
            "APIs expose endpoints that handle object identifiers, creating "
            "a wide attack surface of Object Level Access Control issues."
        ),
        "cwe": "CWE-284",
    },
    "API2:2023": {
        "name": "Broken Authentication",
        "description": (
            "Authentication mechanisms are often implemented incorrectly, "
            "allowing attackers to compromise authentication tokens."
        ),
        "cwe": "CWE-287",
    },
    "API3:2023": {
        "name": "Broken Object Property Level Authorization",
        "description": (
            "Lack of or improper authorization validation at the object "
            "property level can lead to information exposure or manipulation."
        ),
        "cwe": "CWE-285",
    },
    "API4:2023": {
        "name": "Unrestricted Resource Consumption",
        "description": (
            "APIs do not restrict the size or number of resources that can "
            "be requested, leading to denial of service or cost overrun."
        ),
        "cwe": "CWE-770",
    },
    "API5:2023": {
        "name": "Broken Function Level Authorization",
        "description": (
            "Complex access control policies with different hierarchies "
            "and roles can lead to authorization flaws."
        ),
        "cwe": "CWE-285",
    },
    "API6:2023": {
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs that expose business flows without compensating controls "
            "can be exploited by attackers."
        ),
        "cwe": "CWE-799",
    },
    "API7:2023": {
        "name": "Server Side Request Forgery",
        "description": (
            "SSRF flaws occur when an API fetches a remote resource without "
            "validating the user-supplied URI."
        ),
        "cwe": "CWE-918",
    },
    "API8:2023": {
        "name": "Security Misconfiguration",
        "description": (
            "APIs and supporting systems typically contain complex configurations. "
            "Misconfigurations can expose the API to various attacks."
        ),
        "cwe": "CWE-16",
    },
    "API9:2023": {
        "name": "Improper Inventory Management",
        "description": (
            "APIs tend to expose more endpoints than traditional web applications. "
            "Proper inventory and documentation is crucial."
        ),
        "cwe": "CWE-1059",
    },
    "API10:2023": {
        "name": "Unsafe Consumption of APIs",
        "description": (
            "Developers tend to trust data received from third-party APIs "
            "more than user input, leading to weaker security standards."
        ),
        "cwe": "CWE-20",
    },
}


class Reporter:
    """Generate security reports in multiple formats."""

    def __init__(
        self,
        results: list[ScanResult],
        target: str,
        template_dir: str = "templates",
    ) -> None:
        self.results = results
        self.target = target
        self.template_dir = template_dir
        self.findings = self._collect_findings()
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    def _collect_findings(self) -> list[Finding]:
        """Collect and sort all findings by severity."""
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        findings.sort(key=lambda f: get_severity_weight(f.severity), reverse=True)
        return findings

    def _build_report_data(self) -> dict[str, Any]:
        """Build the data structure shared by all report formats."""
        # Group findings by OWASP category
        by_category: dict[str, list[dict[str, Any]]] = {}
        for finding in self.findings:
            cat = finding.owasp_category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding.to_dict())

        # Build severity summary
        severity_counts = {
            "CRITICAL": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in self.findings if f.severity == "LOW"),
            "INFO": sum(1 for f in self.findings if f.severity == "INFO"),
        }

        # Suite summaries
        suite_summaries = []
        for result in self.results:
            suite_summaries.append({
                "name": result.suite_name,
                "endpoints_tested": result.endpoints_tested,
                "findings_count": len(result.findings),
                "duration_seconds": round(result.duration, 2),
            })

        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "suites": suite_summaries,
            "findings_by_category": by_category,
            "findings": [f.to_dict() for f in self.findings],
            "owasp_reference": OWASP_CATEGORIES,
        }

    def generate_json(self, output_path: str) -> str:
        """Generate JSON report.

        Args:
            output_path: Path to save the JSON report.

        Returns:
            Path to the generated report.
        """
        data = self._build_report_data()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

        return str(path)

    def generate_markdown(self, output_path: str) -> str:
        """Generate Markdown report.

        Args:
            output_path: Path to save the Markdown report.

        Returns:
            Path to the generated report.
        """
        data = self._build_report_data()
        lines: list[str] = []

        lines.append(f"# SecureAPI Analyzer - Security Report")
        lines.append("")
        lines.append(f"**Target:** {data['target']}")
        lines.append(f"**Date:** {data['timestamp']}")
        lines.append(f"**Total Findings:** {data['total_findings']}")
        lines.append("")

        # Severity summary
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for severity, count in data["severity_counts"].items():
            lines.append(f"| {severity} | {count} |")
        lines.append("")

        # Suite results
        lines.append("## Test Suites")
        lines.append("")
        lines.append("| Suite | Endpoints Tested | Findings | Duration |")
        lines.append("|-------|-----------------|----------|----------|")
        for suite in data["suites"]:
            lines.append(
                f"| {suite['name']} | {suite['endpoints_tested']} | "
                f"{suite['findings_count']} | {suite['duration_seconds']}s |"
            )
        lines.append("")

        # Findings grouped by OWASP category
        lines.append("## Findings by OWASP Category")
        lines.append("")
        for category, category_findings in data["findings_by_category"].items():
            lines.append(f"### {category}")
            lines.append("")
            for finding in category_findings:
                severity_badge = f"**[{finding['severity']}]**"
                lines.append(f"#### {severity_badge} {finding['title']}")
                lines.append("")
                lines.append(f"- **Endpoint:** `{finding['method']} {finding['endpoint']}`")
                lines.append(f"- **CVSS Score:** {finding['cvss_score']}")
                lines.append(f"- **Description:** {finding['description']}")
                if finding["evidence"]:
                    lines.append(f"- **Evidence:** {finding['evidence']}")
                if finding["remediation"]:
                    lines.append(f"- **Remediation:** {finding['remediation']}")
                lines.append("")

        # OWASP reference
        lines.append("## OWASP API Security Top 10 (2023) Reference")
        lines.append("")
        lines.append("| ID | Category | CWE |")
        lines.append("|----|----------|-----|")
        for cat_id, cat_info in OWASP_CATEGORIES.items():
            lines.append(f"| {cat_id} | {cat_info['name']} | {cat_info['cwe']} |")
        lines.append("")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        return str(path)

    def generate_html(self, output_path: str) -> str:
        """Generate HTML report using Jinja2 template.

        Args:
            output_path: Path to save the HTML report.

        Returns:
            Path to the generated report.
        """
        data = self._build_report_data()

        template_path = Path(self.template_dir)
        if template_path.exists() and (template_path / "report.html").exists():
            env = Environment(
                loader=FileSystemLoader(str(template_path)),
                autoescape=select_autoescape(["html"]),
            )
            template = env.get_template("report.html")
            html_content = template.render(**data)
        else:
            html_content = self._generate_inline_html(data)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        return str(path)

    def _generate_inline_html(self, data: dict[str, Any]) -> str:
        """Generate HTML report without external template."""
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }

        findings_html = ""
        for finding in data["findings"]:
            color = severity_colors.get(finding["severity"], "#6b7280")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 12px 0; background: #f8f9fa;">
                <h3 style="margin: 0 0 8px 0;">
                    <span style="background: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">{finding['severity']}</span>
                    {finding['title']}
                </h3>
                <p><strong>Endpoint:</strong> <code>{finding['method']} {finding['endpoint']}</code></p>
                <p><strong>OWASP:</strong> {finding['owasp_category']}</p>
                <p><strong>CVSS:</strong> {finding['cvss_score']}</p>
                <p>{finding['description']}</p>
                {"<p><strong>Evidence:</strong> " + finding['evidence'] + "</p>" if finding['evidence'] else ""}
                {"<p><strong>Remediation:</strong> " + finding['remediation'] + "</p>" if finding['remediation'] else ""}
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecureAPI Analyzer - Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; color: #1a1a1a; }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 8px; }}
        h2 {{ color: #2d5986; margin-top: 32px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px 14px; text-align: left; }}
        th {{ background: #1e3a5f; color: white; }}
        tr:nth-child(even) {{ background: #f8f9fa; }}
        code {{ background: #e8e8e8; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .meta {{ color: #555; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>SecureAPI Analyzer - Security Report</h1>
    <p class="meta"><strong>Target:</strong> {data['target']}</p>
    <p class="meta"><strong>Date:</strong> {data['timestamp']}</p>
    <p class="meta"><strong>Total Findings:</strong> {data['total_findings']}</p>

    <h2>Severity Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {"".join(f"<tr><td>{sev}</td><td>{cnt}</td></tr>" for sev, cnt in data['severity_counts'].items())}
    </table>

    <h2>Test Suite Results</h2>
    <table>
        <tr><th>Suite</th><th>Endpoints</th><th>Findings</th><th>Duration</th></tr>
        {"".join(f"<tr><td>{s['name']}</td><td>{s['endpoints_tested']}</td><td>{s['findings_count']}</td><td>{s['duration_seconds']}s</td></tr>" for s in data['suites'])}
    </table>

    <h2>Detailed Findings</h2>
    {findings_html}

    <h2>OWASP API Security Top 10 (2023)</h2>
    <table>
        <tr><th>ID</th><th>Category</th><th>CWE</th></tr>
        {"".join(f"<tr><td>{cid}</td><td>{info['name']}</td><td>{info['cwe']}</td></tr>" for cid, info in OWASP_CATEGORIES.items())}
    </table>

    <footer style="margin-top: 40px; padding-top: 16px; border-top: 1px solid #ddd; color: #888; font-size: 12px;">
        Generated by SecureAPI Analyzer v1.0.0
    </footer>
</body>
</html>"""
