#!/usr/bin/env python3
"""Deterministic secure-code gate for AI-assisted changes.

The script scans files or unified diff text for high-risk patterns commonly
introduced by generated code. It does not call an LLM or external service.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    message: str


RULES = [
    Rule("secret.aws_access_key", "critical", re.compile(r"AKIA[0-9A-Z]{16}"), "Possible AWS access key committed."),
    Rule("secret.generic_assignment", "high", re.compile(r"(?i)(secret|token|password|api[_-]?key)\s*=\s*['\"][^'\"]{12,}['\"]"), "Possible hard-coded secret assignment."),
    Rule("python.eval", "high", re.compile(r"\beval\s*\("), "Use of eval() requires security review."),
    Rule("python.exec", "high", re.compile(r"\bexec\s*\("), "Use of exec() requires security review."),
    Rule("python.subprocess_shell", "high", re.compile(r"subprocess\.[a-z_]+\([^\n]*shell\s*=\s*True"), "subprocess shell=True can enable command injection."),
    Rule("python.yaml_unsafe_load", "high", re.compile(r"yaml\.load\s*\([^\n]*(Loader\s*=\s*yaml\.Loader)?"), "Use yaml.safe_load() unless unsafe loading is explicitly justified."),
    Rule("jwt.verify_disabled", "critical", re.compile(r"(?i)(verify_signature|verify)\s*[:=]\s*False"), "Signature verification appears disabled."),
    Rule("terraform.public_ingress", "high", re.compile(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"\s*\]"), "Public ingress requires explicit justification."),
    Rule("aws.iam_wildcard_action", "high", re.compile(r"\"Action\"\s*:\s*\"\*\""), "Wildcard IAM Action requires least-privilege review."),
    Rule("aws.iam_wildcard_resource", "medium", re.compile(r"\"Resource\"\s*:\s*\"\*\""), "Wildcard IAM Resource requires least-privilege review."),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan AI-assisted code for high-risk patterns")
    parser.add_argument("paths", nargs="*", help="Files/directories to scan. Defaults to git diff --cached, then working tree diff.")
    parser.add_argument("--fail-on", choices=["medium", "high", "critical"], default="high")
    args = parser.parse_args(argv)

    text_inputs = collect_inputs(args.paths)
    findings = []
    for source, text in text_inputs:
        findings.extend(scan_text(source, text))

    for finding in findings:
        print(f"{finding['source']}:{finding['line']} [{finding['severity']}] {finding['rule_id']} - {finding['message']}")

    threshold = severity_rank(args.fail_on)
    should_fail = any(severity_rank(item["severity"]) >= threshold for item in findings)
    if should_fail:
        print("secure-ai-review-gate: failed", file=sys.stderr)
        return 1
    print("secure-ai-review-gate: passed")
    return 0


def collect_inputs(paths: list[str]) -> list[tuple[str, str]]:
    if paths:
        collected: list[tuple[str, str]] = []
        for raw in paths:
            path = Path(raw)
            if path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file() and not _skip_file(child):
                        collected.append((str(child), child.read_text(encoding="utf-8", errors="replace")))
            elif path.is_file():
                collected.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        return collected

    diff = run_git_diff(["--cached"])
    if not diff.strip():
        diff = run_git_diff([])
    return [("git-diff", diff)]


def run_git_diff(extra_args: list[str]) -> str:
    try:
        result = subprocess.run(["git", "diff", *extra_args], check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return ""
    return result.stdout


def scan_text(source: str, text: str) -> list[dict[str, str | int]]:
    findings: list[dict[str, str | int]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule.pattern.search(line):
                findings.append({
                    "source": source,
                    "line": line_number,
                    "rule_id": rule.rule_id,
                    "severity": rule.severity,
                    "message": rule.message,
                })
    return findings


def severity_rank(value: str) -> int:
    return {"medium": 1, "high": 2, "critical": 3}[value]


def _skip_file(path: Path) -> bool:
    ignored_parts = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
    return any(part in ignored_parts for part in path.parts)


if __name__ == "__main__":
    raise SystemExit(main())
