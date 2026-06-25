"""Approval-gated change planning for AWS cost optimizer findings.

This module deliberately does not call AWS. It turns analysis findings into a
reviewable plan and blocks every proposed action unless an explicit approval
record names the resource.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import read_json, write_json
from .safety import SafetyCategory

ACTIONABLE_CATEGORIES = {
    SafetyCategory.UNUSED_DELETION_CANDIDATE.value: "review-delete-or-release",
    SafetyCategory.USED_BUT_OVERSIZED.value: "review-rightsize",
}

ALWAYS_BLOCKED_CATEGORIES = {
    SafetyCategory.BLOCKED_BY_VALID_MODIFICATION_API.value,
    SafetyCategory.DR_POSTURE_DECISION_REQUIRED.value,
    SafetyCategory.KEEP.value,
    SafetyCategory.MANUAL_APPROVAL_REQUIRED.value,
    SafetyCategory.OBSERVE_ONLY.value,
}


@dataclass(frozen=True)
class ApprovalRecord:
    approver: str
    ticket: str
    approved_resource_ids: set[str]
    expires_at: str | None = None
    signature: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ApprovalRecord":
        return cls(
            approver=str(payload.get("approver", "")).strip(),
            ticket=str(payload.get("ticket", "")).strip(),
            approved_resource_ids={str(item) for item in payload.get("approved_resource_ids", [])},
            expires_at=payload.get("expires_at"),
            signature=payload.get("signature"),
        )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "approver": self.approver,
            "approved_resource_ids": sorted(self.approved_resource_ids),
            "expires_at": self.expires_at,
            "ticket": self.ticket,
        }


def load_approval_record(path: Path | None) -> ApprovalRecord | None:
    if path is None:
        return None
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("approval record must be a JSON object")
    return ApprovalRecord.from_dict(payload)


def sign_approval_payload(payload: dict[str, Any], secret: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def validate_approval_record(record: ApprovalRecord | None, secret_env: str | None = None) -> list[str]:
    if record is None:
        return ["missing approval record"]

    errors: list[str] = []
    if not record.approver:
        errors.append("missing approver")
    if not record.ticket:
        errors.append("missing ticket")
    if not record.approved_resource_ids:
        errors.append("missing approved_resource_ids")
    if record.expires_at and _is_expired(record.expires_at):
        errors.append("approval record expired")

    if secret_env:
        secret = os.environ.get(secret_env)
        if secret:
            expected = sign_approval_payload(record.canonical_payload(), secret)
            if not hmac.compare_digest(expected, str(record.signature or "")):
                errors.append("invalid approval signature")
        else:
            errors.append(f"missing approval HMAC secret environment variable: {secret_env}")

    return errors


def generate_change_plan(
    analysis: dict[str, Any],
    approval_record: ApprovalRecord | None = None,
    approval_secret_env: str | None = None,
) -> dict[str, Any]:
    approval_errors = validate_approval_record(approval_record, approval_secret_env)
    approved_ids = approval_record.approved_resource_ids if approval_record and not approval_errors else set()

    actions: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    for finding in analysis.get("findings", []):
        resource_id = str(finding.get("resource_id", ""))
        category = str(finding.get("category", ""))
        base = {
            "region": finding.get("region"),
            "service": finding.get("service"),
            "resource_type": finding.get("resource_type"),
            "resource_id": resource_id,
            "category": category,
            "risk": finding.get("risk"),
            "reason": finding.get("reason"),
            "recommendation": finding.get("recommendation"),
        }

        if category in ACTIONABLE_CATEGORIES and resource_id in approved_ids:
            actions.append({
                **base,
                "proposed_action": ACTIONABLE_CATEGORIES[category],
                "execution_mode": "manual-review-only",
                "ticket": approval_record.ticket if approval_record else None,
                "approved_by": approval_record.approver if approval_record else None,
            })
            continue

        block_reasons = list(approval_errors)
        if category in ALWAYS_BLOCKED_CATEGORIES:
            block_reasons.append(f"category is not automatically actionable: {category}")
        elif resource_id not in approved_ids:
            block_reasons.append("resource_id not present in approved_resource_ids")
        blocked.append({**base, "blocked_reasons": sorted(set(block_reasons))})

    return {
        "app_name": analysis.get("app_name", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_analysis_generated_at": analysis.get("generated_at", ""),
        "execution_mode": "no-aws-mutation",
        "actions": actions,
        "blocked": blocked,
        "summary": {
            "approved_actions": len(actions),
            "blocked_findings": len(blocked),
        },
    }


def write_change_plan(path: Path, plan: dict[str, Any]) -> Path:
    write_json(path, plan)
    return path


def _is_expired(expires_at: str) -> bool:
    parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < datetime.now(timezone.utc)
