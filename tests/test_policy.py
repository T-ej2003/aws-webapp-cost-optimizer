from aws_webapp_cost_optimizer.policy import ApprovalRecord, generate_change_plan, sign_approval_payload, validate_approval_record


def test_plan_blocks_without_approval_record():
    analysis = {
        "app_name": "test",
        "findings": [
            {
                "region": "eu-west-2",
                "service": "ec2",
                "resource_type": "eip",
                "resource_id": "eipalloc-idle",
                "category": "unused deletion candidate",
                "risk": "medium",
                "reason": "Elastic IP is not associated.",
                "recommendation": "Verify before release.",
            }
        ],
    }

    plan = generate_change_plan(analysis)

    assert plan["summary"] == {"approved_actions": 0, "blocked_findings": 1}
    assert plan["blocked"][0]["resource_id"] == "eipalloc-idle"
    assert "missing approval record" in plan["blocked"][0]["blocked_reasons"]


def test_plan_approves_only_named_actionable_resource():
    analysis = {
        "app_name": "test",
        "findings": [
            {
                "region": "eu-west-2",
                "service": "ec2",
                "resource_type": "eip",
                "resource_id": "eipalloc-idle",
                "category": "unused deletion candidate",
                "risk": "medium",
                "reason": "Elastic IP is not associated.",
                "recommendation": "Verify before release.",
            },
            {
                "region": "eu-west-2",
                "service": "rds",
                "resource_type": "rds_instance",
                "resource_id": "prod-db",
                "category": "manual approval required",
                "risk": "high",
                "reason": "Database requires review.",
                "recommendation": "Keep until reviewed.",
            },
        ],
    }
    approval = ApprovalRecord(
        approver="security@example.com",
        ticket="COST-123",
        approved_resource_ids={"eipalloc-idle", "prod-db"},
    )

    plan = generate_change_plan(analysis, approval)

    assert plan["summary"] == {"approved_actions": 1, "blocked_findings": 1}
    assert plan["actions"][0]["resource_id"] == "eipalloc-idle"
    assert plan["actions"][0]["execution_mode"] == "manual-review-only"
    assert plan["blocked"][0]["resource_id"] == "prod-db"


def test_signed_approval_record_uses_hmac_sha256(monkeypatch):
    monkeypatch.setenv("APPROVAL_KEY", "test-secret")
    base_payload = {
        "approver": "security@example.com",
        "approved_resource_ids": ["eipalloc-idle"],
        "expires_at": None,
        "ticket": "COST-123",
    }
    signature = sign_approval_payload(base_payload, "test-secret")
    record = ApprovalRecord(
        approver="security@example.com",
        ticket="COST-123",
        approved_resource_ids={"eipalloc-idle"},
        signature=signature,
    )

    assert validate_approval_record(record, "APPROVAL_KEY") == []
