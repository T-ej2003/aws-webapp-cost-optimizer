# Secure AI Developer Tooling

This repository now includes a small deterministic secure AI developer tooling layer that can be shown as a portfolio artifact for GenAI tooling roles.

## Objective

Provide a safe workflow for teams using Copilot, Codex, Claude Code, or other AI coding tools without blindly trusting generated code.

## Threat Model

AI-generated or AI-assisted changes can introduce:

- hard-coded secrets
- unsafe command execution
- disabled signature verification
- broad IAM permissions
- public network exposure
- unsafe deserialization
- unreviewed infrastructure mutations

The first version intentionally avoids calling an LLM inside CI. The gate is deterministic so failures are explainable and repeatable.

## Components

| Component | Path | Purpose |
| --- | --- | --- |
| Secure code gate | `scripts/ai_code_review_gate.py` | Scans changed/source files for high-risk generated-code patterns. |
| CI workflow | `.github/workflows/secure-ai-review.yml` | Runs the gate and unit tests on pull requests and pushes to `main`. |
| Cost optimizer policy engine | `src/aws_webapp_cost_optimizer/policy.py` | Turns findings into no-mutation change plans and blocks actions without approval. |
| Tests | `tests/test_ai_code_review_gate.py`, `tests/test_policy.py` | Proves the guardrails behave deterministically. |

## Local Usage

```bash
python scripts/ai_code_review_gate.py src examples docs README.md --fail-on high
python -m pytest tests
```

## AI-Assisted Pull Request Rules

Use this checklist for every AI-assisted PR:

```text
- State which AI tool was used.
- State which files were AI-generated or AI-edited.
- Run tests locally.
- Run the secure AI review gate.
- Manually review authentication, authorization, secrets, IAM, network exposure, and data deletion paths.
- Never merge AI-generated infrastructure mutation code without separate human approval.
```

## AWS Cost Optimizer Safety Boundary

The optimizer remains evidence-first:

```text
inventory -> analyze -> report -> plan
```

The `plan` step writes `change-plan.json` only. It does not call AWS mutation APIs.

Without an approval record, every candidate is blocked. With an approval record, only explicitly named actionable resources are moved into `actions`; all other findings remain blocked.

Example:

```bash
aws-webapp-cost-optimizer inventory --config examples/config.example.yml
aws-webapp-cost-optimizer analyze --evidence-dir evidence/<generated-dir>
aws-webapp-cost-optimizer report --evidence-dir evidence/<generated-dir>
aws-webapp-cost-optimizer plan --evidence-dir evidence/<generated-dir>
```

## Signed Approval Record

For stronger review control, set an HMAC key and require the approval record signature:

```bash
export COST_OPTIMIZER_APPROVAL_HMAC_KEY='replace-with-secret-from-secret-manager'
aws-webapp-cost-optimizer plan \
  --evidence-dir evidence/<generated-dir> \
  --approval-record examples/approval.example.json \
  --approval-hmac-secret-env COST_OPTIMIZER_APPROVAL_HMAC_KEY
```

The signature is calculated over this canonical payload:

```json
{
  "approver": "security@example.com",
  "approved_resource_ids": ["eipalloc-exampleidle"],
  "expires_at": null,
  "ticket": "COST-123"
}
```

This is still not permission to mutate AWS. It is only a controlled handoff from evidence to human-reviewed change planning.
