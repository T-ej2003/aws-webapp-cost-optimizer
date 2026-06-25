# AWS Web App Cost Optimizer

Read-only AWS inventory and cost optimization analyzer for web applications.

The tool collects evidence, hashes it with SHA256, classifies cost optimization candidates, writes Markdown reports, and can now generate an approval-gated no-mutation change plan. Default example commands run in sample mode and do not call AWS.

This repository also includes a deterministic secure AI developer tooling gate for AI-assisted code review.

## Quick Start

```bash
python -m aws_webapp_cost_optimizer.cli inventory --config examples/config.example.yml
python -m aws_webapp_cost_optimizer.cli analyze --evidence-dir evidence/<generated-dir>
python -m aws_webapp_cost_optimizer.cli report --evidence-dir evidence/<generated-dir>
python -m aws_webapp_cost_optimizer.cli plan --evidence-dir evidence/<generated-dir>
```

After packaging, the intended console script is:

```bash
aws-webapp-cost-optimizer inventory --config examples/config.example.yml
aws-webapp-cost-optimizer analyze --evidence-dir <dir>
aws-webapp-cost-optimizer report --evidence-dir <dir>
aws-webapp-cost-optimizer plan --evidence-dir <dir>
```

## Approval-Gated Change Planning

`plan` writes `change-plan.json` only. It never mutates AWS.

Without an approval record, every candidate is blocked:

```bash
aws-webapp-cost-optimizer plan --evidence-dir <dir>
```

With an approval record, only explicitly named actionable resources are moved into `actions`; everything else remains blocked:

```bash
aws-webapp-cost-optimizer plan \
  --evidence-dir <dir> \
  --approval-record examples/approval.example.json
```

For signed approvals:

```bash
export COST_OPTIMIZER_APPROVAL_HMAC_KEY='replace-with-secret-from-secret-manager'
aws-webapp-cost-optimizer plan \
  --evidence-dir <dir> \
  --approval-record examples/approval.example.json \
  --approval-hmac-secret-env COST_OPTIMIZER_APPROVAL_HMAC_KEY
```

## Secure AI Developer Tooling

Run the deterministic security gate before merging AI-assisted code:

```bash
python scripts/ai_code_review_gate.py src examples docs README.md --fail-on high
```

The gate checks for high-risk generated-code patterns such as hard-coded secrets, unsafe command execution, disabled verification, broad IAM permissions, and public network exposure.

See `docs/SECURE_AI_DEVELOPER_TOOLING.md`.

## What It Classifies

- EC2 instances
- Elastic IPs
- NAT gateways
- Route tables
- ALBs/NLBs
- Target groups
- RDS instances and clusters
- ElastiCache replication groups and clusters
- Auto Scaling Groups
- EBS volumes and snapshots
- ENIs
- VPC endpoints

## Safety Categories

- `unused deletion candidate`
- `used but oversized`
- `DR posture decision required`
- `blocked by AWS valid-modification API`
- `manual approval required`
- `keep`
- `observe only`

These categories are review labels only. They are not approval to change AWS.

## Safety Defaults

- Read-only by default.
- No default command mutates AWS infrastructure.
- Evidence is timestamped and hash-manifested.
- Config metadata is redacted before being written.
- Database, snapshot, DR, DNS, load balancer, and production entry-point resources default conservative.
- Change planning is blocked unless a resource is explicitly approved.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest tests
python -m compileall src scripts
python scripts/ai_code_review_gate.py src examples docs README.md --fail-on high
```

## CTO Recommendation

Treat this as the evidence layer, not the actuator. The next best development step is adding Cost Explorer and CloudWatch metric adapters that still write evidence only, then strengthening the policy engine with owner mapping, expiry enforcement, and signed approval records sourced from a controlled approval workflow.
