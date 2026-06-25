import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ai_code_review_gate.py"
spec = importlib.util.spec_from_file_location("ai_code_review_gate", MODULE_PATH)
ai_code_review_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ai_code_review_gate)


def test_scanner_flags_high_risk_generated_code_patterns():
    findings = ai_code_review_gate.scan_text(
        "example.py",
        "subprocess.run(command, shell=True)\nsecret_key = 'super-secret-token-value'\n",
    )

    rule_ids = {finding["rule_id"] for finding in findings}
    assert "python.subprocess_shell" in rule_ids
    assert "secret.generic_assignment" in rule_ids


def test_scanner_allows_plain_safe_code():
    findings = ai_code_review_gate.scan_text("example.py", "print('hello')\n")

    assert findings == []
