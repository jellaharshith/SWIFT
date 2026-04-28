from agent.models import EscalationPath

def test_escalation_path_fields():
    path = EscalationPath(
        from_vuln="sql_injection",
        steps=["DB credential leak", "Admin panel access"],
        to_impact="account_takeover",
        severity="HIGH",
        finding_ids=["SIGNAL-abc123"],
        ascii_chain="SQLi ──► DB creds ──► Admin",
    )
    assert path.from_vuln == "sql_injection"
    assert path.severity == "HIGH"
    assert "DB credential leak" in path.steps
    assert "──►" in path.ascii_chain
