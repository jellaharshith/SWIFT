# SWIFT Phase 3: Evidence Bundle + Compliance
## Implementation Roadmap

**Status:** 🚀 Ready to Start  
**Estimated Duration:** 15-23 hours (1-2 sprints)  
**Target Completion:** 2026-05-15  
**Priority:** High (Compliance requirement)

---

## Overview

Phase 3 adds comprehensive evidence bundles and compliance features for enterprise and regulated environments.

### What's Included

1. **Evidence Bundle Schema** — Enhanced findings with CWE, exploit description, remediation
2. **SARIF Export** — GitHub Advanced Security integration
3. **Enhanced Triage Ranking** — Severity × exploitability × confidence × impact
4. **API Endpoint** — `/scan/{id}/evidence` for compliance retrieval
5. **Standalone Chains Export** — `exploit_chains.json` for deep-link analysis

### Why Phase 3 Matters

- **Compliance:** Export in SARIF format for GitHub security dashboards
- **Enterprise:** Evidence bundles satisfy audit requirements
- **Context:** Detailed remediation advice accelerates fixing
- **Prioritization:** Ranking helps teams fix most critical vulnerabilities first

---

## Detailed Requirements

### 1. Enhanced Findings.json Schema

**Current Output:**
```json
{
  "vulnerabilities": [
    {
      "id": "SWIFT-001",
      "file_path": "app.py",
      "line_number": 42,
      "vuln_type": "sql_injection",
      "description": "...",
      "severity": "CRITICAL",
      "confidence": 0.97
    }
  ]
}
```

**Phase 3 Output (Enhanced):**
```json
{
  "vulnerabilities": [
    {
      "id": "SWIFT-001",
      "file_path": "app.py",
      "line_number": 42,
      "vuln_type": "sql_injection",
      "description": "User input concatenated into SQL query",
      "severity": "CRITICAL",
      "confidence": 0.97,
      "cwe_id": "CWE-89",
      "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
      "owasp_category": "A03:2021 – Injection",
      "exploit_description": "Attacker provides SQL metacharacters (', --, ;) to bypass authentication or extract data",
      "exploit_impact": "Full database compromise, data breach, user impersonation",
      "remediation": "Use parameterized queries (prepared statements) instead of string concatenation",
      "remediation_code": "query = 'SELECT * FROM users WHERE id=?'; cursor.execute(query, (uid,))",
      "remediation_effort": "LOW",
      "remediation_time_minutes": 5,
      "affected_code": {
        "before": "query = f'SELECT * FROM users WHERE id={uid}'",
        "after": "query = 'SELECT * FROM users WHERE id=?'; cursor.execute(query, (uid,))"
      },
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      ]
    }
  ]
}
```

**Implementation:**
- Extend `Vulnerability` dataclass in `agent/models.py`
- Add fields: cwe_id, cwe_url, owasp_category, exploit_description, exploit_impact, remediation, remediation_code, remediation_effort, remediation_time_minutes, affected_code, references
- Update Sonnet scanner prompt to extract these fields
- Update JSON formatter to output new schema

**Files to Modify:**
- `agent/models.py` → Extend Vulnerability dataclass
- `scanners/sonnet_scanner.py` → Update prompt
- `output/json.py` → Output new schema

**Tests:**
- Verify all new fields present in output
- Validate CWE IDs match MITRE database
- Verify remediation code is syntactically correct
- Check references are valid URLs

### 2. Standalone Chains Export

**Output Format:**
```json
{
  "export_timestamp": "2026-04-20T12:00:00Z",
  "scan_id": "SCAN-001",
  "chains": [
    {
      "chain_id": "CHAIN-001",
      "name": "SQL Injection → Auth Bypass → Admin Access",
      "vulnerability_ids": ["SWIFT-001", "SWIFT-003"],
      "attack_steps": [
        {
          "step": 1,
          "description": "Attacker crafts SQL injection payload in login form",
          "vuln_id": "SWIFT-001",
          "entry_point": "auth/views.py:42",
          "technical_detail": "Unsanitized input concatenated into WHERE clause"
        },
        {
          "step": 2,
          "description": "SQL injection bypasses authentication check",
          "vuln_id": "SWIFT-003",
          "escalation_type": "PRIVILEGE_ESCALATION",
          "technical_detail": "Query evaluates to always-true condition"
        },
        {
          "step": 3,
          "description": "Attacker gains admin panel access",
          "impact": "Full database access, system compromise",
          "severity": "CRITICAL"
        }
      ],
      "estimated_impact": "Complete system compromise",
      "business_impact": "Data breach, customer data exposed, regulatory fines",
      "attack_feasibility": "HIGH",
      "required_attacker_skill": "LOW",
      "required_system_knowledge": "MEDIUM",
      "time_to_exploit": "5 minutes",
      "confidence": 0.91,
      "remediation_summary": "Implement parameterized queries + RBAC"
    }
  ]
}
```

**Implementation:**
- Extend `ExploitChain` dataclass in `agent/models.py`
- Add fields: attack_steps, estimated_impact, business_impact, attack_feasibility, required_attacker_skill, required_system_knowledge, time_to_exploit, remediation_summary
- Create new formatter: `output/chains.py`
- Update orchestrator to export standalone chains file

**Files to Modify:**
- `agent/models.py` → Extend ExploitChain
- `output/chains.py` → NEW, standalone chains exporter
- `agent/orchestrator.py` → Output chains export

**Tests:**
- Verify chains export independently of vulnerabilities
- Validate attack_steps form complete path
- Check all chain references valid

### 3. SARIF Export Format

**Output Structure:**
```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SWIFT",
          "version": "0.1.0",
          "informationUri": "https://github.com/jellaharshith/SWIFT",
          "rules": [
            {
              "id": "CWE-89",
              "name": "SQL Injection",
              "shortDescription": {
                "text": "User input concatenated into SQL query"
              },
              "fullDescription": {
                "text": "SQL injection vulnerabilities allow attackers to manipulate SQL queries..."
              },
              "help": {
                "text": "Use parameterized queries instead of string concatenation"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": {
            "text": "User input concatenated into SQL query"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "app.py"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 10
                }
              }
            }
          ],
          "properties": {
            "swift-severity": "CRITICAL",
            "swift-confidence": 0.97,
            "swift-exploit-description": "Attacker can bypass authentication or extract data"
          }
        }
      ]
    }
  ]
}
```

**Implementation:**
- Create new formatter: `output/sarif.py`
- Implement SARIF schema compliance
- Map CWE IDs to SARIF rules
- Map SWIFT severity to SARIF levels (error, warning, note)

**Files to Create:**
- `output/sarif.py` → SARIF formatter

**Tests:**
- Validate SARIF schema compliance (using jsonschema library)
- Verify GitHub can parse output
- Test GitHub Actions integration (if available)

### 4. Enhanced Triage Ranking

**Current:** Simple severity classification (CRITICAL, HIGH, MEDIUM, LOW)

**Phase 3:** Risk score = severity × exploitability × confidence × business_impact

**Formula:**
```
risk_score = (
    severity_weight(0.0-1.0) *
    exploitability_score(0.0-1.0) *
    confidence(0.0-1.0) *
    business_impact_weight(0.0-1.0)
) × 100
```

**Severity Weights:**
- CRITICAL: 1.0
- HIGH: 0.75
- MEDIUM: 0.5
- LOW: 0.25

**Exploitability Scores:**
- Requires complex attack chain: 0.2
- Requires specific conditions: 0.4
- Requires moderate effort: 0.6
- Trivial to exploit: 0.9

**Business Impact Weights:**
- No impact: 0.0
- Data exposure: 0.6
- Service disruption: 0.7
- Financial loss: 0.8
- Compliance violation: 0.9
- Customer data breach: 1.0

**Example:**
```
SQL Injection:
- Severity: CRITICAL (1.0)
- Exploitability: 0.9 (trivial)
- Confidence: 0.97
- Impact: Customer data breach (1.0)
- Risk Score: 1.0 × 0.9 × 0.97 × 1.0 × 100 = 87.3
```

**Implementation:**
- Create scoring module: `triage/ranking.py`
- Extend Vulnerability dataclass with: exploitability, business_impact_category, risk_score
- Update orchestrator to calculate scores
- Sort output by risk_score descending

**Files to Create/Modify:**
- `triage/ranking.py` → NEW, risk scoring
- `agent/models.py` → Add risk fields
- `agent/orchestrator.py` → Calculate scores
- `output/json.py` → Output risk scores

**Tests:**
- Verify risk scores between 0-100
- Test formula correctness
- Validate sorting by risk_score

### 5. Evidence Bundle API Endpoint

**Endpoint:**
```
GET /scan/{scan_id}/evidence
```

**Response:**
```json
{
  "scan_id": "SCAN-001",
  "timestamp": "2026-04-20T12:00:00Z",
  "evidence": {
    "vulnerabilities": [...],
    "exploit_chains": [...],
    "patches": [...],
    "remediation_checklist": [...]
  },
  "compliance": {
    "cis_benchmark_mappings": [...],
    "owasp_mappings": [...],
    "pci_dss_mappings": [...]
  }
}
```

**Implementation:**
- Create API module: `web/api.py` (uses FastAPI)
- Implement `/scan/{id}` endpoint
- Implement `/scan/{id}/evidence` endpoint
- Add database layer for scan storage
- Add authentication/authorization

**Files to Create/Modify:**
- `web/api.py` → API server
- `web/models.py` → Request/response schemas
- `web/storage.py` → Scan persistence
- `agent/orchestrator.py` → Modify to store scan results

**Tests:**
- Test endpoint responds correctly
- Validate schema
- Test authentication
- Test scan ID validation

---

## Implementation Plan

### Sprint 1 (8-10 hours)

**Goal:** Evidence Bundle Schema + Standalone Chains Export

#### Task 1.1: Extend Vulnerability Dataclass (2 hours)
- [ ] Add fields: cwe_id, cwe_url, owasp_category, exploit_description, exploit_impact, remediation, remediation_code, remediation_effort, remediation_time_minutes, affected_code, references
- [ ] Update tests to validate new fields
- [ ] Write unit tests for dataclass
- [ ] **Files:** `agent/models.py`, `test/unit/test_models.py`

#### Task 1.2: Update Sonnet Scanner Prompt (1.5 hours)
- [ ] Enhance prompt to extract CWE, exploit description, remediation
- [ ] Test prompt with real API (requires gating)
- [ ] Validate output structure matches dataclass
- [ ] **Files:** `scanners/sonnet_scanner.py`, `scanners/prompts.py`, `test/unit/test_sonnet_scanner.py`

#### Task 1.3: Update JSON Output Formatter (1 hour)
- [ ] Extend JSON formatter to output new schema
- [ ] Validate JSON structure
- [ ] Write formatter tests
- [ ] **Files:** `output/json.py`, `test/unit/test_output.py`

#### Task 1.4: Standalone Chains Export (2 hours)
- [ ] Extend ExploitChain dataclass with attack steps, impact, feasibility
- [ ] Create new chains formatter
- [ ] Update orchestrator to export chains
- [ ] Write formatter tests
- [ ] **Files:** `agent/models.py`, `output/chains.py`, `agent/orchestrator.py`, `test/integration/`

#### Task 1.5: Integration Test & Validation (1.5 hours)
- [ ] End-to-end test: scan → evidence bundle + chains export
- [ ] Validate all fields present + correct format
- [ ] Test on sample vulnerable code
- [ ] **Files:** `test/integration/test_evidence_bundle.py`

### Sprint 2 (7-13 hours)

**Goal:** SARIF Export + Enhanced Ranking + API Endpoint

#### Task 2.1: SARIF Formatter (2 hours)
- [ ] Create SARIF formatter module
- [ ] Implement schema compliance
- [ ] Map SWIFT findings to SARIF rules
- [ ] Write formatter tests
- [ ] **Files:** `output/sarif.py`, `test/unit/test_sarif.py`

#### Task 2.2: Risk Scoring Module (2 hours)
- [ ] Create ranking module with scoring formula
- [ ] Implement business impact categorization
- [ ] Extend Vulnerability with risk fields
- [ ] Update orchestrator to calculate scores
- [ ] **Files:** `triage/ranking.py`, `agent/models.py`, `agent/orchestrator.py`, `test/unit/test_ranking.py`

#### Task 2.3: API Endpoint (2-3 hours)
- [ ] Create FastAPI web module
- [ ] Implement `/scan/{id}` endpoint
- [ ] Implement `/scan/{id}/evidence` endpoint
- [ ] Add scan storage (file-based or database)
- [ ] Add authentication (basic for MVP)
- [ ] **Files:** `web/api.py`, `web/models.py`, `web/storage.py`, `test/integration/test_api.py`

#### Task 2.4: Integration & Testing (1 hour)
- [ ] Full integration test: scan → all outputs (JSON, Markdown, SARIF, chains)
- [ ] Validate API responses
- [ ] Test end-to-end workflow
- [ ] **Files:** `test/integration/test_phase_3_complete.py`

#### Task 2.5: Documentation (0.5-1 hour)
- [ ] Update README with Phase 3 features
- [ ] Document new API endpoints
- [ ] Add SARIF examples
- [ ] Update architecture diagram

---

## Success Criteria

### Code Quality
- [ ] All new code has type hints
- [ ] All functions have Google-style docstrings
- [ ] Test coverage >85%
- [ ] No PEP 8 violations
- [ ] No security issues

### Functionality
- [ ] Evidence bundle schema complete + validated
- [ ] SARIF export produces valid schema
- [ ] Risk scoring ranks vulns by exploitability
- [ ] Chains exported standalone
- [ ] API endpoint responds correctly

### Testing
- [ ] 15+ new unit tests
- [ ] 5+ new integration tests
- [ ] All tests passing (234 → 250+)
- [ ] No regressions in Phase 1/2 tests

### Documentation
- [ ] API docs updated
- [ ] README includes Phase 3
- [ ] Examples provided
- [ ] Architecture diagram updated

---

## Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| API schema complexity | Medium | Low | Use OpenAPI/JSON Schema validators |
| Database scalability | Low | Medium | Start with file-based storage, migrate later |
| SARIF compliance | Low | Medium | Use JSON Schema validation, GitHub review |
| Scoring formula accuracy | Medium | Low | Gather user feedback post-launch, iterate |

### Mitigation Strategies

1. **Schema Validation:** Use jsonschema library for validation
2. **Incremental Rollout:** Deploy to staging first, gather feedback
3. **User Testing:** Test with real enterprise users
4. **Monitoring:** Track API performance, error rates, user feedback

---

## Deployment Checklist

### Pre-Deployment
- [ ] All tests passing (250+)
- [ ] Code reviewed
- [ ] Documentation complete
- [ ] Security audit done
- [ ] Performance baseline established

### Deployment
- [ ] Package build succeeds
- [ ] CLI commands work
- [ ] API starts without errors
- [ ] Database initialized
- [ ] Logs properly formatted

### Post-Deployment
- [ ] Monitor API latency
- [ ] Track cost per scan
- [ ] Collect user feedback
- [ ] Monitor error rates
- [ ] Verify SARIF GitHub integration

---

## Dependencies

### External Libraries
- **jsonschema** (for SARIF validation)
- **sqlalchemy** (for database, optional)
- **uvicorn** (already included, FastAPI)

### Internal Dependencies
- Phase 1 features (exploit chains)
- Phase 2 security controls
- Existing CLI + output formatters

### No Breaking Changes
- All Phase 1/2 APIs remain compatible
- Existing CLI commands unchanged
- New features are additive only

---

## Timeline

```
Week 1 (Sprint 1): Evidence Bundle Schema + Chains Export
├─ Mon: Task 1.1 (Vulnerability dataclass)
├─ Tue: Task 1.2 (Sonnet prompt)
├─ Wed: Task 1.3 (JSON formatter)
├─ Thu: Task 1.4 (Chains export)
└─ Fri: Task 1.5 (Integration tests)

Week 2 (Sprint 2): SARIF + Ranking + API
├─ Mon: Task 2.1 (SARIF formatter)
├─ Tue-Wed: Task 2.2 (Risk scoring)
├─ Wed-Thu: Task 2.3 (API endpoint)
├─ Thu: Task 2.4 (Integration tests)
└─ Fri: Task 2.5 (Documentation + cleanup)

Week 3: Buffer / Additional Features
├─ Performance optimization
├─ GitHub Actions integration
├─ Additional testing
└─ Staging deployment + validation
```

**Estimated Total:** 15-23 hours  
**Target Completion:** 2026-05-15  
**Team Size:** 1-2 developers

---

## Next Steps

1. **Review this roadmap** with team
2. **Prioritize tasks** if timeline is tight
3. **Assign owners** to each task
4. **Create GitHub issues** from tasks above
5. **Start Sprint 1** immediately after approval

---

## Questions & Notes

- Should we support database storage or file-based for scans initially? (Recommend file-based MVP)
- Do we need RBAC for API endpoint? (Recommend basic auth for MVP, RBAC in Phase 4)
- Should we support GitHub webhook for automatic scans? (Defer to Phase 4)
- What CWE database should we use? (Recommend MITRE CWE list, hardcode common ones)

---

**Created:** 2026-04-20  
**Status:** Ready for Sprint Planning  
**Approved By:** TBD
