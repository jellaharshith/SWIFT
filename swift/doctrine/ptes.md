# PTES 7-Phase Contract

The Penetration Testing Execution Standard (PTES) defines a seven-phase lifecycle that governs every SWIFT engagement. Each phase has explicit entry criteria, exit criteria, ROE gates, owning specialists, and an output artifact. No phase may begin until the previous phase's exit criteria are met. Phase transitions are logged in the engagement audit trail.

---

## Phase 1: Pre-Engagement

**Purpose:** Establish the legal, operational, and communicative foundation of the engagement before any technical work begins.

**Entry criteria:** Client or program brief received. At minimum: target name, scope description, and authorization confirmation.

**Activities:**
- Scope definition: explicit list of in-scope targets (domains, IP ranges, applications, accounts), explicit out-of-scope exclusions
- Rules of Engagement (ROE) document: authorized techniques, blacklisted techniques, authorized time windows, data handling requirements
- OPPLAN generation: attack objectives ranked by priority, assumed attacker profile, success criteria
- Target list: confirmed in-scope assets with owner contact information
- Emergency contacts: client-side technical lead and legal contact; escalation path if live impact is observed
- Start/end dates and authorized hours; blackout windows
- Reporting format and delivery method agreed in advance

**Exit criteria:** Signed authorization document (or equivalent program brief for bug bounty). `roe.yaml` committed to engagement directory.

**ROE technique required:** `engagement_planning`

**Owning specialist(s):** `soundwave` (interview and OPPLAN generation)

**Output artifact:** `roe.yaml`, `OPPLAN.md`, `ConOps.md`

---

## Phase 2: Intelligence Gathering

**Purpose:** Build a comprehensive map of the target's attack surface using passive and active reconnaissance, without triggering alerts or touching production systems beyond what ROE permits.

**Entry criteria:** Phase 1 complete. `roe.yaml` loaded. Authorized techniques confirmed.

**Activities:**
- Passive OSINT: CT logs, Shodan, Censys, Wayback Machine, GitHub org search, LinkedIn, job postings, SPF/DMARC records, ASN pivoting, acquisition history
- DNS enumeration: subdomain brute-force, permutation generation, reverse DNS, zone transfer attempts
- JavaScript analysis: crawl with katana/gospider, endpoint extraction with LinkFinder/JSluice, parameter mining with Arjun/paramspider, secret regex scanning
- Content discovery: layered wordlist-based directory enumeration
- Active recon (if ROE permits `active_scan`): port scanning, banner grabbing, technology fingerprinting
- Knowledge graph population: all discovered assets inserted as nodes; relationships between assets captured as edges

**Exit criteria:** Asset map complete. All enumerated subdomains resolved and classified (live/dead/403/redirect). JS analysis complete. KG snapshot committed.

**ROE technique required:** `osint` (passive); `active_scan` (active probing)

**Owning specialist(s):** `recon`, `hunt_planner`

**Output artifact:** `asset_map.json`, KG snapshot, `recon_notes.md`

---

## Phase 3: Threat Modeling

**Purpose:** Prioritize the attack surface by mapping discovered assets to likely vulnerability classes based on technology stack, trust assumptions, and assumed attacker profile.

**Entry criteria:** Phase 2 complete. Asset map and KG snapshot available.

**Activities:**
- Attack surface prioritization: rank assets by exposure, complexity, and potential impact
- Vulnerability class mapping: match technology stack observations to known vulnerability patterns (OAuth → token_theft; file upload → RCE/stored_XSS; GraphQL → IDOR/introspection leak)
- Threat actor profile: define assumed attacker capabilities (unauthenticated external, authenticated user, authenticated low-privilege user, authenticated merchant, etc.)
- Attack path ranking: enumerate candidate exploit chains from highest to lowest confidence; score by feasibility × impact
- KG query: use `kg_query` to surface previously observed patterns for this technology stack from prior engagements

**Exit criteria:** Ranked attack path list documented. Top three hypotheses stated as falsifiable claims with success criteria.

**ROE technique required:** `kg_query`

**Owning specialist(s):** `threat_modeler`, `analyst`

**Output artifact:** `threat_model.md`, updated KG with ranked attack paths

---

## Phase 4: Vulnerability Analysis

**Purpose:** Systematically probe the prioritized attack surface to confirm or refute each hypothesis from Phase 3.

**Entry criteria:** Phase 3 complete. Ranked hypotheses available. All probe techniques in use are listed in `roe.yaml`.

**Activities:**
- Scanner runs: OWASP ZAP, Nuclei, custom SWIFT probes against in-scope targets
- Manual probing: targeted HTTP request manipulation, parameter injection, authentication flow testing, OAuth flow analysis, file upload testing
- Confidence classification: each finding classified as Confirmed (TP), Needs Verification, or False Positive (FP)
- Hypothesis update: each probe result updates the hypothesis register; exhausted vectors are marked
- Budget tracking: probe calls, model calls, and wall-clock time tracked against `AgentBudget`

**Exit criteria:** All top-three hypotheses resolved (confirmed or refuted). All scanner findings classified. At least one round of manual probing on highest-confidence paths.

**ROE technique required:** `vuln_pipeline`

**Owning specialist(s):** `scanner`, `oauth_dcr_hunter`, `upload_hunter`, `recon`

**Output artifact:** `findings_raw.json`, updated hypothesis register

---

## Phase 5: Exploitation

**Purpose:** Build working proof-of-concept exploits for confirmed vulnerabilities to establish true impact and demonstrate exploitability.

**Entry criteria:** Phase 4 complete. At least one Confirmed finding present. ROE permits exploitation techniques in use.

**Activities:**
- PoC construction: minimal reproducible exploit for each confirmed finding
- Chain execution: where multiple vulnerabilities can be chained (auth_bypass → IDOR → data_exfil), execute the chain to its logical endpoint
- Evidence capture: HTTP request/response pairs, screenshots, extracted data samples (sanitized), timing measurements
- Simulation mode: unless ROE explicitly permits live exploitation against production data, all exploit runs are simulated against test accounts or staging environments
- Lateral movement feasibility: assess whether an initial foothold enables access to additional assets in scope

**Exit criteria:** Working PoC documented for all Confirmed findings. Chain exploits documented end-to-end. All evidence captured in engagement directory.

**ROE technique required:** `exploit` or `auth_chain` (per technique)

**Owning specialist(s):** `exploiter`, `exploit`, `oauth_dcr_hunter`

**Output artifact:** `exploits/`, evidence archive, `chain_results.json`

---

## Phase 6: Post-Exploitation

**Purpose:** Assess the downstream impact of a successful compromise — what an attacker could do after initial access — without causing actual harm.

**Entry criteria:** Phase 5 complete. At least one working exploit chain demonstrated.

**Activities:**
- Persistence feasibility: assess whether an attacker could maintain access after the initial exploit (token caching, long-lived refresh tokens, backdoor account creation)
- Lateral movement paths: from the compromised account or system, enumerate what additional resources are accessible
- Privilege escalation paths: assess whether the compromised account can escalate to higher privilege within the same application
- Data exfiltration assessment: identify the highest-sensitivity data accessible from the compromised position and estimate realistic exfiltration volume
- All activities remain within authorized scope; no actual persistent access is established without explicit ROE authorization

**Exit criteria:** Post-exploitation impact assessment documented. Data sensitivity classification complete. No unauthorized persistent access left in place.

**ROE technique required:** `post_exploit`

**Owning specialist(s):** `exploiter`, `analyst`

**Output artifact:** `post_exploit_assessment.md`

---

## Phase 7: Reporting

**Purpose:** Produce a narrative report that communicates findings, impact, and remediation guidance to the program or client.

**Entry criteria:** All prior phases complete. All findings classified and evidence captured.

**Activities:**
- Narrative report (Rosén-style): story arc from discovery through escalation to impact; business impact first, technical impact second
- Platform-formatted output: H1 / Bugcrowd / Intigriti / Immunefi format as appropriate for the engagement type
- Reproduction steps: 3-5 steps per finding, exact HTTP requests included, executable in under 10 minutes
- Fix section: concrete, minimal, specific to the technology stack
- MITRE ATT&CK appendix: technique IDs for each phase of the observed kill chain
- Executive summary: two-paragraph non-technical summary suitable for a product manager or CISO

**Exit criteria:** Report reviewed against Rosén test (non-technical PM can understand impact from first paragraph). All findings include working reproduction steps. Fix sections are specific and actionable.

**ROE technique required:** (read-only — no external actions)

**Owning specialist(s):** `report_formatter`, `analyst`

**Output artifact:** `report.md`, platform-specific report files, `mitre_appendix.md`
