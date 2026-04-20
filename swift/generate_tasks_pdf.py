"""Generate SWIFT MVP Tasks PDF."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)

OUTPUT = "SWIFT_MVP_Tasks.pdf"

TASKS = [
    {
        "id": 1,
        "name": "Project Foundation",
        "status": "completed",
        "files": [
            "requirement.txt (fix typo: python-dontenv → python-dotenv)",
            "pyproject.toml (build system + 'swift' CLI entry point)",
            "config/settings.py (Config dataclass + lazy get_config())",
            "config/__init__.py",
            "test/unit/test_config.py (6 TDD tests)",
            "test/unit/conftest.py (autouse cache-reset fixture)",
        ],
        "tests": [
            "test_config_loads_from_env",
            "test_missing_api_key_raises",
            "test_config_defaults (confidence=0.95, timeout=30, retries=3)",
            "test_config_override_from_env",
            "test_importing_config_without_key_does_not_raise",
            "test_validate_config_bad_threshold",
        ],
        "key_notes": [
            "Config loads LAZILY — never at import time",
            "reset_config() required for test isolation",
            "haiku_model = claude-haiku-4-5-20251001",
            "sonnet_model = claude-sonnet-4-6",
        ],
    },
    {
        "id": 2,
        "name": "Data Models",
        "status": "pending",
        "files": [
            "agent/models.py (Vulnerability, Patch, ScanResult, TestResult)",
            "agent/__init__.py",
            "agent/orchestrator.py (stub only — replaced in Task 10)",
            "test/unit/test_models.py (7 TDD tests)",
        ],
        "tests": [
            "test_vulnerability_creation",
            "test_vulnerability_serializable (dataclasses.asdict works)",
            "test_patch_creation",
            "test_scan_result_creation",
            "test_confidence_stored_as_float (0.97 not 97)",
            "test_test_result_summary_passed",
            "test_test_result_summary_failed",
        ],
        "key_notes": [
            "agent/models.py has ZERO internal deps — stdlib only",
            "All other modules import from here",
            "Vulnerability.confidence is float 0.0–1.0 (NOT percent)",
            "TestResult.summary property returns 'PASSED' or 'FAILED' string",
        ],
    },
    {
        "id": 3,
        "name": "Logging Infrastructure",
        "status": "pending",
        "files": [
            "log/logger.py (get_logger, MetricsCollector, _JSONFormatter)",
            "log/__init__.py",
            "test/unit/test_log.py (5 TDD tests)",
        ],
        "tests": [
            "test_setup_logging_returns_logger",
            "test_metrics_collector_start_scan",
            "test_metrics_collector_accumulates_cost",
            "test_metrics_collector_summary",
            "test_metrics_collector_vuln_tracking",
        ],
        "key_notes": [
            "Two handlers: StreamHandler (human, stderr) + FileHandler (JSON, log/swift.log)",
            "Uses logging.getLogger('swift') — NOT root logger",
            "MetricsCollector is plain class, not singleton (tests need fresh copies)",
            "log/ directory created by setup_logging() if missing",
        ],
    },
    {
        "id": 4,
        "name": "Regex Triage Pre-filter",
        "status": "pending",
        "files": [
            "triage/patterns.py (PATTERNS dict + TriageScanner class)",
            "triage/__init__.py",
            "test/unit/test_triage.py (13 TDD tests)",
        ],
        "tests": [
            "test_sql_injection_fstring",
            "test_sql_injection_concatenation",
            "test_command_injection_os_system",
            "test_command_injection_subprocess_shell",
            "test_hardcoded_password",
            "test_hardcoded_api_key",
            "test_weak_crypto_md5",
            "test_unsafe_pickle",
            "test_comment_lines_ignored",
            "test_returns_correct_line_numbers",
            "test_triage_codebase_walks_directory",
            "test_triage_codebase_skips_non_python",
            "test_triage_codebase_skips_git_dir",
        ],
        "key_notes": [
            "NO API calls — pure regex, runs before Haiku",
            "triage_file() returns Set[int] of 1-indexed line numbers",
            "triage_codebase() returns Dict[str, List[int]]",
            "MVP: only .py files scanned",
            "Skips hidden dirs (.git, .venv)",
        ],
    },
    {
        "id": 5,
        "name": "Haiku Scanner (Stage 1 API)",
        "status": "pending",
        "files": [
            "scanners/haiku_scanner.py (HaikuTriageScanner)",
            "scanners/__init__.py",
            "scanners/sonnet_scanner.py (stub — replaced in Task 6)",
            "test/unit/test_haiku_scanner.py (7 TDD tests)",
        ],
        "tests": [
            "test_haiku_calls_correct_model (claude-haiku-4-5-20251001)",
            "test_haiku_returns_line_numbers",
            "test_haiku_empty_response_returns_empty_set",
            "test_haiku_parses_varied_formats",
            "test_haiku_retry_on_api_error",
            "test_haiku_exhausted_retries_raises (3 retries)",
            "test_haiku_builds_correct_prompt",
        ],
        "key_notes": [
            "Model: claude-haiku-4-5-20251001",
            "Response parsing: re.findall(r'\\d+', response) — robust against phrasing",
            "Exponential backoff: time.sleep(2 ** attempt)",
            "Inject client= in constructor for testing (no monkey-patching needed)",
        ],
    },
    {
        "id": 6,
        "name": "Sonnet Analysis Scanner — 95% Gate",
        "status": "pending",
        "files": [
            "scanners/sonnet_scanner.py (SonnetAnalysisScanner — replaces stub)",
            "test/unit/test_sonnet_scanner.py (9 TDD tests)",
        ],
        "tests": [
            "test_sonnet_returns_vulnerability_at_95 (confidence=0.97 → Vulnerability)",
            "test_sonnet_returns_none_at_94 (confidence=0.94 → None)",
            "test_sonnet_returns_none_at_0",
            "test_sonnet_low_confidence_is_logged (logger.warning called)",
            "test_sonnet_calls_correct_model (claude-sonnet-4-6)",
            "test_sonnet_vulnerability_id_increments (SWIFT-001, SWIFT-002)",
            "test_sonnet_invalid_json_returns_none",
            "test_sonnet_missing_confidence_field_returns_none",
            "test_sonnet_severity_normalized ('critical' → 'CRITICAL')",
        ],
        "key_notes": [
            "THE MOST CRITICAL MODULE — 95% gate lives here",
            "if confidence < 0.95: log warning, return None",
            "Sonnet returns structured JSON (no markdown wrapping)",
            "ID counter: itertools.count() for thread safety",
            "Model: claude-sonnet-4-6",
        ],
    },
    {
        "id": 7,
        "name": "Output Formatters",
        "status": "pending",
        "files": [
            "output/formatters.py (JSONFormatter, MarkdownFormatter, format_output)",
            "output/__init__.py",
            "test/unit/test_output.py (14 TDD tests)",
        ],
        "tests": [
            "test_json_formatter_valid_json",
            "test_json_formatter_scan_id_present",
            "test_json_formatter_vulnerabilities_array",
            "test_json_formatter_confidence_as_float (0.97 not string)",
            "test_json_formatter_summary_counts",
            "test_json_formatter_empty_vulns",
            "test_markdown_formatter_has_title ('# SWIFT Vulnerability Report')",
            "test_markdown_formatter_has_summary_section",
            "test_markdown_formatter_vuln_section_per_vuln",
            "test_markdown_formatter_severity_in_heading",
            "test_markdown_formatter_empty_vulns_message ('No vulnerabilities found')",
            "test_format_output_dispatch_json",
            "test_format_output_dispatch_markdown",
            "test_format_output_invalid_format_raises (ValueError for 'xml')",
        ],
        "key_notes": [
            "JSONFormatter uses dataclasses.asdict() — no manual field listing",
            "JSON summary includes: files_scanned, vulnerabilities_found, patches_generated, total_cost_usd",
            "No dependency on Claude API — pure data transformation",
        ],
    },
    {
        "id": 8,
        "name": "Patch Generator",
        "status": "pending",
        "files": [
            "patches/generator.py (PatchGenerator, _score_patch, _generate_unified_diff)",
            "patches/__init__.py",
            "test/unit/test_patch_generator.py (8 TDD tests)",
        ],
        "tests": [
            "test_generate_candidates_calls_sonnet (claude-sonnet-4-6)",
            "test_generate_patch_returns_patch_object",
            "test_generate_patch_skips_low_confidence (confidence < 0.90 → None)",
            "test_patch_id_format (PATCH-001)",
            "test_generate_unified_diff_format (--- and +++ lines)",
            "test_invalid_json_response_returns_none",
            "test_score_patch_minimal_changes (<=2 changed lines → 40pts)",
            "test_select_best_picks_highest_score",
        ],
        "key_notes": [
            "Generate 3 candidates from Sonnet, score all, return best",
            "Scoring: 40pts minimal changes + 30pts correctness + 20pts security comment + 10pts maintainability",
            "Diff: difflib.unified_diff() — standard unified diff format",
            "Skip if vuln confidence < 0.90 (not 0.95 — patching is more lenient)",
        ],
    },
    {
        "id": 9,
        "name": "Docker Sandbox",
        "status": "pending",
        "files": [
            "sandbox/docker_runner.py (SandboxTester)",
            "sandbox/__init__.py",
            "test/unit/test_sandbox.py (11 TDD tests)",
        ],
        "tests": [
            "test_sandbox_calls_docker_run",
            "test_sandbox_network_none (network_mode='none')",
            "test_sandbox_mem_limit ('2g')",
            "test_sandbox_passed_on_exit_0",
            "test_sandbox_failed_on_exit_1",
            "test_sandbox_container_removed_after (even on failure)",
            "test_sandbox_docker_unavailable_raises_clear_error",
            "test_sandbox_copies_repo_to_tmpdir",
            "test_sandbox_writes_patched_file",
            "test_test_result_summary_passed",
            "test_test_result_summary_failed",
        ],
        "key_notes": [
            "Isolation: --network=none, read-only FS, /tmp only",
            "Resources: mem_limit='2g', cpu_period=100000, cpu_quota=200000",
            "container.wait() returns dict {'StatusCode': 0} — NOT raw int",
            "finally block ALWAYS calls container.remove(force=True)",
            "Image: python:3.10-slim",
        ],
    },
    {
        "id": 10,
        "name": "Agent Orchestrator",
        "status": "pending",
        "files": [
            "agent/orchestrator.py (replaces stub — scan_codebase, generate_patches)",
            "test/unit/test_agent.py (12 TDD tests)",
        ],
        "tests": [
            "test_scan_returns_scan_result",
            "test_scan_calls_triage",
            "test_scan_files_scanned_count",
            "test_scan_empty_repo_returns_empty",
            "test_scan_invalid_path_raises (ValueError with path in message)",
            "test_scan_duration_tracked",
            "test_scan_only_includes_high_confidence (0.94 → excluded)",
            "test_scan_calls_haiku_on_flagged_files",
            "test_scan_calls_sonnet_on_flagged_lines",
            "test_generate_patches_calls_patch_generator",
            "test_generate_patches_calls_sandbox",
            "test_scan_timestamp_is_iso",
        ],
        "key_notes": [
            "Pipeline: regex triage → Haiku → Sonnet → (optional) patch",
            "scan_id: f'SCAN-{uuid.uuid4().hex[:8]}'",
            "Imports: TriageScanner, HaikuTriageScanner, SonnetAnalysisScanner, PatchGenerator, SandboxTester",
            "generate_patches_flag=False by default",
        ],
    },
    {
        "id": 11,
        "name": "CLI Commands",
        "status": "pending",
        "files": [
            "cli/commands.py (scan, patch, validate Click commands)",
            "cli/__init__.py",
            "main.py (entry point)",
            "test/unit/test_cli.py (11 TDD tests)",
        ],
        "tests": [
            "test_scan_exits_0",
            "test_scan_outputs_valid_json",
            "test_scan_outputs_markdown",
            "test_scan_missing_repo_exits_2 (Click missing option)",
            "test_scan_invalid_repo_exits_1",
            "test_scan_no_api_key_exits_4",
            "test_scan_with_patches_flag",
            "test_patch_no_flags_exits_2",
            "test_patch_review_prints_diff",
            "test_validate_passed_exits_0",
            "test_validate_failed_exits_3",
        ],
        "key_notes": [
            "Use click.testing.CliRunner for all CLI tests",
            "Exit codes: 0=success, 1=error, 2=invalid args, 3=sandbox fail, 4=config error",
            "--apply flag: scaffold only, prints 'not yet implemented'",
            "main.py is 3 lines: import cli, if __name__=='__main__': cli()",
        ],
    },
    {
        "id": 12,
        "name": "Shared Fixtures + Integration Tests",
        "status": "pending",
        "files": [
            "test/conftest.py (shared fixtures for all tests)",
            "test/integration/test_scan_pipeline.py",
            "test/integration/test_patch_generation.py",
            "test/e2e/test_repo/app.py (intentionally vulnerable Python file)",
            "test/e2e/test_real_scan.py (gated by SWIFT_RUN_E2E=1)",
        ],
        "tests": [
            "Shared fixtures: config, sample_vulnerability, sample_patch, sample_scan_result, mock_anthropic_client",
            "test_full_pipeline_with_mock_api (wires all modules together)",
            "test_95_rule_end_to_end (0.94 confidence → 0 vulnerabilities in result)",
            "test_cost_tracked_through_pipeline",
            "test_patch_generated_for_confirmed_vuln",
            "test_sandbox_called_for_patch",
        ],
        "key_notes": [
            "E2E test repo has 4 vulns: SQL injection, command injection, hardcoded secret, pickle.loads",
            "Integration tests mock Anthropic — no real API calls",
            "E2E tests need SWIFT_RUN_E2E=1 env var to run",
        ],
    },
    {
        "id": 13,
        "name": "Install and Smoke Test",
        "status": "pending",
        "files": [
            "All __init__.py files verified",
        ],
        "tests": [
            "pip install -e . -r requirement.txt succeeds",
            "python -c 'from agent import scan_codebase; from cli import cli; print(OK)'",
            "pytest test/unit/ test/integration/ -v --cov=. (all pass, coverage >80%)",
            "python main.py --help (help text displayed)",
            "python main.py scan --repo test/e2e/test_repo --output json (exits 4 with clear API key error)",
        ],
        "key_notes": [
            "Final verification — all unit + integration tests green",
            "With real API key: swift scan --repo test/e2e/test_repo --output json",
            "Expected: 4+ vulnerabilities found, all confidence >= 0.95",
            "E2E with patches: swift scan --repo test/e2e/test_repo --output markdown --patches",
        ],
    },
]

STATUS_COLORS = {
    "completed": colors.HexColor("#22c55e"),
    "in_progress": colors.HexColor("#f59e0b"),
    "pending": colors.HexColor("#6b7280"),
}

STATUS_LABELS = {
    "completed": "DONE",
    "in_progress": "IN PROGRESS",
    "pending": "PENDING",
}


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=20,
    )
    task_title_style = ParagraphStyle(
        "TaskTitle",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=4,
        spaceAfter=4,
    )
    section_label_style = ParagraphStyle(
        "SectionLabel",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#94a3b8"),
        spaceBefore=6,
        spaceAfter=2,
        fontName="Helvetica-Bold",
    )
    item_style = ParagraphStyle(
        "Item",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#374151"),
        leftIndent=12,
        spaceAfter=1,
    )
    note_style = ParagraphStyle(
        "Note",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#7c3aed"),
        leftIndent=12,
        spaceAfter=1,
    )

    story = []

    # Header
    story.append(Paragraph("SWIFT MVP", title_style))
    story.append(Paragraph("Implementation Tasks — 13 tasks, build in order", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 12))

    # Summary table
    summary_data = [["Task", "Name", "Key Output", "Status"]]
    for t in TASKS:
        summary_data.append([
            f"#{t['id']}",
            t["name"],
            t["files"][0].split("(")[0].strip(),
            STATUS_LABELS[t["status"]],
        ])

    summary_table = Table(
        summary_data,
        colWidths=[0.5 * inch, 1.8 * inch, 3.4 * inch, 1.1 * inch],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Detailed tasks
    for t in TASKS:
        status_color = STATUS_COLORS[t["status"]]
        status_label = STATUS_LABELS[t["status"]]

        # Task header row
        header_data = [[
            Paragraph(f"Task {t['id']}: {t['name']}", task_title_style),
            Paragraph(f"<b>{status_label}</b>", ParagraphStyle(
                "StatusBadge", parent=styles["Normal"],
                fontSize=9, textColor=status_color,
                fontName="Helvetica-Bold",
            )),
        ]]
        header_table = Table(header_data, colWidths=[5.5 * inch, 1.3 * inch])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("LEFTPADDING", (0, 0), (0, 0), 10),
            ("RIGHTPADDING", (-1, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 1, status_color),
        ]))

        # Build task content
        content = [header_table]

        content.append(Paragraph("FILES CREATED / MODIFIED", section_label_style))
        for f in t["files"]:
            content.append(Paragraph(f"• {f}", item_style))

        content.append(Paragraph("TESTS (TDD — write failing tests first)", section_label_style))
        for test in t["tests"]:
            content.append(Paragraph(f"• {test}", item_style))

        content.append(Paragraph("KEY NOTES", section_label_style))
        for note in t["key_notes"]:
            content.append(Paragraph(f"★ {note}", note_style))

        content.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))

        story.append(KeepTogether(content[:4]))  # Keep header + files together
        story.extend(content[4:])
        story.append(Spacer(1, 6))

    # Footer note
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Run order:</b> Tasks 1→2→3→4 are sequential. Tasks 5,6,7,8,9 depend on 1–4. Task 10 needs 1–9. Task 11 needs 10. Task 12–13 are final verification. "
        "Run all unit tests after each task: <b>pytest test/unit/ -v</b>. "
        "Integration tests: <b>pytest test/integration/ -v</b>. "
        "Full E2E (needs API key): <b>SWIFT_RUN_E2E=1 pytest test/e2e/ -v</b>",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#64748b")),
    ))

    doc.build(story)
    print(f"PDF created: {OUTPUT}")


if __name__ == "__main__":
    build_pdf()
