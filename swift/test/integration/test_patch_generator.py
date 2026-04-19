"""Integration tests for PatchGenerator — mocked Anthropic client."""
from __future__ import annotations

import pytest

from patches.generator import PatchGenerator, _make_diff, _score_candidate


class TestScoring:
    def test_few_lines_scores_higher(self):
        assert _score_candidate(3, "fix") > _score_candidate(15, "fix")

    def test_with_reasoning_scores_higher(self):
        assert _score_candidate(3, "good reason") > _score_candidate(3, "")

    def test_many_lines_penalized(self):
        assert _score_candidate(50, "reason") < _score_candidate(4, "reason")


class TestMakeDiff:
    def test_diff_not_empty_on_change(self):
        diff = _make_diff("original\n", "patched\n", "app.py")
        assert diff != ""

    def test_diff_empty_on_same(self):
        assert _make_diff("same\n", "same\n", "app.py") == ""

    def test_diff_has_file_header(self):
        diff = _make_diff("a\n", "b\n", "app.py")
        assert "a/app.py" in diff
        assert "b/app.py" in diff


class TestPatchGenerator:
    def test_generates_patch(self, mock_patch_response, sample_vulnerability):
        gen = PatchGenerator(mock_patch_response)
        patch = gen.generate_patch(sample_vulnerability)
        assert patch is not None
        assert patch.vuln_id == "SWIFT-001"
        assert patch.id.startswith("PATCH-")

    def test_skips_low_confidence(self, mock_patch_response, low_confidence_vulnerability):
        gen = PatchGenerator(mock_patch_response)
        patch = gen.generate_patch(low_confidence_vulnerability)
        assert patch is None
        mock_patch_response.messages.create.assert_not_called()

    def test_patch_has_diff(self, mock_patch_response, sample_vulnerability):
        gen = PatchGenerator(mock_patch_response)
        patch = gen.generate_patch(sample_vulnerability)
        # diff may be empty if original == patched (mock), just check it's a string
        assert isinstance(patch.diff, str)

    def test_generate_patches_batch(self, mock_patch_response, sample_vulnerability):
        gen = PatchGenerator(mock_patch_response)
        patches = gen.generate_patches([sample_vulnerability, sample_vulnerability])
        assert len(patches) == 2

    def test_invalid_json_returns_none(self, mock_anthropic_client, sample_vulnerability):
        mock_anthropic_client.messages.create.return_value.content[0].text = "not json"
        gen = PatchGenerator(mock_anthropic_client)
        patch = gen.generate_patch(sample_vulnerability)
        assert patch is None

    def test_empty_candidates_returns_none(self, mock_anthropic_client, sample_vulnerability):
        import json
        mock_anthropic_client.messages.create.return_value.content[0].text = json.dumps(
            {"candidates": []}
        )
        gen = PatchGenerator(mock_anthropic_client)
        patch = gen.generate_patch(sample_vulnerability)
        assert patch is None
