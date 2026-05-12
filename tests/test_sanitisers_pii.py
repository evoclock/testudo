"""Tests for ``testudo.sanitisers.pii``: detect_pii, redact_pii, sanitise_pii."""

from __future__ import annotations

from testudo.sanitisers.pii import detect_pii, redact_pii, sanitise_pii


def test_detect_pii_finds_email() -> None:
    findings = detect_pii("Contact julen@example.com for details")
    labels = [f.label for f in findings]
    assert "Email address" in labels


def test_detect_pii_returns_no_findings_on_clean_text() -> None:
    assert detect_pii("Nothing to see here") == []


def test_detect_pii_records_line_numbers() -> None:
    text = "line 1\nline 2 contains an email: x@y.com\nline 3"
    findings = detect_pii(text)
    assert findings[0].line_number == 2


def test_redact_pii_replaces_email_with_marker() -> None:
    cleaned, findings = redact_pii("ping me at me@example.com please")
    assert "me@example.com" not in cleaned
    assert "[REDACTED-EMAIL-ADDRESS]" in cleaned
    assert len(findings) == 1


def test_redact_pii_handles_multiple_categories() -> None:
    text = "Email me@example.com or postcode SW1A 1AA"
    cleaned, findings = redact_pii(text)
    assert "me@example.com" not in cleaned
    assert "SW1A 1AA" not in cleaned
    assert len(findings) == 2


def test_sanitise_pii_default_rejects_on_findings() -> None:
    result = sanitise_pii("email me at x@y.com")
    assert result.decision == "reject"
    assert result.content == "email me at x@y.com"
    assert len(result.findings) == 1


def test_sanitise_pii_with_redact_true_returns_redact_decision() -> None:
    result = sanitise_pii("email me at x@y.com", redact=True)
    assert result.decision == "redact"
    assert "x@y.com" not in result.content


def test_sanitise_pii_accepts_clean_content() -> None:
    result = sanitise_pii("nothing personal here")
    assert result.decision == "accept"
    assert result.findings == []
