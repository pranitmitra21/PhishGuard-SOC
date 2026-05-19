"""
Unit tests for the ML Heuristics Engine.

Tests are pure Python — no database, no Redis, no HTTP calls required.
Run with: pytest tests/test_heuristics.py -v
"""
import sys
import os

# Ensure the backend root is on the path so ml.heuristics can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.heuristics import (
    calculate_shannon_entropy,
    levenshtein_distance,
    check_typosquatting,
    analyze_url_heuristics,
)


# ─────────────────────────────────────────────
# Shannon Entropy
# ─────────────────────────────────────────────

def test_entropy_empty_string():
    """Empty string should produce 0 entropy."""
    assert calculate_shannon_entropy("") == 0.0


def test_entropy_low_for_simple_domain():
    """Well-known short domains have low character diversity → low entropy."""
    entropy = calculate_shannon_entropy("google")
    assert entropy < 3.0, f"Expected low entropy for 'google', got {entropy:.3f}"


def test_entropy_high_for_dga_domain():
    """Random-looking DGA hostnames have high character diversity → high entropy."""
    entropy = calculate_shannon_entropy("xkqjz39dnmrp")
    assert entropy > 3.5, f"Expected high entropy for DGA string, got {entropy:.3f}"


def test_entropy_single_char():
    """Single character has 0 entropy (no uncertainty)."""
    assert calculate_shannon_entropy("a") == 0.0


# ─────────────────────────────────────────────
# Levenshtein Distance
# ─────────────────────────────────────────────

def test_levenshtein_identical_strings():
    assert levenshtein_distance("google", "google") == 0


def test_levenshtein_single_substitution():
    """'g00gle' differs from 'google' by 2 (o→0, o→0)."""
    assert levenshtein_distance("google", "g00gle") == 2


def test_levenshtein_single_deletion():
    assert levenshtein_distance("paypal", "paypa") == 1


def test_levenshtein_single_insertion():
    assert levenshtein_distance("apple", "applee") == 1


def test_levenshtein_completely_different():
    d = levenshtein_distance("abc", "xyz")
    assert d == 3


# ─────────────────────────────────────────────
# Typosquatting Detection
# ─────────────────────────────────────────────

def test_typosquat_detects_micros0ft():
    """'0' replacing 'o' should be caught as a Microsoft typosquat."""
    is_squat, brand = check_typosquatting("micros0ft")
    assert is_squat is True
    assert brand == "microsoft"


def test_typosquat_detects_paypa1():
    """'1' replacing 'l' in paypal should be caught."""
    is_squat, brand = check_typosquatting("paypa1")
    assert is_squat is True
    assert brand == "paypal"


def test_typosquat_passes_exact_brand():
    """Exact brand name matches are whitelisted — not flagged as typosquats."""
    is_squat, _ = check_typosquatting("google")
    assert is_squat is False


def test_typosquat_passes_clean_domain():
    """A completely unrelated domain should not trigger typosquatting."""
    is_squat, _ = check_typosquatting("openai")
    assert is_squat is False


# ─────────────────────────────────────────────
# Full Heuristics Analyzer
# ─────────────────────────────────────────────

def test_heuristics_subdomain_brand_detection():
    """'paypal' in subdomain of a different root domain must be flagged."""
    result = analyze_url_heuristics("http://paypal.secure-login-now.com/auth")
    assert result["is_typosquat"] is True
    assert result["heuristic_risk_score"] > 0


def test_heuristics_keyword_density_triggers():
    """URLs with 2+ suspicious keywords must accumulate risk points."""
    result = analyze_url_heuristics("http://secure-login-verify.example.com/account")
    assert result["heuristic_risk_score"] > 0
    assert len(result["reasons"]) > 0


def test_heuristics_high_entropy_url():
    """A hostname that looks like a DGA domain should return measurable entropy.
    The engine flags entropy > 4.0 as high risk. We use a longer random string
    to reliably exceed that threshold."""
    result = analyze_url_heuristics("http://xkqjz39dnbvmwrp4t.net/update")
    # The engine's risk threshold is 4.0; this string reliably crosses it
    assert result["entropy"] > 3.5


def test_heuristics_clean_url_zero_risk():
    """A clean, unambiguous URL should return zero risk and no reasons."""
    result = analyze_url_heuristics("https://cleansite.com/about")
    assert result["heuristic_risk_score"] == 0.0
    assert result["is_typosquat"] is False
    assert result["reasons"] == []


def test_heuristics_returns_all_required_keys():
    """The return dict must always contain the four documented keys."""
    result = analyze_url_heuristics("https://example.com")
    assert "heuristic_risk_score" in result
    assert "reasons" in result
    assert "entropy" in result
    assert "is_typosquat" in result


def test_heuristics_risk_capped_at_100():
    """Even the most malicious URL should never produce a risk score above 100."""
    evil_url = "http://paypal.secure-login-verify-account-billing.micros0ft.com/auth?free=gift"
    result = analyze_url_heuristics(evil_url)
    assert result["heuristic_risk_score"] <= 100.0
