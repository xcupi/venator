"""CSRF preservation unit tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from scanner_core import (  # noqa: E402
    CSRF_FIELD_PATTERNS,
    extract_csrf_values,
    extract_links_and_forms,
    is_csrf_field,
    classify_finding,
)


# ---------- is_csrf_field ----------
def test_csrf_field_common_names():
    for n in [
        "csrf", "csrf_token", "csrftoken", "_csrf", "_token",
        "authenticity_token", "csrfmiddlewaretoken",
        "xsrf", "xsrf_token", "xsrftoken",
        "__RequestVerificationToken",
    ]:
        assert is_csrf_field(n), n


def test_csrf_field_ignores_regular_names():
    for n in ["comment", "q", "email", "password", "name", "message"]:
        assert not is_csrf_field(n), n


def test_csrf_field_case_insensitive():
    assert is_csrf_field("CSRF_Token")
    assert is_csrf_field("AUTHENTICITY_TOKEN")


# ---------- extract_links_and_forms with CSRF ----------
def test_form_with_csrf_token_splits_fields():
    html = """
    <form method='POST' action='/submit'>
      <input type='hidden' name='csrf_token' value='abc123'>
      <input type='hidden' name='return_to' value='/home'>
      <input name='comment' value='hi'>
    </form>
    """
    _, forms = extract_links_and_forms("http://x.com/", html)
    assert len(forms) == 1
    f = forms[0]
    # csrf_token is NOT in fuzz params
    assert "csrf_token" not in f.params
    assert f.csrf_fields == ["csrf_token"]
    # hidden fields (both csrf and non-csrf) preserved for replay
    assert f.hidden_fields["csrf_token"] == "abc123"
    assert f.hidden_fields["return_to"] == "/home"
    # regular field IS fuzzed
    assert "comment" in f.params
    # hidden non-CSRF field is also fuzzed (some apps carry vulns in them)
    assert "return_to" in f.params
    # origin_url tracked
    assert f.origin_url == "http://x.com/"


def test_form_without_csrf():
    html = "<form method='POST'><input name='q'><input name='comment'></form>"
    _, forms = extract_links_and_forms("http://x.com/p", html)
    assert forms[0].csrf_fields == []
    assert set(forms[0].params) == {"q", "comment"}


# ---------- extract_csrf_values ----------
def test_extract_csrf_values_returns_current_values():
    html = """
    <form><input name='csrf_token' value='FRESH_VALUE'>
    <input name='other' value='x'></form>
    """
    out = extract_csrf_values(html, ["csrf_token"])
    assert out == {"csrf_token": "FRESH_VALUE"}


def test_extract_csrf_values_missing_field():
    html = "<form><input name='other'></form>"
    assert extract_csrf_values(html, ["csrf_token"]) == {}


def test_extract_csrf_values_case_matters_for_field_lookup():
    # store returns exact-case name key when it matches (case-insensitive match)
    html = "<input name='CSRF_Token' value='v'>"
    out = extract_csrf_values(html, ["csrf_token"])
    assert out == {"CSRF_Token": "v"}


# ---------- classify_finding csrf_required ----------
def test_classify_csrf_required():
    assert classify_finding("csrf_required", validated=False) == "csrf_token_required"


def test_classify_validated_wins_over_csrf():
    assert classify_finding("csrf_required", validated=True) == "validated"
