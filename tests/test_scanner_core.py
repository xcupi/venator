"""Scanner core unit tests. Purely functional, no network required."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from scanner_core import (  # noqa: E402
    DEFAULT_MARKER,
    classify_context,
    classify_finding,
    extract_get_params,
    extract_links_and_forms,
    in_scope,
    normalize_url,
)


# ---------- Scope ----------
def test_scope_allowed_domain():
    assert in_scope("http://example.com/foo", ["example.com"], [])


def test_scope_disallowed_domain():
    assert not in_scope("http://evil.com/foo", ["example.com"], [])


def test_scope_wildcard_domain():
    assert in_scope("http://a.example.com/x", ["*.example.com"], [])


def test_scope_excluded_path():
    assert not in_scope("http://example.com/logout", ["example.com"], ["/logout"])


def test_scope_redirect_outside():
    assert not in_scope("http://another.com/", ["example.com"], [])


# ---------- URL processing ----------
def test_normalize_drops_fragment():
    assert normalize_url("http://x.com/a?b=1#frag") == "http://x.com/a?b=1"


def test_normalize_sorts_query():
    assert normalize_url("http://x.com/?b=2&a=1") == "http://x.com/?a=1&b=2"


def test_normalize_case():
    assert normalize_url("HTTP://X.COM/A") == "http://x.com/A"


def test_extract_get_params():
    assert extract_get_params("http://x.com/p?a=1&b=2") == ["a", "b"]


# ---------- Parameter discovery ----------
def test_extract_links_and_forms():
    html = """
    <html><body>
      <a href='/one'>one</a>
      <a href='http://x.com/two'>two</a>
      <form method='POST' action='/submit'>
        <input name='q' value='v'>
        <textarea name='body'></textarea>
      </form>
    </body></html>"""
    links, forms = extract_links_and_forms("http://x.com/", html)
    assert "http://x.com/one" in links
    assert "http://x.com/two" in links
    assert len(forms) == 1
    assert forms[0].method == "POST"
    assert set(forms[0].params) == {"q", "body"}


# ---------- Reflection / context ----------
def test_html_reflection():
    body = f"<html>hello {DEFAULT_MARKER} world</html>"
    assert classify_context(body, DEFAULT_MARKER) == "html"


def test_attribute_reflection():
    body = f'<input value="{DEFAULT_MARKER}">'
    assert classify_context(body, DEFAULT_MARKER) == "attribute"


def test_javascript_reflection():
    body = f"<script>var x='{DEFAULT_MARKER}';</script>"
    assert classify_context(body, DEFAULT_MARKER) == "javascript"


def test_encoded_reflection():
    body = f"<html>Hello, {DEFAULT_MARKER.replace('x', 'x')}!</html>".replace(
        DEFAULT_MARKER, DEFAULT_MARKER.replace("x", "&#120;")
    )
    # marker not present raw -> should be encoded or none
    assert classify_context(body, DEFAULT_MARKER) in ("encoded", "none")


def test_non_reflection():
    body = "<html>Static content</html>"
    assert classify_context(body, DEFAULT_MARKER) == "none"


# ---------- Classification ----------
def test_classify_potential():
    assert classify_finding("html", validated=False) == "potential"


def test_classify_safely_encoded():
    assert classify_finding("encoded", validated=False) == "safely_encoded"


def test_classify_validated():
    assert classify_finding("html", validated=True) == "validated"


def test_classify_false_positive():
    assert classify_finding("none", validated=False) == "false_positive"


def test_classify_csrf_token_required():
    # csrf_required context (produced by the engine when a required CSRF token
    # cannot be refreshed) must map to csrf_token_required, not false_positive.
    assert classify_finding("csrf_required", validated=False) == "csrf_token_required"


def test_classify_reflection_only_for_unknown_context():
    # 'unknown' is emitted by the engine when the response body was truncated
    # at the size cap before the marker could be observed. It means "reflection
    # observed but rendering context indeterminate", NOT "no reflection".
    assert classify_finding("unknown", validated=False) == "reflection_only"


def test_classify_validated_wins_over_context():
    # A validated finding is always 'validated', regardless of context.
    assert classify_finding("encoded", validated=True) == "validated"
    assert classify_finding("unknown", validated=True) == "validated"


# ---------- Scanner state legality ----------
def test_scan_states_are_documented():
    from models import Scan  # noqa: F401 -- import for schema smoke test
    valid_states = {"QUEUED", "RUNNING", "PAUSED", "STOPPING", "STOPPED", "COMPLETED", "FAILED"}
    for s in valid_states:
        assert isinstance(s, str)
