"""Core scanner logic — reusable by API-embedded worker and standalone scanner service.

Functions here are pure / stateless where possible so they are testable.
"""
from __future__ import annotations

import re
import html
from dataclasses import dataclass, field
from typing import Iterable, List, Set, Tuple
from urllib.parse import urlparse, urljoin, urlsplit, urlunsplit, parse_qsl, urlencode, urldefrag

from bs4 import BeautifulSoup

MARKER_PREFIX = "xh"
DEFAULT_MARKER = f"{MARKER_PREFIX}TR9K7QZ"  # unique-ish alphanumeric probe
# Secondary marker with special chars to detect HTML-encoding of user input.
ENCODED_PROBE = f"{MARKER_PREFIX}Z<Q>K"


# ---------- Scope / URL processing ----------

def _domain_match(host: str, patterns: Iterable[str]) -> bool:
    host = (host or "").lower()
    for pat in patterns:
        pat = (pat or "").lower().strip()
        if not pat:
            continue
        if pat.startswith("*."):
            if host == pat[2:] or host.endswith("." + pat[2:]):
                return True
        elif host == pat:
            return True
    return False


def in_scope(url: str, allowed_domains: Iterable[str], excluded_paths: Iterable[str]) -> bool:
    """Return True if url is inside the allowed scope."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if not _domain_match(p.hostname or "", allowed_domains):
        return False
    for ex in excluded_paths or []:
        ex = (ex or "").strip()
        if ex and p.path.startswith(ex):
            return False
    return True


def normalize_url(url: str) -> str:
    """Canonicalize URL: drop fragment, sort query keys, lowercase scheme+host, remove default ports."""
    url, _ = urldefrag(url)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port and not ((scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443)):
        netloc = f"{host}:{parts.port}"
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.sort()
    return urlunsplit((scheme, netloc, parts.path or "/", urlencode(q), ""))


# ---------- Parameter discovery ----------

# Field-name patterns commonly used to store CSRF tokens across frameworks
CSRF_FIELD_PATTERNS = re.compile(
    r"^("
    r"csrf(_?token)?|_?csrf|_?token|"
    r"authenticity_token|"
    r"csrfmiddlewaretoken|"
    r"xsrf(_?token)?|"
    r"__requestverificationtoken"
    r")$",
    re.IGNORECASE,
)


def is_csrf_field(name: str) -> bool:
    return bool(name) and bool(CSRF_FIELD_PATTERNS.match(name.strip()))


@dataclass
class ParamTarget:
    url: str
    method: str
    params: List[str] = field(default_factory=list)   # names to fuzz (excludes CSRF fields)
    form_data: dict = field(default_factory=dict)     # baseline values for POST forms
    origin_url: str = ""                              # page the form was found on (for refetching CSRF)
    csrf_fields: List[str] = field(default_factory=list)  # names of CSRF hidden fields discovered
    hidden_fields: dict = field(default_factory=dict)     # hidden non-CSRF fields to preserve


def extract_get_params(url: str) -> List[str]:
    q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return [k for k, _ in q]


def extract_links_and_forms(base_url: str, html_text: str) -> Tuple[List[str], List[ParamTarget]]:
    """Return (urls, form_targets) discovered inside html_text.

    Form targets tag CSRF hidden fields separately so the engine can refresh them
    at test time instead of fuzzing them.
    """
    soup = BeautifulSoup(html_text or "", "html.parser")
    urls: List[str] = []
    for a in soup.find_all("a", href=True):
        urls.append(urljoin(base_url, a["href"]))
    for tag in soup.find_all(["link", "script", "iframe"]):
        src = tag.get("href") or tag.get("src")
        if src:
            urls.append(urljoin(base_url, src))

    forms: List[ParamTarget] = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or base_url)
        method = (form.get("method") or "GET").upper()
        params: List[str] = []
        baseline: dict = {}
        csrf_fields: List[str] = []
        hidden_fields: dict = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inp_type = (inp.get("type") or "").lower()
            value = inp.get("value") or ""
            if is_csrf_field(name):
                csrf_fields.append(name)
                hidden_fields[name] = value
                continue
            if inp_type == "hidden":
                hidden_fields[name] = value
                # hidden non-CSRF fields are preserved but also fuzzed
            params.append(name)
            baseline[name] = value or "test"
        if params:
            forms.append(ParamTarget(
                url=action, method=method, params=params, form_data=baseline,
                origin_url=base_url, csrf_fields=csrf_fields, hidden_fields=hidden_fields,
            ))
    return urls, forms


def extract_csrf_values(html_text: str, field_names: Iterable[str]) -> dict:
    """Return {name: value} for CSRF fields present in the given HTML."""
    if not html_text or not field_names:
        return {}
    soup = BeautifulSoup(html_text, "html.parser")
    wanted = {n.lower() for n in field_names}
    out = {}
    for inp in soup.find_all(["input", "textarea"]):
        n = inp.get("name")
        if n and n.lower() in wanted:
            out[n] = inp.get("value") or ""
    return out


# ---------- Reflection & context ----------

def classify_context(response_text: str, marker: str) -> str:
    """Best-effort context classification: html/attribute/javascript/encoded/none.

    Order of checks matters — encoded reflections are recognised even when they occur
    in HTML text so they are not confused with unsafe reflection.
    """
    if not response_text or not marker:
        return "none"

    # Encoded variants
    encoded_variants = [
        html.escape(marker),           # HTML entity encoded
        marker.replace("<", "&lt;"),   # bare
    ]
    for variant in encoded_variants:
        if variant != marker and variant in response_text and marker not in response_text:
            return "encoded"

    if marker not in response_text:
        # url-encoded?
        if marker.encode().hex() in response_text or f"%{ord(marker[0]):02x}" in response_text.lower():
            return "encoded"
        return "none"

    # Look at surroundings for JS / attribute contexts
    idx = response_text.find(marker)
    start = max(0, idx - 120)
    end = min(len(response_text), idx + len(marker) + 120)
    window = response_text[start:end]

    # JavaScript context: inside <script>...</script>
    lower_full = response_text.lower()
    script_open = lower_full.rfind("<script", 0, idx)
    script_close = lower_full.rfind("</script>", 0, idx)
    if script_open != -1 and script_open > script_close:
        return "javascript"

    # Attribute context: reflection inside quoted attribute value of a tag
    # find nearest '<' before marker and '>' after marker; check for '=' between
    left_lt = response_text.rfind("<", 0, idx)
    right_gt = response_text.find(">", idx)
    if left_lt != -1 and right_gt != -1:
        segment = response_text[left_lt:right_gt]
        # heuristic: marker appears inside quotes following '='
        if "=" in segment and (
            re.search(r'="[^"]*' + re.escape(marker), segment)
            or re.search(r"='[^']*" + re.escape(marker), segment)
        ):
            return "attribute"

    return "html"


def guess_severity(context: str, validated: bool) -> str:
    if validated:
        return "high"
    if context == "javascript":
        return "high"
    if context == "html":
        return "medium"
    if context == "attribute":
        return "medium"
    if context == "encoded":
        return "low"
    return "low"


def classify_finding(context: str, validated: bool) -> str:
    """Map (context, validated) -> classification label."""
    if validated:
        return "validated"
    if context == "csrf_required":
        return "csrf_token_required"
    if context == "none":
        return "false_positive"
    if context == "encoded":
        return "safely_encoded"
    if context in ("html", "attribute", "javascript"):
        return "potential"
    return "reflection_only"


# ---------- Payload building ----------

def build_probe_marker(base: str = DEFAULT_MARKER) -> str:
    return base


PAYLOADS_BY_CONTEXT = {
    "html": ['<svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>'],
    "attribute": ['" autofocus onfocus=alert(1) x="', "' onmouseover=alert(1) '"],
    "javascript": [';alert(1);//', '</script><script>alert(1)</script>'],
    "encoded": [],  # unlikely to be exploitable
}
