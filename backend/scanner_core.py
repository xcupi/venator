"""Core scanner logic — reusable by API-embedded worker and standalone scanner service.

Functions here are pure / stateless where possible so they are testable.
"""
from __future__ import annotations

import re
import html
from dataclasses import dataclass, field
from typing import Iterable, List, Set, Tuple
from urllib.parse import (
    urlparse, urljoin, urlsplit, urlunsplit, parse_qsl, urlencode, urldefrag, quote,
)

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
    if context == "header":
        return "low"
    return "low"


def classify_finding(context: str, validated: bool) -> str:
    """Map (context, validated) -> classification label.

    Label semantics:
      - ``validated``         — browser worker triggered a real alert() with a
                                context-specific payload; XSS confirmed.
      - ``potential``         — marker landed in a rendering sink (html /
                                attribute / javascript). NOT confirmed XSS.
      - ``safely_encoded``    — reflection observed but the target HTML-escapes
                                the input; not exploitable via this vector.
      - ``csrf_token_required`` — a required CSRF token could not be refreshed;
                                probe was not sent (no bypass attempted).
      - ``reflection_only``   — reflection was observed but the rendering
                                context is not a body-level XSS sink. Currently
                                emitted for (a) body truncation before the
                                marker could be observed (context ``unknown``),
                                and (b) reflection into a response header
                                (context ``header``) — a header echo is not
                                directly executable as XSS but is recorded so
                                a human reviewer can decide.
      - ``false_positive``    — marker was not observed in the response body,
                                the baseline (pre-injection) response already
                                contained the marker (so any probe hit is
                                coincidental / server-injected), or the
                                context is an unrecognised label.
    """
    if validated:
        return "validated"
    if context == "csrf_required":
        return "csrf_token_required"
    if context in ("html", "attribute", "javascript"):
        return "potential"
    if context == "encoded":
        return "safely_encoded"
    if context == "unknown":
        return "reflection_only"
    if context == "header":
        return "reflection_only"
    # "none" or any unrecognised future context — no reflection observed.
    return "false_positive"


# ---------- Baseline diff + header-reflection guard ----------

def marker_in_header_values(headers, marker: str) -> bool:
    """Return True if ``marker`` appears in any response-header VALUE.

    Accepts either a list of ``(name, value)`` tuples (the shape returned by
    scanner_engine._fetch) or a mapping. Multi-value headers (e.g. Set-Cookie)
    are supported via the list-of-tuples form. Header NAMES are ignored on
    purpose — the marker is a random-ish alphanumeric string; no legitimate
    server would embed it in a header name. Comparison is case-sensitive
    because the marker itself is a mixed-case token.
    """
    if not marker or not headers:
        return False
    if isinstance(headers, dict):
        iterable = headers.items()
    else:
        iterable = headers
    for _name, value in iterable:
        if marker in (value or ""):
            return True
    return False


def apply_baseline_and_header_context(
    context: str,
    reflected: bool,
    truncated: bool,
    marker: str,
    probe_headers,
    baseline_body,
    baseline_headers,
):
    """Pure post-classification pass: fold in the pre-injection baseline and
    detect header-only reflection. Returns ``(context, reflected)``.

    Rules — applied in order:

    1. **Truncation short-circuit.** If ``truncated=True`` and body reflection
       is not established (``reflected=False``), the caller has already set
       ``context = "unknown"``. Do not run baseline / header logic against a
       truncated response — a header seen in a truncated prefix could still be
       misleading, and the ``reflection_only`` (unknown) label already captures
       the "we don't know" state. Returned unchanged.

    2. **Baseline pollution.** If a baseline response is available AND the
       marker appears in the baseline body OR any baseline header value, then
       any subsequent probe-hit on the same URL cannot be attributed to our
       injection (it is server-injected or coincidental). Downgrade to
       ``("none", False)`` so ``classify_finding`` maps to ``false_positive``.

    3. **Header-only reflection.** If body reflection is ``"none"`` (marker
       genuinely not in probe body) but the marker appears in a probe response
       header AND was NOT in a baseline header of the same URL, promote to
       ``("header", True)``. ``classify_finding`` maps this to
       ``reflection_only`` because a header echo is not directly executable as
       XSS in the response body's rendering context.

    4. Otherwise return input unchanged. Body-level classifications
       (``html`` / ``attribute`` / ``javascript`` / ``encoded``) are NEVER
       overridden by header reflection — the body signal is stronger and we
       do not want to double-count.

    Baseline is optional: when ``baseline_body is None`` (baseline was not
    fetched, e.g. for CSRF-protected POSTs), rules 2 and 3 that require a
    baseline naturally reduce to no-ops.
    """
    # Rule 1: never touch a truncated / unknown result.
    if truncated and not reflected:
        return context, reflected

    have_baseline = baseline_body is not None

    # Rule 2: baseline pollution → false positive.
    if have_baseline:
        if (marker in (baseline_body or "")) or marker_in_header_values(baseline_headers, marker):
            return "none", False

    # Rule 3: header-only reflection (only when body reflection is 'none').
    if context == "none" and marker_in_header_values(probe_headers, marker):
        # If baseline is unavailable OR baseline headers do not already echo
        # the marker, treat as header reflection.
        if not have_baseline or not marker_in_header_values(baseline_headers, marker):
            return "header", True

    # Rule 4: everything else unchanged.
    return context, reflected


# ---------- Injection locations (beyond query/form params) ----------
#
# A single scan probes several injection LOCATIONS per discovered URL. Query
# and form-body parameters keep their bare name as the Finding.param value
# (unchanged, backwards compatible). The additional locations added for
# reflected-XSS coverage are encoded into Finding.param with a "<kind>:<name>"
# prefix so the value stays human-readable, keeps per-(url,method,param,context)
# dedup working with no schema change, and lets the browser validator rebuild
# the exact request that produced the reflection.

HEADER_LOCATION = "header"
COOKIE_LOCATION = "cookie"
PATH_LOCATION = "path"
QUERY_LOCATION = "query"

# Marker used inside the param label for a path-segment injection. The value is
# appended as a trailing path segment, so there is a single well-known label.
PATH_PARAM = f"{PATH_LOCATION}:append"

# Request headers most commonly reflected into responses (error pages,
# "you came from" banners, analytics debug output, virtual-host routing, ...).
# Case is preserved as sent. User-Agent is included because many apps echo it.
DEFAULT_FUZZ_HEADERS: List[str] = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
]


def header_param_label(name: str) -> str:
    return f"{HEADER_LOCATION}:{name}"


def cookie_param_label(name: str) -> str:
    return f"{COOKIE_LOCATION}:{name}"


def decode_injection_location(param: str) -> Tuple[str, str]:
    """Return ``(kind, name)`` for a Finding.param value.

    ``kind`` is one of ``header`` / ``cookie`` / ``path`` / ``query``. Bare
    names (no recognised prefix) decode to ``("query", name)`` — this is the
    established convention for query/form params and keeps old findings working.
    """
    if not param:
        return QUERY_LOCATION, param
    for kind in (HEADER_LOCATION, COOKIE_LOCATION, PATH_LOCATION):
        prefix = kind + ":"
        if param.startswith(prefix):
            return kind, param[len(prefix):]
    return QUERY_LOCATION, param


def resolve_fuzz_headers(names: Iterable[str] | None) -> List[str]:
    """Normalise a configured header-name list, falling back to the defaults.

    Blank / whitespace-only entries are dropped; duplicates (case-insensitive)
    are collapsed while preserving first-seen order.
    """
    source = list(names) if names else list(DEFAULT_FUZZ_HEADERS)
    out: List[str] = []
    seen: Set[str] = set()
    for n in source:
        n = (n or "").strip()
        if not n or n.lower() in seen:
            continue
        seen.add(n.lower())
        out.append(n)
    return out


def normalize_cookie_names(names: Iterable[str] | None) -> List[str]:
    """Normalise a configured cookie-name list (blanks dropped, deduped)."""
    out: List[str] = []
    seen: Set[str] = set()
    for n in list(names or []):
        n = (n or "").strip()
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def inject_path_marker(url: str, value: str) -> str:
    """Return ``url`` with ``value`` appended as a trailing path segment.

    Query and fragment are preserved. ``value`` is percent-encoded so the
    resulting string is a valid URL. Used both for the marker probe and for the
    per-URL path baseline (with a neutral placeholder value).
    """
    parts = urlsplit(url)
    path = parts.path or "/"
    seg = quote(value, safe="")
    newpath = path + seg if path.endswith("/") else path + "/" + seg
    return urlunsplit((parts.scheme, parts.netloc, newpath, parts.query, ""))


# ---------- Payload building ----------

def build_probe_marker(base: str = DEFAULT_MARKER) -> str:
    return base


PAYLOADS_BY_CONTEXT = {
    "html": ['<svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>'],
    "attribute": ['" autofocus onfocus=alert(1) x="', "' onmouseover=alert(1) '"],
    "javascript": [';alert(1);//', '</script><script>alert(1)</script>'],
    "encoded": [],  # unlikely to be exploitable
}
