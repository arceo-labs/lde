"""URL fetch + HTML parse + Gemini extraction for affected npm/PyPI package names.

Given a URL to a security advisory, CVE write-up, or vulnerability blog post,
fetches the page, strips it to plain text, and asks Gemini to extract the names
of affected npm and PyPI packages.

Returns a plain list of package name strings (one per package).
"""

import concurrent.futures
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from . import log as log_mod

logger = log_mod.get('pkg_extractor')


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_FETCH_TIMEOUT_S = 30
_MAX_REDIRECTS = 5
# Same set urllib.request.HTTPRedirectHandler follows for GET.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


# RFC 6598 shared/CGNAT address space (100.64.0.0/10). Some cloud providers
# route internal services here; ipaddress.is_private/is_reserved do not flag
# it, so it needs an explicit check.
_SHARED_ADDRESS_SPACE_V4 = ipaddress.ip_network('100.64.0.0/10')


def _blocked_ip(ip):
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    if ip.is_multicast or ip.is_unspecified:
        return True
    if ip.version == 4 and ip in _SHARED_ADDRESS_SPACE_V4:
        return True
    return False


def _parse_fetch_url(url):
    """Return a parsed http(s) URL on port 80/443, or raise ValueError."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f'URL scheme {parsed.scheme!r} is not allowed (only http/https)')
    if not hostname:
        raise ValueError(f'URL has no hostname: {url}')
    if port not in (80, 443):
        raise ValueError(f'URL port {port} is not allowed (only 80 and 443)')
    return parsed, hostname, port


def _resolve_public_ips(hostname, port):
    """Resolve *hostname* once. Reject if any address is blocked; return public IPs.

    Order from getaddrinfo is preserved, duplicates dropped. Callers must try
    each address without resolving the hostname again.
    """
    try:
        addrinfos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f'Cannot resolve hostname {hostname!r}: {exc}') from exc
    public = []
    seen = set()
    for _family, _type, _proto, _canon, sockaddr in addrinfos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _blocked_ip(ip):
            raise ValueError(f'URL resolves to blocked address {ip} ({hostname})')
        key = str(ip)
        if key not in seen:
            seen.add(key)
            public.append(key)
    if not public:
        raise ValueError(f'Cannot resolve hostname {hostname!r}: no addresses')
    return public


def _checked_url(url):
    """Parse *url*, resolve once, and return (parsed, hostname, port, ips)."""
    parsed, hostname, port = _parse_fetch_url(url)
    ips = _resolve_public_ips(hostname, port)
    return parsed, hostname, port, ips


def _validate_url(url):
    """Raise ValueError if *url* targets a private/reserved/loopback address."""
    _checked_url(url)
    return url


def _request_path(parsed):
    path = parsed.path or '/'
    if parsed.query:
        path = f'{path}?{parsed.query}'
    return path


def _response_charset(resp):
    msg = EmailMessage()
    msg['content-type'] = resp.getheader('Content-Type') or 'text/html'
    return msg.get_content_charset() or 'utf-8'


def _connect_pinned(parsed, hostname, port, ips, timeout):
    """Open a socket to a validated IP and attach it to an HTTP(S) connection.

    Tries each address from the already-resolved list; does not look up
    *hostname* again. TLS uses *hostname* for SNI and certificate verification.
    """
    last_exc = None
    sock = None
    for ip in ips:
        try:
            sock = socket.create_connection((ip, port), timeout)
            break
        except OSError as exc:
            last_exc = exc
    if sock is None:
        raise last_exc if last_exc is not None else OSError('no addresses to connect')
    try:
        if parsed.scheme == 'https':
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=hostname)
            conn = http.client.HTTPSConnection(
                hostname, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(hostname, port, timeout=timeout)
    except Exception:
        sock.close()
        raise
    conn.sock = sock
    return conn


def _http_get_pinned(url, headers, timeout=_FETCH_TIMEOUT_S):
    """GET *url* by connecting only to a once-validated IP. Follow redirects.

    Each hop (including Location targets) is resolved and checked before
    connect. Redirects are followed in Python so urlopen cannot re-resolve
    DNS or land on a blocked address.
    """
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        parsed, hostname, port, ips = _checked_url(current)
        conn = _connect_pinned(parsed, hostname, port, ips, timeout)
        try:
            req_headers = dict(headers)
            req_headers['Host'] = f'[{hostname}]' if ':' in hostname else hostname
            conn.request('GET', _request_path(parsed), headers=req_headers)
            resp = conn.getresponse()
            if resp.status in _REDIRECT_STATUSES:
                location = resp.getheader('Location')
                resp.read()
                if not location:
                    raise ValueError(f'Redirect from {hostname} had no Location')
                current = urljoin(current, location)
                continue
            if resp.status >= 300:
                reason = resp.reason or str(resp.status)
                resp.read()
                raise OSError(reason)
            body = resp.read()
            return body.decode(_response_charset(resp), errors='replace')
        finally:
            conn.close()
    raise ValueError(f'Too many redirects fetching {url}')


# ---------------------------------------------------------------------------
# HTML → plain text  (identical logic to sumologic_query_generator)
# ---------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    """Extract visible text from HTML, stripping scripts/styles."""

    SKIP_TAGS = frozenset(['script', 'style', 'noscript', 'svg', 'head'])

    def __init__(self):
        super().__init__()
        self._pieces = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        if tag in ('p', 'br', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                    'li', 'tr', 'blockquote', 'pre'):
            self._pieces.append('\n')

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        if tag in ('p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                    'li', 'tr', 'blockquote', 'pre', 'table'):
            self._pieces.append('\n')

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._pieces.append(data)

    def get_text(self):
        raw = ''.join(self._pieces)
        lines = raw.split('\n')
        cleaned = [' '.join(line.split()) for line in lines if line.strip()]
        return '\n'.join(cleaned)


# Gemini 3.x Flash accepts ~1M input tokens; 400k chars is ~100k tokens.
# Advisories put the affected-package table last, so a low cap drops it.
_MAX_TEXT_CHARS = 400_000


def _cap_text(text):
    """Return (text, truncated) with text cut to _MAX_TEXT_CHARS."""
    if len(text) <= _MAX_TEXT_CHARS:
        return text, False
    return (text[:_MAX_TEXT_CHARS]
            + f'\n\n[Content truncated at {_MAX_TEXT_CHARS:,} characters]'), True


def _html_to_text(html):
    """Convert HTML to plain text suitable for LLM analysis (uncapped)."""
    parser = _TextExtractor()
    parser.feed(html)
    return parser.get_text()


def _collect_strings_from_json(obj, min_len=3, _depth=0):
    """Recursively collect human-readable string values from a JSON structure.

    Skips values that look like URLs, CSS, or internal framework keys, which
    are abundant in __NEXT_DATA__ but useless for LLM analysis.  min_len is
    kept low (3) so short package names like "@antv/g" or "vue" are retained.
    """
    if _depth > 20:
        return []
    results = []
    if isinstance(obj, str):
        s = obj.strip()
        if (len(s) >= min_len
                and not s.startswith(('http', '/', '{', '<', 'data:', 'function'))
                and '\n' not in s[:10]):
            results.append(s)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_collect_strings_from_json(v, min_len, _depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_collect_strings_from_json(item, min_len, _depth + 1))
    return results


# Script block patterns worth extracting text from even when the visible HTML
# is empty (JS-rendered / Next.js / Gatsby sites).
_SCRIPT_PATTERNS = [
    # Next.js pre-rendered page data
    re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
               re.DOTALL | re.IGNORECASE),
    # JSON-LD structured data (articles, blog posts often embed full body here)
    re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
               re.DOTALL | re.IGNORECASE),
    # Nuxt.js / generic hydration blobs
    re.compile(r'<script[^>]+id=["\']__NUXT_DATA__["\'][^>]*>(.*?)</script>',
               re.DOTALL | re.IGNORECASE),
]


def _extract_script_json_text(html):
    """Pull human-readable text out of JSON embedded in <script> blocks.

    Handles __NEXT_DATA__, application/ld+json, and __NUXT_DATA__ — the
    three most common ways SSG/SSR frameworks embed page content in the
    static HTML shell that a headless-browser-less fetch sees.
    """
    pieces = []
    for pattern in _SCRIPT_PATTERNS:
        for m in pattern.finditer(html):
            try:
                data = json.loads(m.group(1))
                strings = _collect_strings_from_json(data)
                if strings:
                    pieces.extend(strings)
                    logger.debug('_extract_script_json_text: found %d strings in %s block',
                                 len(strings), pattern.pattern[:40])
            except (json.JSONDecodeError, ValueError):
                pass
    return '\n'.join(pieces)


_USER_AGENTS = [
    # Many SSR frameworks (Next.js, Nuxt, Gatsby) serve pre-rendered HTML to
    # search crawlers even when the same URL returns an empty shell to browsers.
    # Try Googlebot first so JS-rendered advisory sites still work.
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; SecurityAdvisoryParser/1.0)',
]

_SPARSE_THRESHOLD = 200  # chars of visible text below which we retry with next UA


def _fetch_url(url):
    """Fetch *url* with SSRF checks on initial and redirect hops.

    Tries multiple user-agents in order, stopping at the first response that
    yields more than _SPARSE_THRESHOLD characters of visible text.  This handles
    JS-rendered sites (Next.js, React SPAs) that serve pre-rendered HTML to
    search crawlers but return empty shells to plain browser requests.

    Returns the best HTML string found.
    """
    last_html = ''
    last_exc = None
    for ua in _USER_AGENTS:
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,*/*',
        }
        try:
            html = _http_get_pinned(url, headers)
        except ValueError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            last_exc = exc
            continue

        text = _html_to_text(html)
        if len(text.strip()) >= _SPARSE_THRESHOLD:
            logger.debug('_fetch_url: got %d chars with UA=%r', len(text), ua[:40])
            return html
        logger.debug('_fetch_url: only %d chars with UA=%r — retrying', len(text), ua[:40])
        last_html = html  # keep as fallback

    if not last_html and last_exc:
        reason = getattr(last_exc, 'reason', last_exc)
        raise ValueError(f'Failed to fetch URL: {reason}')
    return last_html


# ---------------------------------------------------------------------------
# JSON recovery helpers (same logic as sumologic_query_generator)
# ---------------------------------------------------------------------------

def _strip_code_fence(text):
    """Remove markdown code fences that Gemini sometimes wraps output in."""
    text = text.strip()
    if text.startswith('```'):
        lines = text.split('\n')
        if lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].strip() == '```':
            lines = lines[:-1]
        text = '\n'.join(lines)
    return text


def _repair_truncated_json(text):
    """Recover a JSON array truncated mid-token by MAX_TOKENS.

    Walks the character stream to find the last fully-closed top-level array
    item, then appends the closing brackets needed to make the document
    parseable. Returns a list on success or None if unrecoverable.
    """
    brace_depth = 0
    bracket_depth = 0
    in_string = False
    escape_next = False
    last_safe_end = -1

    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
            if brace_depth == 1 and bracket_depth == 1:
                last_safe_end = i + 1
        elif ch == '[':
            bracket_depth += 1
        elif ch == ']':
            bracket_depth -= 1

    if last_safe_end == -1:
        return None

    snippet = text[:last_safe_end]
    bd = bkd = 0
    in_s = esc = False
    for ch in snippet:
        if esc:
            esc = False
            continue
        if ch == '\\' and in_s:
            esc = True
            continue
        if ch == '"':
            in_s = not in_s
            continue
        if in_s:
            continue
        if ch == '{':
            bd += 1
        elif ch == '}':
            bd -= 1
        elif ch == '[':
            bkd += 1
        elif ch == ']':
            bkd -= 1

    closing = (']' * max(0, bkd)) + ('}' * max(0, bd))
    try:
        return json.loads(snippet + closing)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Gemini prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a security researcher reviewing a software vulnerability advisory or blog post.
Your task is to extract the names of affected npm and PyPI packages mentioned in the text.

STRICT SCOPE — only include:
- npm packages (JavaScript/Node.js, published to npmjs.com)
- PyPI packages (Python, published to pypi.org)

DO NOT include:
- IP addresses, domain names, URLs, file hashes, or any other network indicators
- Operating system packages (apt, rpm, brew, etc.)
- Maven, NuGet, RubyGems, Go modules, Cargo, or any other ecosystem
- CVE identifiers, version ranges, or standalone version numbers
- Generic tool names, binary names, or framework names that are not package manager entries
- Invented or hallucinated package names

Return ONLY a JSON array of objects. Each object has exactly these fields:
  "name"      - the exact package name as it appears on npm or PyPI
                (e.g. "async-waterfall", "@babel/core", "requests", "pillow")
  "ecosystem" - exactly "npm" or "pypi"
List each package once, even if several versions are affected.

If no qualifying packages are mentioned, return an empty array: []
Return valid JSON only — no markdown fences, no commentary outside the JSON.
"""

_USER_PROMPT = """\
Extract all affected npm and PyPI package names from the following text:

{article_text}
"""

_USER_PROMPT_PART = """\
This is part {part} of {parts} of one document. Its first line repeats the
document's first line (a title or column header) for context.

Extract all affected npm and PyPI package names from the following text:

{article_text}
"""

# Long, repetitive lists (hundreds of near-identical @scope/* names) lose
# recall in a single call: 19 of 481 antv packages were dropped. Split them.
_CHUNK_THRESHOLD_LINES = 200
_CHUNK_LINES = 150
_CHUNK_WORKERS = 4
# Bound what one upload can cost: at most 20 calls (3,000 non-blank lines),
# a short header copy per chunk, and a deadline under the UI's 180 s poll.
_MAX_CHUNKS = 20
_CHUNK_HEAD_CHARS = 500
_EXTRACT_DEADLINE_S = 170


def connection_status(api_key, model='gemini-3.8-flash', timeout=10):
    """Validate the configured Gemini API key against the configured model.

    Calls ``GET /v1beta/models/{model}`` — Google's model-metadata lookup,
    documented as free of charge (it does no generation) — to confirm the
    key is accepted, is authorized for the Generative Language API, and the
    configured model exists and supports ``generateContent``. This mirrors
    ``dtrack_client.connection_status``: it validates only the server-side
    saved settings (never a key/model from the request body), costs nothing
    to run, and never logs or returns the raw key.

    Returns::

        {
          'configured': bool,           # a key is present
          'ok': bool,                   # key accepted and model usable
          'model': str | None,          # resource name Google reports, e.g. "models/gemini-3.8-flash"
          'supports_generate': bool,    # 'generateContent' in supportedGenerationMethods
          'message': str,               # human-readable, never leaks the raw key
        }
    """
    key = (api_key or '').strip()
    if not key:
        return {'configured': False, 'ok': False, 'model': None,
                'supports_generate': False,
                'message': 'No Gemini API key configured.'}

    model = (model or 'gemini-3.8-flash').strip()
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{urllib.parse.quote(model)}'
    req = urllib.request.Request(url, headers={'x-goog-api-key': key}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')[:300]
        try:
            err_status = json.loads(detail).get('error', {}).get('status')
        except (json.JSONDecodeError, AttributeError):
            err_status = None
        logger.warning('Gemini key test -> HTTP %d (%s)', exc.code, err_status)
        if exc.code in (400, 401, 403):
            return {'configured': True, 'ok': False, 'model': None,
                    'supports_generate': False,
                    'message': 'API key rejected by Google. Check that it is valid, '
                               'not restricted to a different API, and not reported leaked.'}
        if exc.code == 404:
            return {'configured': True, 'ok': False, 'model': None,
                    'supports_generate': False,
                    'message': f'Model "{model}" not found. Check Gemini model in Settings.'}
        if exc.code == 429:
            return {'configured': True, 'ok': False, 'model': None,
                    'supports_generate': False,
                    'message': 'Key is valid but rate-limited (quota exhausted). Try again shortly.'}
        return {'configured': True, 'ok': False, 'model': None,
                'supports_generate': False,
                'message': f'Google returned HTTP {exc.code} validating the key.'}
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = getattr(exc, 'reason', exc)
        logger.warning('Gemini key test -> network error: %s', log_mod.safe(str(reason)))
        return {'configured': True, 'ok': False, 'model': None,
                'supports_generate': False,
                'message': 'Could not reach the Gemini API. Verify network connectivity.'}

    methods = data.get('supportedGenerationMethods') or []
    supports_generate = 'generateContent' in methods
    name = data.get('name')
    message = f'Key valid; model "{model}" is reachable.'
    if not supports_generate:
        message += ' Warning: model does not support generateContent — extraction will fail.'
    return {'configured': True, 'ok': True, 'model': name,
            'supports_generate': supports_generate, 'message': message}


def _call_gemini(text, api_key, model='gemini-3.8-flash', part=None):
    """Call Gemini and return a list of {name, ecosystem} dicts.

    *part* is (k, n) when *text* is chunk k of n from _split_chunks.
    """
    if part:
        prompt = _USER_PROMPT_PART.format(part=part[0], parts=part[1], article_text=text)
    else:
        prompt = _USER_PROMPT.format(article_text=text)
    payload = json.dumps({
        'system_instruction': {'parts': [{'text': _SYSTEM_PROMPT}]},
        'contents': [{'role': 'user', 'parts': [{'text': prompt}]}],
        'generationConfig': {
            'responseMimeType': 'application/json',
            'maxOutputTokens': 65536,
            'thinkingConfig': {'thinkingLevel': 'low'},
        },
    }).encode('utf-8')

    url = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    req = urllib.request.Request(url, data=payload, headers={
        'Content-Type': 'application/json',
        'x-goog-api-key': api_key,
    }, method='POST')

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')[:300]
        raise ValueError(f'Gemini API error {exc.code}: {detail}') from exc
    except TimeoutError as exc:
        raise ValueError(
            f'Gemini call timed out after 300s (model={model}). '
            'Try a shorter article or paste the package list manually.'
        ) from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, 'reason', exc)
        if isinstance(reason, TimeoutError) or 'timed out' in str(reason).lower():
            raise ValueError(
                f'Gemini call timed out after 300s (model={model}). '
                'Try a shorter article or paste the package list manually.'
            ) from exc
        raise ValueError(f'Gemini API unreachable: {exc.reason}') from exc

    duration_ms = (time.monotonic() - t0) * 1000

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError('Gemini returned non-JSON envelope') from exc

    candidates = data.get('candidates') or []
    if not candidates:
        raise ValueError('Gemini returned no candidates')

    finish_reason = candidates[0].get('finishReason')
    usage = data.get('usageMetadata') or {}
    logger.info('Gemini call: finishReason=%s promptTokens=%s outputTokens=%s thoughtsTokens=%s (%.0fms)',
                log_mod.safe(str(finish_reason)),
                int(usage.get('promptTokenCount') or 0),
                int(usage.get('candidatesTokenCount') or 0),
                int(usage.get('thoughtsTokenCount') or 0),
                duration_ms)
    parts = (candidates[0].get('content') or {}).get('parts') or []
    if not parts:
        raise ValueError('Gemini candidate has no content parts')

    text_out = _strip_code_fence(''.join(p.get('text', '') for p in parts))

    parsed = None
    try:
        parsed = json.loads(text_out)
    except json.JSONDecodeError:
        if finish_reason == 'MAX_TOKENS':
            parsed = _repair_truncated_json(text_out)
            if parsed:
                logger.warning('Gemini output was truncated (MAX_TOKENS); recovered partial result')
            else:
                raise ValueError(
                    'Gemini hit the output token limit and the response could not be recovered. '
                    'Try a shorter article or paste the package list manually.'
                )
        else:
            # Last-resort: find the JSON array inside the text
            start = text_out.find('[')
            end = text_out.rfind(']')
            if start != -1 and end > start:
                try:
                    parsed = json.loads(text_out[start:end + 1])
                except json.JSONDecodeError as exc:
                    raise ValueError('Could not parse Gemini JSON response') from exc
            else:
                raise ValueError('Gemini response did not contain a JSON array')

    if not isinstance(parsed, list):
        raise ValueError(f'Gemini returned unexpected shape: {type(parsed).__name__}')

    cleaned = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or '').strip()
        ecosystem = str(item.get('ecosystem') or '').strip().lower()
        if not name:
            continue
        if ecosystem not in ('npm', 'pypi'):
            ecosystem = ''
        cleaned.append({'name': name, 'ecosystem': ecosystem})
    return cleaned


def _split_chunks(text):
    """Split long text into _CHUNK_LINES-line chunks; short text is one chunk.

    Blank lines are dropped first. Every chunk after the first starts with
    the document's first line (cut to _CHUNK_HEAD_CHARS), so a CSV header or
    advisory title stays in view. More than _MAX_CHUNKS raises ValueError
    before any Gemini call is made.
    """
    lines = [line for line in text.split('\n') if line.strip()]
    if not lines:
        return []
    if len(lines) <= _CHUNK_THRESHOLD_LINES:
        return ['\n'.join(lines)]
    count = -(-len(lines) // _CHUNK_LINES)
    if count > _MAX_CHUNKS:
        raise ValueError(
            f'Package list too long: {len(lines):,} lines. The limit is '
            f'{_MAX_CHUNKS * _CHUNK_LINES:,} lines per extraction; split the file.')
    head = lines[0][:_CHUNK_HEAD_CHARS]
    chunks = []
    for start in range(0, len(lines), _CHUNK_LINES):
        part = lines[start:start + _CHUNK_LINES]
        if start:
            part = [head] + part
        chunks.append('\n'.join(part))
    return chunks


def _extract_packages(text, api_key, model='gemini-3.8-flash'):
    """Extract packages from *text*, in parallel chunks when it is long.

    Any failed chunk raises, so a short list is never returned silently.
    Results are merged in document order, each package once.
    """
    chunks = _split_chunks(text)
    if not chunks:
        return []
    if len(chunks) == 1:
        return _call_gemini(chunks[0], api_key, model=model)

    total = len(chunks)
    logger.info('package_extractor: splitting into %d chunks', total)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(_CHUNK_WORKERS, total))
    try:
        futures = [pool.submit(_call_gemini, chunk, api_key, model, (i + 1, total))
                   for i, chunk in enumerate(chunks)]
        done, pending = concurrent.futures.wait(
            futures, timeout=_EXTRACT_DEADLINE_S,
            return_when=concurrent.futures.FIRST_EXCEPTION)
        for f in done:
            if f.exception() is not None:
                raise f.exception()
        if pending:
            raise ValueError(
                f'Extraction did not finish within {_EXTRACT_DEADLINE_S}s '
                f'({len(done)} of {total} chunks done). Try a shorter file.')
        results = [f.result() for f in futures]
    finally:
        # Queued chunks never start; calls already in flight end on their own timeout.
        pool.shutdown(wait=False, cancel_futures=True)

    merged, seen = [], set()
    for items in results:
        for item in items:
            key = item['name'].lower()
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged


# ---------------------------------------------------------------------------
# Task entry point (called by task_queue.submit)
# ---------------------------------------------------------------------------

def run(set_stage, url, gemini_api_key, model='gemini-3.8-flash'):
    """Full pipeline: fetch → parse → Gemini → list of package name strings.

    Returns a plain list of package name strings suitable for joining with
    newlines into the search textarea.
    """
    set_stage('fetching')
    logger.info('package_extractor: fetching %s', log_mod.safe(url))
    html = _fetch_url(url)

    set_stage('parsing')
    text = _html_to_text(html)
    logger.debug('package_extractor: regular HTML extraction yielded %d chars', len(text))

    if len(text.strip()) < _SPARSE_THRESHOLD:
        # Visible HTML is sparse — the page is likely JS-rendered. Fall back to
        # extracting text from embedded JSON script blocks (__NEXT_DATA__, etc.).
        script_text = _extract_script_json_text(html)
        if script_text:
            logger.info('package_extractor: supplementing sparse HTML (%d chars) with '
                        '%d chars from embedded script JSON', len(text.strip()), len(script_text))
            text = script_text
        else:
            logger.warning('package_extractor: very sparse text (%d chars) and no '
                           'script JSON found — proceeding with best available content',
                           len(text.strip()))

    text, truncated = _cap_text(text)
    logger.info('package_extractor: sending %d chars to Gemini (truncated=%s)', len(text), truncated)

    set_stage('gemini')
    packages = _extract_packages(text, gemini_api_key, model=model)
    logger.info('package_extractor: extracted %d package(s) from %s',
                len(packages), log_mod.safe(url))

    set_stage('done')
    # Return just the names — the frontend joins them with newlines into the textarea.
    return [p['name'] for p in packages]


def run_from_text(set_stage, raw_content, filename, gemini_api_key, model='gemini-3.8-flash'):
    """Extract packages from raw file content (client-side upload path).

    Treats the content as HTML if the filename ends in .html/.htm, otherwise
    as plain text.  Applies the same __NEXT_DATA__ fallback as run().
    """
    set_stage('parsing')
    fname_lower = filename.lower() if filename else ''
    is_html = fname_lower.endswith(('.html', '.htm', '.mhtml', '.mht', '.eml'))

    if is_html:
        text = _html_to_text(raw_content)
        logger.debug('run_from_text: HTML extraction yielded %d chars from %s',
                     len(text), log_mod.safe(filename))
        if len(text.strip()) < _SPARSE_THRESHOLD:
            script_text = _extract_script_json_text(raw_content)
            if script_text:
                logger.info('run_from_text: supplementing sparse HTML with %d chars '
                            'from embedded script JSON', len(script_text))
                text = script_text
    else:
        text = raw_content
        logger.debug('run_from_text: plain text, %d chars from %s',
                     len(text), log_mod.safe(filename))

    text, truncated = _cap_text(text)
    logger.info('run_from_text: sending %d chars to Gemini (truncated=%s)', len(text), truncated)

    set_stage('gemini')
    packages = _extract_packages(text, gemini_api_key, model=model)
    logger.info('run_from_text: extracted %d package(s) from %s',
                len(packages), log_mod.safe(filename))

    set_stage('done')
    return [p['name'] for p in packages]
