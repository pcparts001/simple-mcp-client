#!/usr/bin/env python3
"""
MCP Server Tester
A CLI script to quickly verify the implemented MCP Server (mcpServer.py) from another environment.
Runs on the standard library only; does not use an LLM or function calling.

OAuth 2.1 + PKCE support (optional):
  Only when oauth.enabled=true in mcp_tester_config.json, it performs the
  Authorization Code Flow (+PKCE) with the IdP and attaches the obtained
  Bearer token to all requests. When disabled, it runs unauthenticated as before.

Usage:
    python3 mcpTester.py [URL]

Examples:
    python3 mcpTester.py                              # Check http://localhost:9000
    python3 mcpTester.py http://localhost:9000        # Specify the URL explicitly
    python3 mcpTester.py http://192.168.1.10:9000     # Verify a server in another environment
    MCP_SERVER_URL=http://host:9000 python3 mcpTester.py   # Specify via environment variable

Exit code: all passed=0 / any failure=1
"""

import sys
import os
import re
import json
import time
import base64
import hashlib
import secrets
import threading
import webbrowser
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


# --- Color output (omit escape sequences when not a TTY) ---
_USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t):
    return _c("92", t)


def red(t):
    return _c("91", t)


def cyan(t):
    return _c("96", t)


def yellow(t):
    return _c("93", t)


def bold(t):
    return _c("1", t)


# JSON-RPC standard error code meanings
JSONRPC_ERRORS = {
    -32700: "Parse error",
    -32600: "Invalid Request",
    -32601: "Method not found",
    -32602: "Invalid params",
    -32603: "Internal error",
}


# ===========================================================================
# OAuth 2.1 + PKCE client (standard library only)
# ===========================================================================

def generate_pkce():
    """Generate a PKCE pair (code_verifier, code_challenge) using S256."""
    verifier = secrets.token_urlsafe(64)  # 43-128 characters
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _format_http_error(e, max_body=500):
    """Render an urllib HTTPError into a diagnostic string: status line plus
    the response body (truncated) and a few useful headers. Without this, the
    body of 4xx/5xx responses is silently discarded, hiding the server's
    explanation of *why* a request failed (e.g. the reason behind an HTTP 500).
    """
    try:
        body = e.read().decode("utf-8", errors="replace").strip()
    except Exception:
        body = ""
    if len(body) > max_body:
        body = body[:max_body] + f" ... ({len(body)} bytes total)"
    parts = [f"HTTP {e.code} {e.reason}"]
    interesting = ("WWW-Authenticate", "Content-Type", "Server",
                   "X-Request-Id", "X-Correlation-Id")
    hdrs = [f"{name}: {e.headers.get(name)}" for name in interesting
            if e.headers.get(name)]
    if hdrs:
        parts.append("headers={{{}}}".format(", ".join(hdrs)))
    if body:
        parts.append(f"body={body}")
    return " | ".join(parts)


def fetch_as_metadata(issuer, timeout=15):
    """Fetch the IdP's metadata.
    Tries RFC 8414 (oauth-authorization-server), and falls back to
    OIDC Discovery (openid-configuration) on failure.
    (Okta/Auth0 use the former; Duo SSO uses the latter)
    """
    base = issuer.rstrip("/")
    candidates = [
        base + "/.well-known/oauth-authorization-server",  # RFC 8414
        base + "/.well-known/openid-configuration",        # OIDC Discovery
    ]
    last_error = None
    for url in candidates:
        print(f"   [debug] trying AS metadata: {url}")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = _format_http_error(e)
            print(f"   [debug] -> {detail}, trying next candidate...")
            last_error = RuntimeError(f"{detail} at {url}")
        except urllib.error.URLError as e:
            print(f"   [debug] -> {e.reason}, trying next candidate...")
            last_error = RuntimeError(f"Failed to fetch ({e.reason}) at {url}")
    raise last_error or RuntimeError("Failed to fetch AS metadata from all candidates")


def register_client(registration_endpoint, redirect_uri, scope,
                    client_name="mcpTester",
                    token_endpoint_auth_method="none",
                    initial_access_token="", timeout=30):
    """Register a new OAuth client via RFC 7591 Dynamic Client Registration.

    POSTs a JSON registration request to the AS's registration_endpoint and
    returns the parsed registration response dict (containing at least
    client_id, plus client_secret / client_id_issued_at /
    client_secret_expires_at when the AS issues them).

    Fixed metadata (tool behavior):
      grant_types=["authorization_code"], response_types=["code"]
    Derivable from existing config:
      redirect_uris=[redirect_uri], scope=scope
    Customizable via caller (defaults shown):
      client_name, token_endpoint_auth_method
    Optional Initial Access Token (RFC 7591 §3.2.1):
      sent as Authorization: Bearer <initial_access_token> when provided.
    """
    metadata = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "scope": scope,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if initial_access_token:
        headers["Authorization"] = f"Bearer {initial_access_token}"

    data = json.dumps(metadata).encode("utf-8")
    req = urllib.request.Request(
        registration_endpoint, data=data, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        hint = ""
        if e.code in (401, 403):
            hint = (" (hint: AS may require an Initial Access Token "
                    "— set oauth.dcr_options.initial_access_token)")
        raise RuntimeError(
            f"DCR endpoint returned HTTP {e.code}: {detail[:300]}{hint}"
        )
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to reach DCR endpoint ({e.reason})")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise RuntimeError(f"DCR returned non-JSON body: {body[:300]}")
    if not payload.get("client_id"):
        raise RuntimeError(f"DCR response missing client_id: {payload}")
    return payload


# ---------------------------------------------------------------------------
# [1] RFC 9728: discover the IdP (authorization server) from the protected
#     resource (the MCP server) when `issuer` is not configured.
# ---------------------------------------------------------------------------

def fetch_protected_resource_metadata(resource_url, timeout=15):
    """[Route A] Fetch the RFC 9728 protected resource metadata document.
    GET {resource_url}/.well-known/oauth-protected-resource and return the JSON.
    """
    base = resource_url.rstrip("/")
    url = base + "/.well-known/oauth-protected-resource"
    print(f"   [discover] trying protected resource metadata: {url}")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{_format_http_error(e)} at {url}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch ({e.reason}) at {url}")


def _extract_issuer_from_protected_metadata(metadata):
    """Pull the authorization server (issuer) URI out of RFC 9728 metadata,
    using the first entry of `authorization_servers`.
    """
    if not isinstance(metadata, dict):
        raise ValueError("Protected resource metadata is not a JSON object")
    servers = metadata.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        raise ValueError("Protected resource metadata has no 'authorization_servers'")
    issuer = servers[0].strip() if isinstance(servers[0], str) else ""
    if not issuer:
        raise ValueError("'authorization_servers' is present but empty")
    return issuer


def _probe_401_resource_metadata(resource_url, timeout=15):
    """[Route B fallback] Trigger a 401 by sending an unauthenticated JSON-RPC
    `initialize`, read the `WWW-Authenticate` header to find a
    `resource_metadata` URL, and fetch that metadata document. Returns the JSON.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "mcpTester", "version": "1.0.0"},
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        resource_url.rstrip("/"),
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise RuntimeError(
                f"Expected 401 challenge but got {_format_http_error(e)}"
            )
        www_auth = e.headers.get("WWW-Authenticate", "")
        if not www_auth:
            raise RuntimeError(
                "401 returned without a WWW-Authenticate header "
                f"(response: {_format_http_error(e)})"
            )
        # resource_metadata="https://..."  or  resource_metadata=https://...
        match = re.search(
            r'resource_metadata=("(?P<q>[^"]+)"|(?P<b>[^,\s]+))', www_auth
        )
        if not match:
            raise RuntimeError("WWW-Authenticate has no resource_metadata parameter")
        meta_url = match.group("q") or match.group("b")
        print(f"   [discover] resource_metadata pointed to: {meta_url}")
        req2 = urllib.request.Request(meta_url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req2, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e2:
            raise RuntimeError(f"{_format_http_error(e2)} at {meta_url}")
        except urllib.error.URLError as e2:
            raise RuntimeError(f"Failed to fetch ({e2.reason}) at {meta_url}")
    # No 401 raised -> the resource is not protected through this path
    raise RuntimeError("No 401 challenge received (resource may be public)")


def discover_issuer(resource_url, timeout=15):
    """Discover the authorization server (issuer) URI from the protected
    resource (MCP server) per RFC 9728. Used only when `issuer` is not set.

    Order:
      A) GET {resource_url}/.well-known/oauth-protected-resource  (canonical)
      B) Trigger a 401 and follow the WWW-Authenticate resource_metadata hint

    Returns the discovered issuer URI. Raises if neither route yields one.
    """
    resource = resource_url.rstrip("/")
    print(f"   [discover] issuer not configured; discovering from resource: {resource}")

    # Route A: canonical well-known endpoint
    try:
        metadata = fetch_protected_resource_metadata(resource, timeout)
        issuer = _extract_issuer_from_protected_metadata(metadata)
        print(f"   {green('[discover] found authorization server via RFC 9728:')} {issuer}")
        return issuer
    except Exception as e:
        print(f"   {yellow('[discover] route A failed')} ({e})")

    # Route B: 401 challenge via WWW-Authenticate resource_metadata
    print(f"   {yellow('[discover] falling back to 401 challenge (WWW-Authenticate)')}")
    metadata = _probe_401_resource_metadata(resource, timeout)
    issuer = _extract_issuer_from_protected_metadata(metadata)
    print(f"   {green('[discover] found authorization server via 401 challenge:')} {issuer}")
    return issuer


class _CallbackHandler(BaseHTTPRequestHandler):
    """Temporary HTTP handler (loopback) to receive the authorization code."""

    def do_GET(self):
        parsed = urlparse(self.path)
        self.server.auth_params = parse_qs(parsed.query)
        code = self.server.auth_params.get("code", [""])[0]
        err = self.server.auth_params.get("error", [""])[0]
        if code:
            body = (b"<html><body><h2>Authentication successful.</h2>"
                    b"<p>You can close this tab and return to the terminal.</p>"
                    b"</body></html>")
        else:
            body = (b"<html><body><h2>Authentication failed: " + err.encode()
                    + b"</h2></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def wait_for_callback(redirect_uri, expected_state, timeout=300):
    """Start a loopback server and wait for the authorization code via the IdP redirect."""
    parsed = urlparse(redirect_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 8080

    httpd = HTTPServer((host, port), _CallbackHandler)
    httpd.auth_params = None
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    started = time.time()
    while httpd.auth_params is None and time.time() - started < timeout:
        time.sleep(0.2)
    httpd.shutdown()
    thread.join(timeout=5)

    if httpd.auth_params is None:
        raise TimeoutError("Authorization callback timed out")

    params = httpd.auth_params
    if params.get("state", [""])[0] != expected_state:
        raise ValueError("State mismatch (possible CSRF attack)")
    if "error" in params:
        err = params.get("error_description", params["error"])[0]
        raise ValueError(f"Authorization error: {err}")
    code = params.get("code", [""])[0]
    if not code:
        raise ValueError("No authorization code received")
    return code


def exchange_token(token_endpoint, redirect_uri, client_id, code, code_verifier,
                   client_secret="", resource="", timeout=30):
    """Exchange the authorization code + PKCE verifier for an access token.
    If client_secret is provided, send as a confidential client using HTTP Basic auth.
    Otherwise, send as a public client (PKCE only) with client_id in the body.
    If resource is provided (RFC 8707), include it in the token request as well.
    ASes that mandate audience binding (e.g. Duo) require the same `resource`
    here that was sent in the authorization request, else they return
    invalid_target.
    """
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if client_secret:
        # Confidential client: send client_id in the Basic auth header
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    else:
        # Public client: send client_id in the body
        params["client_id"] = client_id
    if resource:
        params["resource"] = resource

    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(token_endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Token endpoint returned HTTP {e.code}: {detail[:300]}")
    if "access_token" not in payload:
        raise RuntimeError(f"No access_token in response: {payload}")
    return payload["access_token"]


class OAuthClient:
    """OAuth 2.1 public client (PKCE only, no client_secret required)."""

    def __init__(self, oauth_config, resource_url="", timeout=15, config_path=""):
        self.enabled = bool(oauth_config.get("enabled", False))
        self.issuer = (oauth_config.get("issuer") or "").strip()
        self.client_id = (oauth_config.get("client_id") or "").strip()
        self.client_secret = (oauth_config.get("client_secret") or "").strip()
        self.redirect_uri = (oauth_config.get("redirect_uri")
                             or "http://localhost:8080/callback")
        self.scope = oauth_config.get("scope") or "openid profile"
        self.send_resource = bool(oauth_config.get("send_resource", False))
        self.dcr = bool(oauth_config.get("dcr", False))
        self.dcr_options = oauth_config.get("dcr_options") or {}
        self.config_path = config_path or ""
        # When dcr=true: if client_id is already configured (e.g. saved from a
        # prior DCR run), it is reused and DCR is skipped in authenticate().
        # Only a missing client_id triggers a fresh registration.
        self.resource_url = resource_url or ""
        self.timeout = timeout
        self.access_token = None

    def authenticate(self):
        """Obtain and return a token via the Authorization Code Flow + PKCE."""
        # Debug: print the loaded config values and the URL being accessed
        issuer_display = (self.issuer or
                          "(not set — will auto-discover via RFC 9728)")
        print(f"   [config] issuer        = {issuer_display}")
        if self.dcr:
            if self.client_id:
                print("   [config] client_id     = (configured; DCR will be skipped)")
                print("   [config] client_secret = (configured; DCR will be skipped)")
            else:
                print("   [config] client_id     = (not set; will register via DCR)")
                print("   [config] client_secret = (not set; will register via DCR)")
        else:
            print(f"   [config] client_id     = {self.client_id}")
            print(f"   [config] client_secret = {'(set)' if self.client_secret else '(none)'}")
        print(f"   [config] redirect_uri  = {self.redirect_uri}")
        print(f"   [config] scope         = {self.scope}")
        if self.send_resource:
            if not self.resource_url:
                raise ValueError(
                    "send_resource is enabled but no resource URL (server URL) "
                    "is available to send"
                )
            print(f"   [config] resource      = {self.resource_url}  (RFC 8707)")

        # If issuer is not configured, discover it from the resource (RFC 9728)
        if not self.issuer:
            if not self.resource_url:
                raise ValueError(
                    "issuer is not configured and no resource URL is available "
                    "to discover it from"
                )
            self.issuer = discover_issuer(self.resource_url, self.timeout)

        metadata = fetch_as_metadata(self.issuer, self.timeout)
        authorize_ep = metadata.get("authorization_endpoint")
        token_ep = metadata.get("token_endpoint")
        if not authorize_ep or not token_ep:
            raise ValueError("AS metadata is missing authorization/token endpoint")

        # Dynamic Client Registration (RFC 7591): when enabled and no client_id
        # is configured yet, register a fresh client, persist the obtained
        # credentials to the config file, and reuse them on subsequent runs.
        # When client_id is already present, DCR is skipped to avoid
        # re-registering each time. Everything below (PKCE, authorize request,
        # token exchange) works unchanged because exchange_token() adapts to
        # secret presence.
        if self.dcr:
            if self.client_id:
                print("   [dcr] oauth.dcr=true but client_id is already "
                      "configured; skipping DCR (reusing existing client_id)")
            else:
                registration_ep = metadata.get("registration_endpoint")
                if not registration_ep:
                    raise ValueError(
                        "oauth.dcr=true is set but the AS metadata has no "
                        "registration_endpoint (RFC 7591 DCR not supported by "
                        "this IdP). Set oauth.dcr=false and configure "
                        "client_id/client_secret manually."
                    )
                print(f"   [dcr] registering client at {registration_ep} ...")
                reg = register_client(
                    registration_endpoint=registration_ep,
                    redirect_uri=self.redirect_uri,
                    scope=self.scope,
                    client_name=self.dcr_options.get("client_name", "mcpTester"),
                    token_endpoint_auth_method=self.dcr_options.get(
                        "token_endpoint_auth_method", "none"),
                    initial_access_token=self.dcr_options.get(
                        "initial_access_token", ""),
                    timeout=self.timeout,
                )
                self.client_id = reg.get("client_id", "")
                self.client_secret = reg.get("client_secret", "") or ""
                if not self.client_id:
                    raise RuntimeError(f"DCR response missing client_id: {reg}")
                # Credentials printed UNMASKED (test/troubleshoot tool).
                print(green(f"   [dcr] client_id obtained     = {self.client_id}"))
                print(green(f"   [dcr] client_secret obtained = "
                            f"{self.client_secret or '(none — public client)'}"))
                self._save_credentials()
                kind = ("confidential (secret issued)"
                        if self.client_secret else "public (no secret, PKCE only)")
                print(green(f"   [dcr] client registered  [{kind}]"))

        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if self.send_resource:
            params["resource"] = self.resource_url
        query = urllib.parse.urlencode(params)
        url = f"{authorize_ep}?{query}"
        print(f"   Opening browser for IdP authentication...")
        print(f"   If it does not open automatically, visit:\n     {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass  # The URL is printed, so it can be opened manually

        code = wait_for_callback(self.redirect_uri, state)
        resource_val = self.resource_url if self.send_resource else ""
        self.access_token = exchange_token(
            token_ep, self.redirect_uri, self.client_id, code, code_verifier,
            self.client_secret, resource=resource_val
        )
        return self.access_token

    def _save_credentials(self):
        """Persist the DCR-obtained client_id/client_secret into the config
        file so subsequent runs skip DCR and reuse them. Only writes when the
        config file exists; otherwise the credentials are only printed above.
        """
        if not self.config_path:
            print(yellow("   [dcr] config_path not set; credentials printed "
                         "above but not saved"))
            return
        if not os.path.exists(self.config_path):
            print(yellow(f"   [dcr] {self.config_path} not found; credentials "
                         f"printed above but not saved"))
            return
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            oauth = cfg.setdefault("oauth", {})
            oauth["client_id"] = self.client_id
            if self.client_secret:
                oauth["client_secret"] = self.client_secret
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=4)
                f.write("\n")
            saved = "client_id" + (
                " + client_secret" if self.client_secret else "")
            print(green(f"   [dcr] saved {saved} to {self.config_path}"))
        except Exception as e:
            print(yellow(f"   [dcr] failed to save credentials to "
                         f"{self.config_path}: {e}"))


def load_tester_config(config_path="mcp_tester_config.json"):
    """Load the mcpTester config (defaults to OAuth disabled if missing)."""
    default = {"oauth": {"enabled": False}}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                default.update(cfg)
            print(f"✅ Loaded tester config from {config_path}")
        except Exception as e:
            print(f"⚠️  Failed to load tester config ({e}); using defaults")
    else:
        print(f"ℹ️  No {config_path} found; OAuth disabled (run unauthenticated)")
    return default


# ===========================================================================
# MCP Tester main body
# ===========================================================================

# Hardcoded arguments used when invoking a known tool in single-tool mode.
# Unknown tools are called with empty arguments.
SINGLE_TOOL_ARGUMENTS = {
    "get_test_string": {"prefix": "Hello"},
    "echo": {"message": "ping"},
    "check_maintenance": {},
}


class MCPTester:
    """Client that performs a quick verification of the MCP server."""

    def __init__(self, base_url, oauth_client=None, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._id = 0
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.oauth_client = oauth_client

    def _next_id(self):
        self._id += 1
        return self._id

    # --- Display helpers ---
    def _section(self, title):
        print()
        print(bold(cyan(f"── {title} ") + cyan("─" * max(1, 54 - len(title)))))

    def _ok(self, label, detail=""):
        self.passed += 1
        msg = f"  {green('✅')} {label}"
        if detail:
            msg += f"\n     {detail}"
        print(msg)

    def _fail(self, label, detail=""):
        self.failed += 1
        msg = f"  {red('❌')} {label}"
        if detail:
            msg += f"\n     {red(detail)}"
        print(msg)

    def _warn(self, label, detail=""):
        self.warnings += 1
        msg = f"  {yellow('⚠️')} {label}"
        if detail:
            msg += f"\n     {detail}"
        print(msg)

    @staticmethod
    def _err_text(error):
        code = error.get("code")
        msg = error.get("message", "")
        meaning = JSONRPC_ERRORS.get(code, "")
        return f"code={code} ({meaning}): {msg}" if meaning else f"code={code}: {msg}"

    def _auth_headers(self, extra=None):
        headers = dict(extra or {})
        if self.oauth_client and self.oauth_client.access_token:
            headers["Authorization"] = f"Bearer {self.oauth_client.access_token}"
        return headers

    # --- HTTP communication ---
    def _get(self, url=None):
        target = url or self.base_url
        req = urllib.request.Request(target, method="GET", headers=self._auth_headers())
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body

    def _post_jsonrpc(self, method, params=None):
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {},
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base_url,
            data=data,
            headers=self._auth_headers({
                "Content-Type": "application/json",
                "Accept": "application/json",
            }),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body[:300]}")

        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError(f"Invalid JSON response: {body[:300]}")

    # --- Steps ---
    def step_oauth(self):
        """Obtain an access token via OAuth 2.1 + PKCE."""
        self._section("0. OAuth 2.1 + PKCE (Authorization Code Flow)")
        try:
            token = self.oauth_client.authenticate()
            # Token printed UNMASKED on purpose: this is a test/troubleshoot
            # tool, so the raw Bearer token is needed to decode the JWT and
            # inspect its claims. Do not do this in production.
            self._ok("Access token obtained", f"Bearer {token}")
        except Exception as e:
            self._fail("OAuth authentication", str(e))
            return False
        return True

    def step_health_check(self):
        self._section("1. Health Check (GET)")
        try:
            status, body = self._get()
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = None
            detail = f"HTTP {status}"
            if isinstance(data, dict):
                detail += (f" | server={data.get('server', '?')} "
                           f"v{data.get('version', '?')} | {data.get('message', '')}")
            self._ok(f"Server is responding (HTTP {status})", detail)
        except urllib.error.HTTPError as e:
            # 4xx that means "server is up but rejects this request" (auth
            # required, GET not supported, etc.) still proves the server is
            # reachable, so treat them as success and continue to next steps.
            if e.code in (401, 403, 404, 405):
                self._ok(f"Server is reachable (HTTP {e.code})",
                         f"{self.base_url} — GET/auth rejected but server is up")
            else:
                # Any other 4xx/5xx still proves the server is reachable (the
                # request was received and processed enough to return an HTTP
                # status). Warn and continue — subsequent steps may still work
                # or surface more specific error detail (e.g. 500/502/503).
                self._warn(
                    f"Server reachable but returned HTTP {e.code} (continuing)",
                    f"{self.base_url} — server is up, will try subsequent steps")
        except urllib.error.URLError as e:
            self._fail("Cannot reach server", f"{self.base_url}  ({e.reason})")
        except Exception as e:
            self._fail("Health check failed", str(e))

    def step_initialize(self):
        self._section("2. initialize")
        try:
            resp = self._post_jsonrpc("initialize", {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "mcpTester", "version": "1.0.0"},
            })
            if "error" in resp:
                self._fail("initialize", self._err_text(resp["error"]))
                return
            result = resp.get("result", {})
            info = result.get("serverInfo", {})
            caps = list((result.get("capabilities") or {}).keys())
            self._ok(
                f"Initialized: {info.get('name', '?')} v{info.get('version', '?')}",
                f"protocolVersion={result.get('protocolVersion', '?')} "
                f"| capabilities={caps}",
            )
        except Exception as e:
            self._fail("initialize", str(e))

    def step_tools_list(self):
        self._section("3. tools/list")
        try:
            resp = self._post_jsonrpc("tools/list", {})
            if "error" in resp:
                self._fail("tools/list", self._err_text(resp["error"]))
                return None
            tools = resp.get("result", {}).get("tools", [])
            names = [t.get("name", "?") for t in tools]
            self._ok(f"{len(tools)} tool(s) available",
                     f"tools: {', '.join(names) if names else '(none)'}")
            return tools
        except Exception as e:
            self._fail("tools/list", str(e))
            return None

    def step_call_tool(self, tool_name, arguments, label_detail=""):
        label = f"tools/call: {tool_name}"
        if label_detail:
            label += f" ({label_detail})"
        try:
            resp = self._post_jsonrpc("tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })
            if "error" in resp:
                self._fail(label, self._err_text(resp["error"]))
                return
            contents = resp.get("result", {}).get("content", [])
            texts = [c.get("text", "") for c in contents if c.get("type") == "text"]
            preview = texts[0] if texts else "(no text content)"
            if len(preview) > 200:
                preview = preview[:200] + " ..."
            self._ok(label, f"result: {preview}")
        except Exception as e:
            self._fail(label, str(e))

    def step_simple(self, method):
        """Simple existence check such as ping / prompts/list / resources/list."""
        try:
            resp = self._post_jsonrpc(method, {})
            if "error" in resp:
                self._fail(method, self._err_text(resp["error"]))
                return
            result = resp.get("result", {})
            if method == "ping":
                self._ok(method, f"result: {result}")
                return
            # List-type: show the count of the collection under the first key
            if isinstance(result, dict) and result:
                k = next(iter(result))
                v = result[k]
                n = len(v) if isinstance(v, list) else 1
                self._ok(method, f"{k}: {n} item(s)")
            else:
                self._ok(method, f"result: {result}")
        except Exception as e:
            self._fail(method, str(e))

    # --- Execution ---
    def run(self):
        oauth_on = bool(self.oauth_client and self.oauth_client.enabled)
        mode = "OAuth 2.1+PKCE" if oauth_on else "no auth"
        print(bold(f"MCP Server Tester → {self.base_url}")
              + yellow(f"  [{mode}]") + f"  (timeout={self.timeout}s)")

        # 0. OAuth authentication (only when enabled)
        if oauth_on:
            if not self.step_oauth():
                self._print_summary()
                return False

        # 1. Health check (early exit only if the server is unreachable; server
        #    errors such as 4xx/5xx are warnings and still proceed to initialize)
        self.step_health_check()
        if self.failed > 0:
            self._print_summary()
            return False

        # 2. initialize
        self.step_initialize()
        # 3. tools/list
        tools = self.step_tools_list()
        tool_names = [t.get("name") for t in (tools or [])]

        # 4. tools/call (actually invoke the implemented tools)
        self._section("4. tools/call (invoke implemented tools)")
        if "get_test_string" in tool_names:
            self.step_call_tool("get_test_string", {"prefix": "Hello"}, "prefix=Hello")
        if "echo" in tool_names:
            self.step_call_tool("echo", {"message": "ping"}, "message=ping")
        if "check_maintenance" in tool_names:
            self.step_call_tool("check_maintenance", {}, "read secret_notes.txt")

        # 5. Other features
        self._section("5. Other features")
        self.step_simple("ping")
        self.step_simple("prompts/list")
        self.step_simple("resources/list")

        self._print_summary()
        return self.failed == 0

    def run_single_tool(self, tool_name):
        """Invoke a single specified tool only:
        oauth -> health check -> initialize -> tools/list (existence check) -> tools/call."""
        oauth_on = bool(self.oauth_client and self.oauth_client.enabled)
        mode = "OAuth 2.1+PKCE" if oauth_on else "no auth"
        print(bold(f"MCP Server Tester → {self.base_url}")
              + yellow(f"  [{mode}, single-tool]") + f"  tool={tool_name}  (timeout={self.timeout}s)")

        # 0. OAuth authentication (only when enabled)
        if oauth_on:
            if not self.step_oauth():
                self._print_summary()
                return False

        # 1. Health check (early exit if the server is unreachable)
        self.step_health_check()
        if self.failed > 0:
            self._print_summary()
            return False

        # 2. initialize
        self.step_initialize()

        # 3. tools/list — verify the requested tool exists on the server
        self._section("3. tools/list (verify tool exists)")
        try:
            resp = self._post_jsonrpc("tools/list", {})
        except Exception as e:
            self._fail("tools/list", str(e))
            self._print_summary()
            return False
        if "error" in resp:
            self._fail("tools/list", self._err_text(resp["error"]))
            self._print_summary()
            return False
        tool_names = [t.get("name", "?") for t in resp.get("result", {}).get("tools", [])]
        if tool_name not in tool_names:
            available = ", ".join(tool_names) if tool_names else "(none)"
            self._fail(f"tools/call: {tool_name}",
                       f"tool not found on server. available: {available}")
            self._print_summary()
            return False
        self._ok(f"tools/call: {tool_name}",
                 f"tool exists on server ({len(tool_names)} tool(s) listed)")

        # 4. tools/call — invoke only the requested tool
        self._section("4. tools/call (invoke single tool)")
        self.step_call_tool(tool_name, SINGLE_TOOL_ARGUMENTS.get(tool_name, {}))

        self._print_summary()
        return self.failed == 0

    def _print_summary(self):
        total = self.passed + self.failed
        print()
        print(bold("─" * 60))
        if self.failed == 0:
            print(green(f"✅ ALL PASSED  ({self.passed}/{total})"))
        else:
            print(red(f"❌ {self.failed} FAILED  ({self.passed}/{total} passed)"))
        if self.warnings > 0:
            print(yellow(f"⚠️ {self.warnings} warning(s)"))
        print(bold("─" * 60))


def resolve_args(argv):
    """Resolve (url, tool_name) from argv.
    url is argv[1] (or MCP_SERVER_URL env / default);
    tool_name is argv[2] when present -> single-tool mode."""
    if len(argv) > 1:
        url = argv[1]
    else:
        url = os.environ.get("MCP_SERVER_URL", "http://localhost:9000")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    tool_name = argv[2] if len(argv) > 2 else None
    return url, tool_name


def main():
    base_url, tool_name = resolve_args(sys.argv)
    config_path = "mcp_tester_config.json"
    tester_config = load_tester_config(config_path)
    oauth_client = OAuthClient(
        tester_config.get("oauth", {}), resource_url=base_url,
        config_path=config_path,
    )
    tester = MCPTester(base_url, oauth_client=oauth_client, timeout=15)
    ok = tester.run_single_tool(tool_name) if tool_name else tester.run()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
