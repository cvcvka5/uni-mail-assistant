#!/usr/bin/env python3
"""Multiple Gmail accounts through Google OAuth 2.0 (read-only, no app passwords).

  python3 gmail_oauth.py add [CLIENT_ID] link a Gmail account (opens your browser; CLIENT_ID picks one of several OAuth clients)
  python3 gmail_oauth.py list            show linked accounts
  python3 gmail_oauth.py remove EMAIL    disconnect: revokes access at Google, deletes the token and wipes the stored mail content

Security: OAuth "installed app" flow with PKCE and a loopback redirect (127.0.0.1, random port); only the
read-only Gmail scope is requested. Each account's refresh token is kept in the macOS Keychain
(service "unimail-gmail-oauth:<address>"); access tokens live in memory and are refreshed on demand.
"""
import base64
import concurrent.futures
import datetime as dt
import email
import hashlib
import http.server
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

import helper

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
API = "https://gmail.googleapis.com/gmail/v1/users/me/"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SCOPES = "openid email " + GMAIL_SCOPE
TOKEN_SERVICE = "unimail-gmail-oauth:"
# Gmail's own tabs already remove most marketing; override with "gmail_query" in config.json.
DEFAULT_QUERY = "in:inbox -category:promotions -category:social -category:forums"
MAX_LIST = 300  # newest mail first; override with "gmail_max_messages" in config.json

_tokens = {}  # address -> (access_token, expires_at)


class GoogleError(RuntimeError):  # also raised for a wrong client secret (error 'invalid_client')
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code

# ------------------------------------------------------------------ OAuth

def clients():
    """OAuth clients from config.json: {"google_oauth": {"clients": [{"client_id", "keychain"}, ...]}}
    (a single {"client_id", "keychain"} object also works). Each Gmail account remembers which client linked it."""
    g = helper.CFG.get("google_oauth") or {}
    out = g.get("clients") or ([g] if g.get("client_id") else [])
    return [{"client_id": c["client_id"], "keychain": c.get("keychain", "unimail-google-client-secret")}
            for c in out if c.get("client_id")]


def _client(client_id=None, addr=None):
    if addr and not client_id:
        r = helper.db().execute("SELECT client_id FROM gmail_accounts WHERE email=?", (addr,)).fetchone()
        client_id = r[0] if r else None
    cl = clients()
    if not cl:
        raise RuntimeError("Google OAuth is not set up: add \"google_oauth\": {\"clients\": [{\"client_id\": ..., "
                           "\"keychain\": ...}]} to config.json (see docs/ADD-MORE-ACCOUNTS.md).")
    c = next((c for c in cl if c["client_id"] == client_id), cl[0]) if client_id else cl[0]
    return c["client_id"], helper.keychain_secret(c["keychain"])


def _post(url, data):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            err = json.load(e)
        except Exception:
            err = {}
        raise GoogleError(err.get("error_description") or err.get("error") or "HTTP %s" % e.code, err.get("error"))


def _save_token(addr, refresh_token):
    helper.keychain_set(TOKEN_SERVICE + addr, addr, refresh_token)


def access_token(addr):
    """A valid access token for this account (refreshed with the stored refresh token when needed)."""
    tok, exp = _tokens.get(addr, (None, 0))
    if tok and time.time() < exp - 60:
        return tok
    cid, secret = _client(addr=addr)
    try:
        r = _post(TOKEN_URL, {"client_id": cid, "client_secret": secret, "grant_type": "refresh_token",
                              "refresh_token": helper.keychain_secret(TOKEN_SERVICE + addr)})
    except GoogleError as e:
        if e.code == "invalid_grant":
            raise RuntimeError("%s: access expired or was revoked. Link it again: python3 gmail_oauth.py add" % addr)
        raise RuntimeError("%s: token refresh failed (%s)" % (addr, e))
    if r.get("refresh_token"):  # Google may rotate it
        _save_token(addr, r["refresh_token"])
    _tokens[addr] = (r["access_token"], time.time() + int(r.get("expires_in", 3600)))
    return r["access_token"]


def link(client_id=None, timeout=300):
    """Runs the browser consent flow, stores the token, registers the account. Returns the address."""
    cid, secret = _client(client_id)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).items()}
            if "code" in q or "error" in q:
                result.update(q)
                body = "<h3>Done. You can close this tab and go back to Uni Mail Assistant.</h3>"
                self.send_response(200)
            else:
                body = ""
                self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    srv.timeout = 2
    redirect = "http://127.0.0.1:%d" % srv.server_port
    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": redirect, "response_type": "code", "scope": SCOPES,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "access_type": "offline", "prompt": "consent select_account"})
    print("Opening your browser to link a Gmail account…\nIf nothing opens, visit:\n" + url, flush=True)
    webbrowser.open(url)
    deadline = time.time() + timeout
    try:
        while not result and time.time() < deadline:
            srv.handle_request()
    finally:
        srv.server_close()
    if not result:
        raise RuntimeError("Timed out waiting for Google sign-in.")
    if result.get("state") != state:
        raise RuntimeError("Sign-in response did not match this request (state mismatch). Nothing was saved.")
    if "code" not in result:
        raise RuntimeError("Google sign-in was cancelled or denied (%s)." % result.get("error", "unknown"))

    tok = _post(TOKEN_URL, {"client_id": cid, "client_secret": secret, "code": result["code"],
                            "code_verifier": verifier, "redirect_uri": redirect, "grant_type": "authorization_code"})
    refresh = tok.get("refresh_token")
    if GMAIL_SCOPE not in (tok.get("scope") or ""):
        if refresh:
            _post(REVOKE_URL, {"token": refresh})
        raise RuntimeError("Gmail read access was not granted. Link again and tick the Gmail permission.")
    if not refresh:
        raise RuntimeError("Google returned no refresh token. Remove the app at myaccount.google.com/permissions, then link again.")
    req = urllib.request.Request(USERINFO_URL, headers={"Authorization": "Bearer " + tok["access_token"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        info = json.load(r)
    addr = (info.get("email") or "").lower()
    if not addr:
        raise RuntimeError("Could not read the account's email address.")
    _save_token(addr, refresh)
    _tokens[addr] = (tok["access_token"], time.time() + int(tok.get("expires_in", 3600)))
    con = helper.db()
    con.execute("INSERT OR REPLACE INTO gmail_accounts (email, linked, client_id) VALUES (?,?,?)",
                (addr, dt.datetime.now().isoformat(timespec="minutes"), cid))
    con.commit()
    helper.log("Gmail linked: " + addr)
    return addr


def remove(addr):
    """Disconnects an account: revoke at Google (best effort), delete the token, wipe stored mail content of that inbox."""
    addr = addr.lower()
    con = helper.db()
    if not con.execute("SELECT 1 FROM gmail_accounts WHERE email=?", (addr,)).fetchone():
        raise RuntimeError("%s is not linked." % addr)
    try:
        _post(REVOKE_URL, {"token": helper.keychain_secret(TOKEN_SERVICE + addr)})
    except Exception:
        pass  # already revoked or offline: local cleanup still happens
    helper.keychain_delete(TOKEN_SERVICE + addr)
    _tokens.pop(addr, None)
    # Wipe the content but keep ids/fingerprints, so linking the account again never creates duplicate reminders.
    con.execute("UPDATE emails SET body='', links='[]', subject='', sender='', sender_addr='', summary=NULL, action=NULL, "
                "deadline=NULL, needs_reply=0, importance='ignore', category='removed', notified=1 WHERE account=?", (addr,))
    con.execute("DELETE FROM state WHERE key=?", ("first_sync:" + addr,))
    con.execute("DELETE FROM gmail_accounts WHERE email=?", (addr,))
    con.commit()
    helper.log("Gmail disconnected: " + addr)


def accounts():
    con = helper.db()
    return [dict(r) for r in con.execute("SELECT email, linked FROM gmail_accounts ORDER BY linked")]

# ------------------------------------------------------------------ Gmail API

QUOTA_WAITS = (15, 30, 60, 60)  # seconds to wait before each retry when Google says "slow down"


def api(addr, path, params=None):
    url = API + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
    refreshed = False
    for attempt in range(len(QUOTA_WAITS) + 1):
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + access_token(addr)})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code == 401 and not refreshed:
                refreshed = True
                _tokens.pop(addr, None)
                continue
            slow_down = e.code in (429, 500, 503) or (e.code == 403 and re.search(r"quota|rate ?limit", body, re.I))
            if slow_down and attempt < len(QUOTA_WAITS):
                helper.log("Gmail %s: Google asks to slow down, waiting %ds…" % (addr, QUOTA_WAITS[attempt]))
                time.sleep(QUOTA_WAITS[attempt])
                continue
            raise RuntimeError("%s: Gmail API error %s %s" % (addr, e.code, body[:200]))


def _ids(addr, query, limit):
    ids, page = [], None
    while len(ids) < limit:
        params = {"q": query, "maxResults": min(100, limit)}
        if page:
            params["pageToken"] = page
        r = api(addr, "messages", params)
        ids += [m["id"] for m in r.get("messages", [])]
        page = r.get("nextPageToken")
        if not page:
            break
    return ids[:limit]


def fetch_new(addr, days, known):
    """Yields (msg_id, email.Message) for inbox mail of the last `days` days that is not in `known`."""
    query = "%s newer_than:%dd" % (helper.CFG.get("gmail_query", DEFAULT_QUERY), days)
    ids = _ids(addr, query, int(helper.CFG.get("gmail_max_messages", MAX_LIST)))
    todo = [g for g in ids if "gmail:%s:%s" % (addr, g) not in known]
    helper.log("Gmail %s: %d message(s) found, %d new to download" % (addr, len(ids), len(todo)))
    def get(gid):
        raw = api(addr, "messages/" + gid, {"format": "raw"})["raw"]
        return email.message_from_bytes(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))

    # Parallel download (each request opens a new HTTPS connection, so sequential fetching is slow).
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for n, (gid, msg) in enumerate(zip(todo, pool.map(get, todo)), 1):
            if n % 25 == 0:
                helper.log("Gmail %s: downloaded %d/%d" % (addr, n, len(todo)))
            yield "gmail:%s:%s" % (addr, gid), msg


def reply_refs(addr, days=30):
    """Message-IDs of mails the user has replied to (from the Sent label)."""
    refs = set()
    for gid in _ids(addr, "in:sent newer_than:%dd" % days, 200):
        d = api(addr, "messages/" + gid, {"format": "metadata", "metadataHeaders": ["In-Reply-To", "References"]})
        for h in d.get("payload", {}).get("headers", []):
            refs.update(re.findall(r"<[^>]+>", h.get("value", "")))
    return refs

# ------------------------------------------------------------------ CLI

def main(argv):
    cmd = argv[0] if argv else ""
    if cmd == "add":
        print("Linked:", link(argv[1] if len(argv) > 1 else None))
    elif cmd == "list":
        rows = accounts()
        for r in rows:
            print("  %-34s linked %s" % (r["email"], r["linked"].replace("T", " ")))
        if not rows:
            print("No Gmail accounts linked. Run: python3 gmail_oauth.py add")
    elif cmd == "remove" and len(argv) > 1:
        remove(argv[1])
        print("Disconnected:", argv[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (RuntimeError, urllib.error.URLError) as e:
        sys.exit("Problem: %s" % e)
