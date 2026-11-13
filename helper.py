#!/usr/bin/env python3
"""Uni Mail Helper – background engine.

  python3 helper.py check   -> test logins, Gemini, Reminders/Calendar (and Matrix if enabled)
  python3 helper.py sync    -> fetch + analyse new mail/messages, send reminders (the background service runs this)
  python3 helper.py status  -> show what is stored
  python3 helper.py gmail add|list|remove EMAIL  -> link / view / disconnect Gmail accounts (Google OAuth)

Rules: mail is read-only; only real messages are stored; bank numbers, amounts, IDs and PINs are
removed before anything is stored or sent to Gemini. Links stay on your Mac/iCloud only.
"""
import datetime as dt
import email
import email.header
import email.utils
import fcntl
import hashlib
import html
import imaplib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
DB_PATH = os.path.join(HERE, "mail.db")
LOG_PATH = os.path.join(HERE, "activity.log")
LOCK_PATH = os.path.join(HERE, ".sync.lock")

if not os.path.exists(CONFIG_PATH):
    sys.exit("No config.json yet. Run:  bash setup.sh")
with open(CONFIG_PATH, encoding="utf-8") as _f:
    CFG = json.load(_f)


def log(msg):
    line = "%s  %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def accounts():
    return [a for a in CFG["accounts"] if a.get("enabled", True)]


GMAIL_LIST = CFG.get("gmail_reminders_list", "Gmail – reminders")
SIGNAL = "importance IN ('high','medium')"  # the only mail that is ever surfaced


def gmail_accounts(con):
    """Gmail addresses linked through Google OAuth (see gmail_oauth.py)."""
    return [r[0] for r in con.execute("SELECT email FROM gmail_accounts ORDER BY linked")]

# ------------------------------------------------------------------ Keychain

def _security(*args):
    return subprocess.run(["/usr/bin/security", *args], capture_output=True, text=True)


def keychain_login(service):
    r = _security("find-generic-password", "-s", service)
    m = re.search(r'"acct"<blob>="([^"]*)"', r.stdout)
    pw = _security("find-generic-password", "-s", service, "-w").stdout.strip()
    if not m or not pw:
        raise RuntimeError("Login '%s' not found in Keychain. See the README." % service)
    return m.group(1), pw


def keychain_secret(service):
    v = _security("find-generic-password", "-s", service, "-w").stdout.strip()
    if not v:
        raise RuntimeError("'%s' not found in Keychain. See the README." % service)
    return v

def keychain_set(service, account, secret):
    r = _security("add-generic-password", "-U", "-s", service, "-a", account, "-w", secret)
    if r.returncode != 0:
        raise RuntimeError("Could not save to Keychain: " + r.stderr.strip())


def keychain_delete(service):
    _security("delete-generic-password", "-s", service)

# ------------------------------------------------------------------ database

def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS emails (
        msg_id TEXT PRIMARY KEY, received TEXT, sender TEXT, sender_addr TEXT, subject TEXT,
        body TEXT, category TEXT, importance TEXT, summary TEXT, action TEXT,
        needs_reply INTEGER DEFAULT 0, replied INTEGER DEFAULT 0, reply_reminded INTEGER DEFAULT 0,
        analysed INTEGER DEFAULT 0, notified INTEGER DEFAULT 0, error TEXT);
    CREATE INDEX IF NOT EXISTS idx_received ON emails(received);
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY, msg_id TEXT, kind TEXT, title TEXT, day TEXT, time TEXT,
        status TEXT, reminder_id TEXT, created TEXT, UNIQUE(kind, title, day));
    CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS made (key TEXT PRIMARY KEY);  -- everything we ever created, even if you deleted it later
    CREATE TABLE IF NOT EXISTS gmail_accounts (email TEXT PRIMARY KEY, linked TEXT, client_id TEXT);
    """)
    for table, col in (("emails", "account TEXT DEFAULT 'Uni'"), ("emails", "links TEXT"), ("emails", "deadline TEXT"),
                       ("emails", "reminder_id TEXT"), ("emails", "rfc_id TEXT"), ("emails", "fingerprint TEXT"),
                       ("gmail_accounts", "client_id TEXT")):
        try:
            con.execute("ALTER TABLE %s ADD COLUMN %s" % (table, col))
        except sqlite3.OperationalError:
            pass
    return con


def get_state(con, key):
    r = con.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return r[0] if r else None


def set_state(con, key, value):
    con.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, value))
    con.commit()

# ------------------------------------------------------------------ privacy filter

REDACTIONS = [
    (re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"), "[HIDDEN-IBAN]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[HIDDEN-NUMBER]"),
    (re.compile(r"(?:€|EUR)\s?\d[\d.,]*|\d[\d.,]*\s?(?:€|(?:EUR|Euro)\b)", re.I), "[HIDDEN-AMOUNT]"),
    (re.compile(r"\b\d{6,9}\b"), "[HIDDEN-ID]"),
    (re.compile(r"(?i)\b(passwor[td]|kennwort|pin|tan|code)\s*[:=]\s*\S+"), r"\1: [HIDDEN]"),
]
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def redact(text):
    text = URL_RE.sub("[link]", text or "")  # links never go to the AI
    for pattern, repl in REDACTIONS:
        text = pattern.sub(repl, text)
    return text

# ------------------------------------------------------------------ noise pre-filter
# Mail matching these rules is never analysed, reminded or shown. Deliberately narrow: anything unclear goes to the AI.

SECURITY_RE = re.compile(
    r"verification code|security code|one[- ]time (pass)?(code|word)|\botp\b|\b2fa\b|two[- ]factor|2[- ]step|"
    r"sign[- ]?in (attempt|alert|from|to|notice)|new (login|sign-in|device)|log[- ]?in (alert|attempt|from|notice)|"
    r"security alert|suspicious (activity|sign|login)|password (reset|was changed|has been changed|changed)|"
    r"reset your password|(confirm|verify) your (email|e-mail|account|identity)|(login|verification|confirmation) code|"
    r"third-party (oauth )?application|authorized (oauth|application)|oauth application|personal access token|"
    r"new (ssh|gpg) key|passkey|"
    r"bestätigungscode|sicherheitscode|einmalcode|einmal-?passwort|passwort (zurückgesetzt|geändert)|"
    r"passwort zurücksetzen|neues gerät|neue anmeldung|verdächtige|"
    r"\[github\].*(sign|token|ssh|key|password|verif|device|security|authoriz|oauth|two-factor)", re.I)

RECEIPT_RE = re.compile(
    r"\breceipt\b|your order\b|order (confirmation|confirmed|received|shipped|#|no\.?)|payment (received|confirmation|successful)|"
    r"thank you for your (order|purchase|payment)|has (been )?shipped|out for delivery|\bdelivered\b|tracking (number|update)|"
    r"your package|bestellbestätigung|ihre bestellung|zahlungsbestätigung|quittung|versandbestätigung|"
    r"wurde (versendet|zugestellt)|paket(verfolgung|zustellung)|sendungsverfolgung|ihre sendung", re.I)

PROMO_RE = re.compile(
    r"\bsale\b|% ?(off|rabatt)|discount|\bdeals?\b|special offer|limited time|angebot|rabatt|gutschein|coupon|"
    r"newsletter|webinar|black friday|jetzt sparen|unsubscribe", re.I)


def noise_reason(sender_addr, subject, msg=None):
    """Why this mail is noise (security/auth alert, receipt/shipping, marketing), or None."""
    subject = subject or ""
    if SECURITY_RE.search(subject):
        return "security"
    if RECEIPT_RE.search(subject):
        return "receipt"
    if any(s in (sender_addr or "") for s in CFG.get("skip_ai_for_senders", [])):
        return "marketing"
    bulk = msg is not None and (msg.get("List-Unsubscribe") or "bulk" in (msg.get("Precedence") or "").lower())
    if bulk and PROMO_RE.search(subject):
        return "marketing"
    return None

# ------------------------------------------------------------------ mail

def decode(value):
    out = []
    for text, enc in email.header.decode_header(value or ""):
        if isinstance(text, bytes):
            try:
                text = text.decode(enc or "utf-8", errors="replace")
            except LookupError:
                text = text.decode("utf-8", errors="replace")
        out.append(text)
    return re.sub(r"\s+", " ", "".join(out)).strip()


SKIP_LINK = re.compile(r"unsubscribe|abmelden|abbestellen|optout|opt-out|/track|click\.|pixel|\.png|\.jpg|\.gif|"
                       r"mailto:|facebook\.com|instagram\.com|twitter\.com|x\.com/|linkedin\.com/(?:company|shareArticle)|"
                       r"youtube\.com|privacy|datenschutz|impressum|imprint", re.I)


def parts(msg):
    plain = htm = None
    for part in msg.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        try:
            payload = part.get_payload(decode=True)
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload else ""
        except (LookupError, AttributeError):
            continue
        if part.get_content_type() == "text/plain" and plain is None:
            plain = text
        elif part.get_content_type() == "text/html" and htm is None:
            htm = text
    return plain, htm


def extract_links(plain, htm, limit=6):
    """Useful links (with their label when available). Tracking/unsubscribe/social links are dropped."""
    found = []
    if htm:
        for href, label in re.findall(r'(?is)<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', htm):
            label = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", label))).strip()
            found.append((html.unescape(href), label))
    for u in URL_RE.findall(plain or ""):
        found.append((u, ""))
    out, seen = [], set()
    for url, label in found:
        url = url.rstrip(".,;")
        if not url.startswith("http") or SKIP_LINK.search(url) or SKIP_LINK.search(label or "") or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "label": label[:60]})
        if len(out) >= limit:
            break
    return out


def body_text(plain, htm):
    if not plain and htm:
        h = re.sub(r"(?is)<(script|style).*?</\1>", " ", htm)
        h = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>", "\n", h)
        plain = html.unescape(re.sub(r"<[^>]+>", " ", h))
    text = re.split(r"\n(?:>|Am .{5,80} schrieb|On .{5,80} wrote)", plain or "")[0]
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n", text).strip()[:5000]


def imap_connect(acc):
    user, pw = keychain_login(acc["keychain"])
    m = imaplib.IMAP4_SSL(acc["imap_server"], acc.get("imap_port", 993), timeout=60)
    try:
        m.login(user, pw)
    except imaplib.IMAP4.error:
        raise RuntimeError("%s: login was rejected. Check the username/password (README)." % acc["name"])
    return m


def sent_folder(m):
    names = []
    for raw in m.list()[1] or []:
        line = raw.decode(errors="replace")
        name = line.rsplit(' "', 1)[-1].rstrip('"') if line.endswith('"') else line.split()[-1]
        if "\\Sent" in line:
            return name
        names.append(name)
    for guess in ("Sent", "INBOX.Sent", "Gesendet", "INBOX.Gesendet", "Sent Items", "Gesendete Objekte"):
        if guess in names:
            return guess
    return None


def fetch(m, folder, since_days, known=None, headers_only=None):
    """Yields messages since N days. Downloads only small headers first; full emails only
    for messages whose Message-ID is not in `known`. headers_only='IN-REPLY-TO REFERENCES' etc. = never full."""
    typ, _ = m.select('"%s"' % folder, readonly=True)
    if typ != "OK":
        return
    since = (dt.date.today() - dt.timedelta(days=since_days)).strftime("%d-%b-%Y")
    typ, data = m.search(None, "SINCE", since)
    nums = data[0].split() if typ == "OK" and data[0] else []
    if not nums:
        return
    fields = headers_only or "MESSAGE-ID"
    typ, hdrs = m.fetch(b",".join(nums), "(BODY.PEEK[HEADER.FIELDS (%s)])" % fields)
    heads = [email.message_from_bytes(h[1]) for h in hdrs or [] if isinstance(h, tuple)]
    if headers_only:
        yield from heads
        return
    for num, h in zip(nums, heads):
        if known is not None and (h.get("Message-ID") or "").strip() in known:
            continue
        typ, msgdata = m.fetch(num, "(BODY.PEEK[])")
        if typ == "OK" and msgdata and isinstance(msgdata[0], tuple):
            yield email.message_from_bytes(msgdata[0][1])


def imap_answered(m):
    """Message-IDs of mails the user has replied to (from the Sent folder)."""
    answered = set()
    folder = sent_folder(m)
    if folder:
        for msg in fetch(m, folder, 30, headers_only="IN-REPLY-TO REFERENCES"):
            for h in ("In-Reply-To", "References"):
                answered.update(re.findall(r"<[^>]+>", msg.get(h) or ""))
    return answered


def received_time(msg):
    try:
        return email.utils.parsedate_to_datetime(msg.get("Date")).astimezone().replace(tzinfo=None)
    except Exception:
        return dt.datetime.now()

# ------------------------------------------------------------------ Gemini

class QuotaError(RuntimeError):
    """Free Gemini limit reached. Unanalysed mail simply waits for the next run."""


def gemini(prompt, want_json=True):
    key = keychain_secret(CFG.get("gemini_keychain", "unimail-gemini"))
    last = None
    quota_hits = 0
    for model in CFG["gemini_models"]:
        url = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent" % model
        gcfg = {"temperature": 0}
        if want_json:
            gcfg["responseMimeType"] = "application/json"
        body = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": gcfg}).encode()
        for attempt in range(2):
            req = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json", "x-goog-api-key": key})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    resp = json.load(r)
                text = resp["candidates"][0]["content"]["parts"][0]["text"].strip()
                if not want_json:
                    return text
                return json.loads(re.sub(r"^```(?:json)?|```$", "", text).strip())
            except urllib.error.HTTPError as e:
                last = "%s: HTTP %s %s" % (model, e.code, e.read().decode(errors="replace")[:200])
                if e.code in (400, 401, 403):
                    raise RuntimeError("Gemini rejected the request: " + last)
                if e.code == 404:
                    break
                if e.code == 429:  # limit of this model reached -> try the next model
                    quota_hits += 1
                    break
            except Exception as e:
                last = "%s: %s" % (model, e)
            time.sleep(5 * (attempt + 1))
    if quota_hits == len(CFG["gemini_models"]):
        raise QuotaError("Free Gemini limit reached for now (%s)" % last)
    raise RuntimeError("Gemini not reachable (%s)" % last)


ANALYSE_PROMPT = """You are a strict filter for a university student at """ + CFG.get("university", "a university") + """ who rarely
checks email. Surface ONLY what needs attention. Today is {today} ({weekday}).
The message was received {received} in the "{account}" inbox. Answer ONLY with JSON:
{{
 "importance": "high" (the student must act, reply or decide, or there is a deadline/appointment; or a real person,
                       employer, authority or lecturer wrote something that needs an answer),
               "medium" (genuinely relevant personal, university, job/work or project update the student should know),
               "ignore" (EVERYTHING ELSE, see below),
 "category": "uni_admin" | "course" | "job" | "money" | "personal" | "other" | "noise",
 "title": "max 45 chars, what it is about (e.g. 'Register for exams in LSF')",
 "summary": "ONE short sentence, max 15 words: what happened or why it matters. No filler.",
 "action": "max 8 words: what to do, or null",
 "deadline": "YYYY-MM-DD of the key deadline/date, or null",
 "deadline_time": "HH:MM or null",
 "needs_reply": true only if a real person expects an answer,
 "dates": [{{"kind": "exam|deadline|payment|appointment|task", "title": "max 60 chars",
            "date": "YYYY-MM-DD", "time": "HH:MM or null"}}]   (only concrete FUTURE dates the student must act on/attend)
}}
Use "ignore" (category "noise", other fields null/empty) for: security/login/OAuth alerts, verification or 2FA codes,
password resets, receipts and order confirmations, shipping/delivery updates without needed action, newsletters,
mailing-list digests, ads and promotions, social-media/app notifications, and automated notices with nothing to do.
When unsure whether something needs action, prefer "ignore" over "medium".
Resolve relative dates ("next Monday", "bis Freitag") using the received date.
Numbers shown as [HIDDEN-...] and links shown as [link] were removed for privacy.

From: {sender}
Subject: {subject}
Text:
{body}"""


_SCHEMA = ANALYSE_PROMPT[ANALYSE_PROMPT.index("{{\n"):ANALYSE_PROMPT.index("\n}}") + 3]

BATCH_PROMPT = """You are a strict filter for a university student at """ + CFG.get("university", "a university") + """ who rarely
checks email. Surface ONLY what needs attention. Today is {today} ({weekday}).
Below are {n} separate messages, each starting with ### MESSAGE <number>.
Judge EACH message on its own. Answer ONLY with JSON: {{"results": [ one object per message ]}}
Each object has "n" (the message number) plus these fields:
""" + _SCHEMA + """
Use "ignore" (category "noise", other fields null/empty) for: security/login/OAuth alerts, verification or 2FA codes,
password resets, receipts and order confirmations, shipping/delivery updates without needed action, newsletters,
mailing-list digests, ads and promotions, social-media/app notifications, and automated notices with nothing to do.
When unsure whether something needs action, prefer "ignore" over "medium".
Resolve relative dates ("next Monday", "bis Freitag") using each message's received date.
Numbers shown as [HIDDEN-...] and links shown as [link] were removed for privacy.

{messages}"""


def analyse_batch(rows):
    """One Gemini request for several emails -> {msg_id: analysis}."""
    per_mail = max(1200, 24000 // len(rows))
    blocks = []
    for i, r in enumerate(rows, 1):
        rec = dt.datetime.fromisoformat(r["received"])
        blocks.append("### MESSAGE %d\nInbox: %s\nReceived: %s\nFrom: %s <%s>\nSubject: %s\nText:\n%s" % (
            i, r["account"], rec.strftime("%A %Y-%m-%d %H:%M"), r["sender"], r["sender_addr"],
            redact(r["subject"]), (r["body"] or "")[:per_mail]))
    res = gemini(BATCH_PROMPT.format(today=dt.date.today().isoformat(), weekday=dt.date.today().strftime("%A"),
                                     n=len(rows), messages="\n\n".join(blocks)))
    out = {}
    for item in (res.get("results") if isinstance(res, dict) else res) or []:
        try:
            out[rows[int(item["n"]) - 1]["msg_id"]] = item
        except (KeyError, ValueError, IndexError, TypeError):
            continue
    return out

# ------------------------------------------------------------------ Apple apps (values passed as arguments, never pasted into code)

def osa(script, *args):
    r = subprocess.run(["/usr/bin/osascript", "-", *[str(a) for a in args]],
                       input=script, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError("AppleScript: " + r.stderr.strip())
    return r.stdout.strip()


MKDATE = """
on mkdate(y, mo, d, hh, mi)
    set t to current date
    set day of t to 1
    set year of t to (y as integer)
    set month of t to (mo as integer)
    set day of t to (d as integer)
    set hours of t to (hh as integer)
    set minutes of t to (mi as integer)
    set seconds of t to 0
    return t
end mkdate
"""


def add_reminder(list_name, title, notes, due=None, alarm=None, priority=0):
    """due/alarm: datetime or None. priority: 0 none, 1 high, 5 medium, 9 low (Apple's scale)."""
    d = due or alarm
    a = alarm
    args = [list_name, title, notes, priority,
            "1" if due else "0", *(d.strftime("%Y %m %d %H %M").split() if d else ["0"] * 5),
            "1" if a else "0", *(a.strftime("%Y %m %d %H %M").split() if a else ["0"] * 5)]
    return osa(MKDATE + """on run argv
    tell application "Reminders"
        set r to make new reminder at end of reminders of list (item 1 of argv) with properties {name:(item 2 of argv), body:(item 3 of argv), priority:((item 4 of argv) as integer)}
        if (item 5 of argv) is "1" then set due date of r to my mkdate(item 6 of argv, item 7 of argv, item 8 of argv, item 9 of argv, item 10 of argv)
        if (item 11 of argv) is "1" then set remind me date of r to my mkdate(item 12 of argv, item 13 of argv, item 14 of argv, item 15 of argv, item 16 of argv)
        return id of r
    end tell
end run""", *args)


def reminder_exists(list_name, name):
    """True if a reminder with exactly this title is already in that list (open or completed)."""
    try:
        return osa("""on run argv
    tell application "Reminders"
        if (count of (reminders of list (item 1 of argv) whose name is (item 2 of argv))) > 0 then return "yes"
        return "no"
    end tell
end run""", list_name, name) == "yes"
    except Exception:
        return False


def event_exists(title, day):
    """True if a calendar event whose title contains `title` already exists on that day (any of our calendars)."""
    y, mo, d = day.split("-")
    try:
        return osa(MKDATE + """on run argv
    set s to my mkdate(item 2 of argv, item 3 of argv, item 4 of argv, 0, 0)
    set e to s + (1 * days)
    tell application "Calendar"
        repeat with i from 5 to count of argv
            try
                if (count of (every event of calendar (item i of argv) whose summary contains (item 1 of argv) and start date >= s and start date < e)) > 0 then return "yes"
            end try
        end repeat
    end tell
    return "no"
end run""", title, y, mo, d, *sorted(set(CFG["calendars"].values()))) == "yes"
    except Exception:
        return False


def add_event_once(calendar, title, notes, day, time_, alerts):
    plain = title.split(" ", 1)[-1]  # drop the leading icon
    if event_exists(plain, day):
        log("Already in calendar, skipped: %s (%s)" % (plain, day))
        return
    add_event(calendar, title, notes, day, time_, alerts)


def reminder_status(rid):
    return osa("""on run argv
    tell application "Reminders"
        try
            if completed of (reminder id (item 1 of argv)) then return "done"
            return "open"
        on error
            return "gone"
        end try
    end tell
end run""", rid)


def add_event(calendar, title, notes, day, time_, alerts):
    y, mo, d = day.split("-")
    hh, mi = (time_.split(":") if time_ else ("0", "0"))
    allday = "false" if time_ else "true"
    if not time_:
        alerts = [a - 9 * 60 for a in alerts]
    osa(MKDATE + """on run argv
    set s to my mkdate(item 3 of argv, item 4 of argv, item 5 of argv, item 6 of argv, item 7 of argv)
    if (item 8 of argv) is "true" then
        set e to s + (1 * days)
    else
        set e to s + (1 * hours)
    end if
    tell application "Calendar"
        tell calendar (item 1 of argv)
            set ev to make new event at end with properties {summary:(item 2 of argv), start date:s, end date:e, allday event:((item 8 of argv) is "true"), description:(item 9 of argv)}
            repeat with i from 10 to count of argv
                make new display alarm at end of display alarms of ev with properties {trigger interval:-((item i of argv) as integer)}
            end repeat
        end tell
    end tell
end run""", calendar, title, y, mo, d, hh, mi, allday, notes, *alerts)


def notify(title, text):
    try:
        osa('on run argv\n display notification (item 2 of argv) with title (item 1 of argv) sound name "Glass"\nend run',
            title, text[:200])
    except Exception:
        pass


def ensure_lists_and_calendars():
    lists = {CFG["confirm_list"], CFG["digest_list"], GMAIL_LIST} | {a["reminders_list"] for a in accounts()}
    if CFG.get("matrix", {}).get("enabled"):
        lists.add(CFG["matrix"]["reminders_list"])
    for name in lists:
        osa("""on run argv
    tell application "Reminders"
        if not (exists list (item 1 of argv)) then make new list with properties {name:(item 1 of argv)}
    end tell
end run""", name)
    for name in set(CFG["calendars"].values()):
        osa("""on run argv
    tell application "Calendar"
        if not (exists calendar (item 1 of argv)) then make new calendar with properties {name:(item 1 of argv)}
    end tell
end run""", name)

# ------------------------------------------------------------------ helpers for reminders

ICONS = {"exam": "📝", "deadline": "⏰", "payment": "💶", "appointment": "📅", "task": "✅"}
CAT_ICONS = {"uni_admin": "🏛", "course": "📚", "job": "💼", "money": "💶", "account_security": "🔐",
             "personal": "👤", "newsletter": "📰", "promotion": "🏷", "other": "📩"}


def pretty(day, time_=None):
    return dt.date.fromisoformat(day).strftime("%a %d %b %Y") + (" " + time_ if time_ else "")


def at(day, time_, default_hour=9):
    d = dt.date.fromisoformat(day)
    if time_ and re.fullmatch(r"\d{1,2}:\d{2}", time_):
        h, m = map(int, time_.split(":"))
        return dt.datetime.combine(d, dt.time(h, m))
    return dt.datetime.combine(d, dt.time(default_hour, 0))


def norm(text):
    """Comparable form of a title/subject: no Re:/Fwd:, case, punctuation or extra spaces."""
    text = re.sub(r"(?i)^(\s*(re|fw|fwd|aw|wg)\s*:\s*)+", "", text or "")
    return re.sub(r"\W+", " ", text.lower()).strip()


def once(con, *parts_):
    """True the first time a key is seen, False ever after. Used so nothing is created twice,
    not even after you delete or complete the reminder yourself."""
    key = hashlib.sha1("|".join(str(p) for p in parts_).encode()).hexdigest()
    try:
        con.execute("INSERT INTO made (key) VALUES (?)", (key,))
        return key
    except sqlite3.IntegrityError:
        return None


def forget(con, key):
    con.execute("DELETE FROM made WHERE key=?", (key,))
    con.commit()


def first_link(links):
    return ("\n" + links[0]["url"]) if links else ""


def links_text(links):
    if not links:
        return ""
    return "\n🔗 LINKS\n" + "\n".join(("%s:\n%s" % (l["label"], l["url"])) if l.get("label") else l["url"] for l in links)


def soon(minutes=2):
    return dt.datetime.now().replace(second=0, microsecond=0) + dt.timedelta(minutes=minutes)

# ------------------------------------------------------------------ sync steps

def fingerprint(sender_addr, subject, rec):
    """Same sender + subject + minute = same mail, whichever inbox it arrived in."""
    base = "%s|%s|%s" % ((sender_addr or "").lower(), re.sub(r"\W+", " ", (subject or "").lower()).strip(),
                         rec.isoformat(timespec="minutes"))
    return hashlib.sha1(base.encode()).hexdigest()


def store_message(con, account, mid, msg, rec=None):
    """Stores one message. Noise is stored as an already-ignored stub (no body) so it is never fetched or analysed again."""
    rec = rec or received_time(msg)
    plain, htm = parts(msg)
    name, addr = email.utils.parseaddr(decode(msg.get("From")))
    subject = decode(msg.get("Subject"))
    rfc_id = (msg.get("Message-ID") or "").strip()
    fp = fingerprint(addr, subject, rec)
    # Same mail already stored (e.g. delivered to two of your inboxes): keep only the first one.
    dup = con.execute("SELECT 1 FROM emails WHERE msg_id!=? AND (fingerprint=? OR (?!='' AND rfc_id=?))",
                      (mid, fp, rfc_id, rfc_id)).fetchone()
    reason = "duplicate" if dup else ("noise" if noise_reason(addr.lower(), subject, msg) else None)
    if reason:
        con.execute("INSERT INTO emails (msg_id, account, received, sender, sender_addr, subject, body, links, rfc_id, "
                    "fingerprint, category, importance, analysed, notified) VALUES (?,?,?,?,?,?,?,?,?,?,?,'ignore',1,1)",
                    (mid, account, rec.isoformat(timespec="minutes"), name or addr, addr.lower(), subject, "", "[]",
                     rfc_id, fp, reason))
        return False
    con.execute("INSERT INTO emails (msg_id, account, received, sender, sender_addr, subject, body, links, rfc_id, fingerprint) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (mid, account, rec.isoformat(timespec="minutes"), name or addr, addr.lower(), subject,
                 redact(body_text(plain, htm)), json.dumps(extract_links(plain, htm)), rfc_id, fp))
    return True


def download_new(con, acc, m):
    key = "first_sync:" + acc["name"]
    days = CFG["first_sync_days"] if get_state(con, key) is None else CFG["resync_days"]
    new = 0
    for msg in fetch(m, "INBOX", days, known={r[0] for r in con.execute("SELECT msg_id FROM emails")}):
        rec = received_time(msg)
        mid = (msg.get("Message-ID") or "").strip() or "%s|%s" % (rec.isoformat(), decode(msg.get("Subject")))
        old = con.execute("SELECT links FROM emails WHERE msg_id=?", (mid,)).fetchone()
        if old:
            if old["links"] is None:  # fill in links for mail stored before links existed
                plain, htm = parts(msg)
                con.execute("UPDATE emails SET links=? WHERE msg_id=?", (json.dumps(extract_links(plain, htm)), mid))
            continue
        new += store_message(con, acc["name"], mid, msg, rec)
    con.commit()
    set_state(con, key, "done")
    return new


def download_new_gmail(con, addr):
    import gmail_oauth
    key = "first_sync:" + addr
    days = CFG["first_sync_days"] if get_state(con, key) is None else CFG["resync_days"]
    known = {r[0] for r in con.execute("SELECT msg_id FROM emails WHERE account=?", (addr,))}
    new = 0
    try:
        for i, (mid, msg) in enumerate(gmail_oauth.fetch_new(addr, days, known), 1):
            new += store_message(con, addr, mid, msg)
            if i % 25 == 0:
                con.commit()  # keep progress if Google interrupts us; the next run continues where this stopped
    finally:
        con.commit()
    set_state(con, key, "done")
    return new


def analyse_pending(con):
    """Newest mail first, several emails per Gemini request (much faster, uses far less of the free limit)."""
    rows = con.execute("SELECT * FROM emails WHERE analysed=0 ORDER BY received DESC").fetchall()
    todo = []
    for row in rows:
        if noise_reason(row["sender_addr"], row["subject"]):
            con.execute("UPDATE emails SET analysed=1, category='noise', importance='ignore', notified=1 "
                        "WHERE msg_id=?", (row["msg_id"],))
        else:
            todo.append(row)
    con.commit()
    size = CFG.get("batch_size", 10)
    done = 0
    for start in range(0, len(todo), size):
        batch = todo[start:start + size]
        try:
            results = analyse_batch(batch)
        except QuotaError as e:
            log("%s – %d email(s) wait for the next run." % (e, len(todo) - done))
            if get_state(con, "quota_note") != dt.date.today().isoformat():
                notify("Gemini free limit reached", "Remaining emails will be analysed automatically later.")
                set_state(con, "quota_note", dt.date.today().isoformat())
            break
        except Exception as e:
            log("Could not analyse %d email(s) yet: %s" % (len(todo) - done, e))
            if "rejected" in str(e):
                raise
            break  # e.g. no internet: try again next run
        for row in batch:
            if row["msg_id"] in results:
                save_analysis(con, row, results[row["msg_id"]])
                done += 1
        log("Analysed %d/%d" % (done, len(todo)))
    return done


def save_analysis(con, row, a):
    imp = a.get("importance")
    if imp not in ("high", "medium") or a.get("category") == "noise":  # high-signal only
        con.execute("UPDATE emails SET analysed=1, error=NULL, category='noise', importance='ignore', summary=NULL, "
                    "action=NULL, needs_reply=0, deadline=NULL, notified=1 WHERE msg_id=?", (row["msg_id"],))
        con.commit()
        return
    deadline = a.get("deadline") if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(a.get("deadline"))) else None
    if deadline and a.get("deadline_time") and re.fullmatch(r"\d{1,2}:\d{2}", str(a.get("deadline_time"))):
        deadline += "T" + a["deadline_time"]
    title = (a.get("title") or "").strip()[:50]
    summary = (a.get("summary") or "").strip()[:140]
    action = (a.get("action") or "").strip()[:80] or None
    con.execute("""UPDATE emails SET analysed=1, error=NULL, category=?, importance=?, summary=?, action=?,
                   needs_reply=?, deadline=? WHERE msg_id=?""",
                (a.get("category", "other"), imp, (title + " || " if title else "") + summary,
                 action, 1 if a.get("needs_reply") else 0, deadline, row["msg_id"]))
    con.commit()
    suggest_dates(con, row, a.get("dates") or [])


def split_summary(s):
    if s and " || " in s:
        t, rest = s.split(" || ", 1)
        return t, rest
    return None, s or ""


def suggest_dates(con, row, dates):
    today = dt.date.today()
    for it in dates:
        kind = it.get("kind") if it.get("kind") in ICONS else "task"
        try:
            day = dt.date.fromisoformat(str(it.get("date")))
        except ValueError:
            continue
        if day < today:
            continue
        t = it.get("time") if re.fullmatch(r"\d{1,2}:\d{2}", str(it.get("time") or "")) else None
        title = (it.get("title") or row["subject"])[:50]
        # Already known (also when you rejected it): same kind/day/time, or the same title on that day.
        if con.execute("SELECT 1 FROM items WHERE kind=? AND day=? AND IFNULL(time,'')=IFNULL(?,'')",
                       (kind, day.isoformat(), t)).fetchone():
            continue
        nt = norm(title)
        if any(nt == norm(o["title"]) or (len(nt) >= 8 and (nt in norm(o["title"]) or norm(o["title"]) in nt))
               for o in con.execute("SELECT title FROM items WHERE day=?", (day.isoformat(),))):
            continue
        links = json.loads(row["links"] or "[]")
        name = "%s %s – %s" % (ICONS[kind], title, pretty(day.isoformat(), t))
        notes = "Tick = add to calendar, delete = ignore.\n%s · %s%s" % (row["account"], row["sender"][:30], first_link(links))
        if reminder_exists(CFG["confirm_list"], name):
            continue
        if event_exists(title, day.isoformat()):  # already in your calendar: remember it, don't ask again
            con.execute("INSERT INTO items (msg_id,kind,title,day,time,status,reminder_id,created) VALUES (?,?,?,?,?,?,?,?)",
                        (row["msg_id"], kind, title, day.isoformat(), t, "added", None, dt.datetime.now().isoformat()))
            con.commit()
            continue
        rid = add_reminder(CFG["confirm_list"], name, notes)
        con.execute("INSERT INTO items (msg_id,kind,title,day,time,status,reminder_id,created) VALUES (?,?,?,?,?,?,?,?)",
                    (row["msg_id"], kind, title, day.isoformat(), t, "pending", rid, dt.datetime.now().isoformat()))
        con.commit()
        log("Suggested: " + name)


def approvals(con):
    for it in con.execute("SELECT i.*, e.sender, e.subject, e.account, e.links FROM items i LEFT JOIN emails e USING(msg_id) "
                          "WHERE status='pending'").fetchall():
        st = reminder_status(it["reminder_id"])
        if st == "gone":
            con.execute("UPDATE items SET status='rejected' WHERE id=?", (it["id"],))
        elif st == "done":
            add_event_once(CFG["calendars"].get(it["kind"], CFG["calendars"]["task"]),
                      "%s %s" % (ICONS[it["kind"]], it["title"]),
                      "%s · %s%s" % (it["sender"][:30], it["account"], first_link(json.loads(it["links"] or "[]"))),
                      it["day"], it["time"], CFG["alerts_minutes"].get(it["kind"], [1440]))
            con.execute("UPDATE items SET status='added' WHERE id=?", (it["id"],))
            log("Added to calendar: %s (%s)" % (it["title"], it["day"]))
        con.commit()


def email_reminders(con):
    """Every important/useful email becomes one iPhone reminder with all details and links."""
    acc_list = {a["name"]: a["reminders_list"] for a in CFG["accounts"]}
    if CFG.get("matrix"):
        acc_list["Matrix"] = CFG["matrix"]["reminders_list"]
    wanted = CFG.get("remind_for_importance", ["high", "medium"])
    since = (dt.datetime.now() - dt.timedelta(days=CFG["first_sync_days"])).isoformat()
    rows = con.execute("SELECT * FROM emails WHERE analysed=1 AND reminder_id IS NULL AND notified=0 AND received>=? "
                       "ORDER BY received", (since,)).fetchall()
    fresh = (dt.datetime.now() - dt.timedelta(days=2)).isoformat()
    for r in rows:
        if r["importance"] not in wanted:
            con.execute("UPDATE emails SET notified=1 WHERE msg_id=?", (r["msg_id"],))
            continue
        title, summary = split_summary(r["summary"])
        high = r["importance"] == "high"
        name = "%s%s %s" % ("❗️" if high else "", CAT_ICONS.get(r["category"], "📩"), (title or r["subject"])[:50])
        notes = ["%s · %s" % (r["account"], r["sender"][:30]), summary]
        if r["action"]:
            notes.append("→ " + r["action"])
        if r["deadline"]:
            notes.append("Due " + pretty(r["deadline"][:10], r["deadline"][11:] or None))
        if r["needs_reply"]:
            notes.append("↩ reply needed")
        notes.append(first_link(json.loads(r["links"] or "[]")).strip())
        due = alarm = None
        if r["deadline"] and r["deadline"][:10] >= dt.date.today().isoformat():
            due = at(r["deadline"][:10], r["deadline"][11:] or None)
        if high and r["received"] >= fresh:
            alarm = soon()  # ring now for new important mail
        elif due:
            alarm = due - dt.timedelta(days=1)
            alarm = alarm if alarm > dt.datetime.now() else soon()
        target = acc_list.get(r["account"].split(":")[0]) or (
            GMAIL_LIST if "@" in r["account"] else CFG["accounts"][0]["reminders_list"])
        # One reminder per topic: same sender + subject (Re:/Fwd: ignored) + same deadline (or same week).
        when = r["deadline"] or dt.datetime.fromisoformat(r["received"]).strftime("%G-W%V")
        key = once(con, "mail", norm(r["subject"]), r["sender_addr"], when)
        if key is None or reminder_exists(target, name):
            con.execute("UPDATE emails SET notified=1 WHERE msg_id=?", (r["msg_id"],))
            con.commit()
            log("Duplicate, skipped: " + name)
            continue
        try:
            rid = add_reminder(target, name, "\n".join(n for n in notes if n), due, alarm, 1 if high else 5)
        except Exception:
            forget(con, key)
            raise
        con.execute("UPDATE emails SET reminder_id=?, notified=1 WHERE msg_id=?", (rid, r["msg_id"]))
        con.commit()
        if high and r["received"] >= fresh:
            notify("Important: " + r["account"], "%s – %s" % (r["sender"], title or r["subject"]))
        log("Reminder: " + name)


def check_replies(con, account, reminders_list, get_answered):
    """get_answered() -> set of Message-IDs the user replied to; only called when a reply is awaited."""
    waiting = con.execute("SELECT * FROM emails WHERE account=? AND needs_reply=1 AND replied=0 AND reply_reminded=0",
                          (account,)).fetchall()
    if not waiting:
        return
    answered = get_answered()
    limit = dt.timedelta(days=CFG["reply_reminder_after_days"])
    for r in waiting:
        if (r["rfc_id"] or r["msg_id"]) in answered:
            con.execute("UPDATE emails SET replied=1 WHERE msg_id=?", (r["msg_id"],))
        elif dt.datetime.now() - dt.datetime.fromisoformat(r["received"]) > limit:
            _, summary = split_summary(r["summary"])
            add_reminder(reminders_list, "↩ Reply to %s: %s" % (r["sender"][:20], r["subject"][:40]),
                         "%s\n%s" % (r["account"], summary), None, soon(), 1)
            con.execute("UPDATE emails SET reply_reminded=1 WHERE msg_id=?", (r["msg_id"],))
            log("Reply reminder: " + r["subject"][:60])
    con.commit()


def daily_digest(con):
    """Every morning: one reminder with what needs attention since yesterday, grouped by inbox."""
    now = dt.datetime.now()
    today = now.date().isoformat()
    if now.hour < CFG["digest_hour"] or get_state(con, "digest") == today:
        return
    since = (now - dt.timedelta(days=1)).replace(hour=0, minute=0).isoformat()
    rows = con.execute("SELECT * FROM emails WHERE received>=? AND " + SIGNAL +
                       " ORDER BY account, importance='high' DESC, received", (since,)).fetchall()
    waiting = con.execute("SELECT kind,title,day,time FROM items WHERE status='pending' ORDER BY day").fetchall()
    upcoming = con.execute("SELECT kind,title,day,time FROM items WHERE status='added' AND day BETWEEN ? AND ? ORDER BY day",
                           (today, (now.date() + dt.timedelta(days=7)).isoformat())).fetchall()
    lines = []
    for acct in dict.fromkeys(r["account"] for r in rows):
        sel = [r for r in rows if r["account"] == acct]
        lines.append("📬 %s (%d)" % (acct, len(sel)))
        for r in sel:
            t, _ = split_summary(r["summary"])
            lines.append("• %s%s – %s" % ("❗️ " if r["importance"] == "high" else "", r["sender"], t or r["subject"]))
        lines.append("")
    if upcoming:
        lines.append("🗓 IN YOUR CALENDAR THIS WEEK")
        lines += ["• %s %s – %s" % (ICONS.get(i["kind"], ""), i["title"], pretty(i["day"], i["time"])) for i in upcoming] + [""]
    if waiting:
        lines.append("⏳ WAITING FOR YOUR OK (list '%s')" % CFG["confirm_list"])
        lines += ["• %s %s – %s" % (ICONS.get(i["kind"], ""), i["title"], pretty(i["day"], i["time"])) for i in waiting]
    hi = sum(r["importance"] == "high" for r in rows)
    add_reminder(CFG["digest_list"], "☀️ %s: %d relevant, %d important" % (now.strftime("%a %d %b"), len(rows), hi),
                 "\n".join(lines) or "Nothing needs your attention. 🎉", None, soon(), 0)
    notify("Good morning", "%d relevant message(s) since yesterday, %d important. Details in Reminders." % (len(rows), hi))
    set_state(con, "digest", today)


def sync():
    lock = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("Sync already running.")
        return
    con = db()
    approvals(con)
    total = 0
    errors = []
    for acc in accounts():
        try:
            m = imap_connect(acc)
            try:
                total += download_new(con, acc, m)
                check_replies(con, acc["name"], acc["reminders_list"], lambda: imap_answered(m))
            finally:
                try:
                    m.logout()
                except Exception:
                    pass
        except Exception as e:
            if "not found in Keychain" in str(e):  # account switched on but not set up yet: skip quietly
                log("Skipping %s: not set up yet (no login in Keychain)." % acc["name"])
                continue
            errors.append("%s: %s" % (acc["name"], e))
            log("ERROR %s: %s" % (acc["name"], e))
    for addr in gmail_accounts(con):
        try:
            import gmail_oauth
            total += download_new_gmail(con, addr)
            check_replies(con, addr, GMAIL_LIST, lambda: gmail_oauth.reply_refs(addr))
        except Exception as e:
            errors.append("%s: %s" % (addr, e))
            log("ERROR %s: %s" % (addr, e))
    analysed = analyse_pending(con)
    if CFG.get("matrix", {}).get("enabled"):
        try:
            import matrix
            matrix.sync(con)
        except Exception as e:
            errors.append("Matrix: %s" % e)
            log("ERROR Matrix: %s" % e)
    email_reminders(con)
    daily_digest(con)
    set_state(con, "last_sync", dt.datetime.now().isoformat(timespec="minutes"))
    log("Sync done: %d new email(s), %d analysed." % (total, analysed))
    if errors:
        raise RuntimeError("; ".join(errors))


def status():
    con = db()
    print("Last sync:", get_state(con, "last_sync"))
    print("Gmail accounts:", ", ".join(gmail_accounts(con)) or "none")
    for r in con.execute("SELECT account, substr(received,1,10) day, SUM(" + SIGNAL +
                         ") n, SUM(importance='high') hi, SUM(analysed=0) todo FROM emails "
                         "GROUP BY account, day ORDER BY day DESC LIMIT 20"):
        print("  %-26s %s  %3d relevant  (%d important, %d not analysed yet)" % (r["account"], r["day"], r["n"] or 0, r["hi"] or 0, r["todo"] or 0))


def check():
    ok = True
    def step(name, fn):
        nonlocal ok
        try:
            fn()
            print("  ✅", name)
        except QuotaError:
            print("  ⚠️  %s → key works, but today's free Gemini limit is used up. Mail is analysed later automatically." % name)
        except Exception as e:
            ok = False
            print("  ❌ %s → %s" % (str(name), str(e)[:300]))
    print("Checking:")
    for acc in accounts():
        step("%s: login works" % acc["name"], lambda acc=acc: imap_connect(acc).logout())
    for addr in gmail_accounts(db()):
        import gmail_oauth
        step("%s: Gmail access works" % addr, lambda addr=addr: gmail_oauth.api(addr, "profile"))
    step("Gemini answers", lambda: gemini('Reply with JSON {"ok": true}'))
    step("Reminders lists + calendars", ensure_lists_and_calendars)
    if CFG.get("matrix", {}).get("enabled"):
        import matrix
        step("Matrix login works", matrix.whoami)
    print("\nAll good." if ok else "\nFix the ❌ lines (see README), then run check again.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sync"
    if cmd == "check":
        check()
    elif cmd == "status":
        status()
    elif cmd == "gmail":
        import gmail_oauth
        gmail_oauth.main(sys.argv[2:])
    elif cmd == "sync":
        try:
            sync()
        except Exception as e:
            log("ERROR: %s" % e)
            notify("Uni Mail Helper problem", str(e))
            sys.exit(1)
    else:
        print(__doc__)
