"""conol_emails.py — email provider abstraction for conol registration.

Providers:
  gmail   — plus-alias on one mailbox (yourname+conol<SUFFIX>@gmail.com), IMAP gmail
  tonline — dedicated @t-online.de mailboxes from working_mails.txt (email:password),
            IMAP secureimap.t-online.de:993 (login verified live 2026-10-03)
  catchall — catch-all @mail.example.com через apimail admin API (ящик не нужен,
            адрес генерится на месте; чтение без IMAP)

Config (config.json -> emails section, all optional):
    {"gmail": {"enabled": true},
     "tonline": {"enabled": true,
                 "creds_file": "REPLACE_ME/Downloads/Telegram Desktop/working_mails.txt",
                 "state_file": "tonline_state.json",
                 "imap_host": "secureimap.t-online.de"},
     "catchall": {"enabled": true,
                     "api_base": "https://apimail.example.com",
                     "admin_key": "...", "domain": "mail.example.com"}}

Public API:
    providers() -> list[str]                       enabled provider ids
    next_address(tag, provider=None) -> dict|None  {"address","provider", ...} — reserves it
    wait_for_verify_link(res, since_epoch, timeout, pattern) -> url|None
"""
from __future__ import annotations

import email as email_module
import email.utils
import imaplib
import json
import os
import quopri
import re
import ssl
import threading
import time
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent
DATA_DIR = _ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)


def _cfg() -> dict:
    p = _ROOT / "config.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        return {}


_E = _cfg().get("emails", {}) or {}
_REG = _cfg().get("registration", {}) or {}

GMAIL_CFG = _E.get("gmail", {}) or {}
TONLINE_CFG = _E.get("tonline", {}) or {}
CATCHALL_CFG = _E.get("catchall", {}) or {}

CATCHALL_API = (os.environ.get("CONOL_CATCHALL_API")
             or CATCHALL_CFG.get("api_base", "https://apimail.example.com")).rstrip("/")
CATCHALL_KEY = os.environ.get("CONOL_CATCHALL_KEY") or CATCHALL_CFG.get("admin_key", "")
CATCHALL_DOMAIN = os.environ.get("CONOL_CATCHALL_DOMAIN") or CATCHALL_CFG.get("domain", "mail.example.com")

# gmail identity comes from conol_secrets (config.json -> gmail section)
try:
    from conol_secrets import GMAIL, GMAIL_APP
except Exception:  # pragma: no cover - standalone import guard
    GMAIL, GMAIL_APP = "", ""

GMAIL_PREFIX = _REG.get("email_prefix") or (GMAIL.split("@")[0] if GMAIL else "")
GMAIL_DOMAIN = _REG.get("email_domain") or (GMAIL.split("@")[-1] if GMAIL else "gmail.com")

TONLINE_CREDS = TONLINE_CFG.get(
    "creds_file", r"C:\Users\User\Downloads\Telegram Desktop\working_mails.txt")
TONLINE_STATE = DATA_DIR / TONLINE_CFG.get("state_file", "tonline_state.json")
TONLINE_IMAP = TONLINE_CFG.get("imap_host", "secureimap.t-online.de")

_lock = threading.Lock()


def providers() -> list:
    out = []
    if GMAIL and GMAIL_CFG.get("enabled", True):
        out.append("gmail")
    if TONLINE_CFG.get("enabled", True) and Path(TONLINE_CREDS).exists():
        out.append("tonline")
    if CATCHALL_CFG.get("enabled", False) and CATCHALL_KEY:
        out.append("catchall")
    return out


# ------------------------------------------------------------------ t-online

def _tonline_load_state() -> dict:
    try:
        return json.loads(TONLINE_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"offset": 0, "used": []}


def _tonline_save_state(st: dict) -> None:
    tmp = TONLINE_STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st), encoding="utf-8")
    tmp.replace(TONLINE_STATE)


def _tonline_next() -> Optional[dict]:
    """Reserve the next unused t-online mailbox. State file guards against reuse
    across processes/restarts; the in-file `used` list is the source of truth."""
    path = Path(TONLINE_CREDS)
    if not path.exists():
        return None
    with _lock:
        st = _tonline_load_state()
        used = set(st.get("used", []))
        offset = int(st.get("offset", 0))
        picked = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f):
                if idx < offset:
                    continue
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("---"):
                    continue
                if ":" not in line:
                    continue
                mail, pwd = line.split(":", 1)
                mail = mail.strip()
                if not mail.endswith("@t-online.de") or not pwd.strip():
                    continue
                if mail in used:
                    continue
                picked = {"address": mail, "password": pwd.strip(),
                          "provider": "tonline", "imap_host": TONLINE_IMAP}
                offset = idx + 1
                break
        if picked is None:
            return None
        used.add(picked["address"])
        st["used"] = sorted(used)[-5000:]   # keep the tail; offset protects the head
        st["offset"] = offset
        _tonline_save_state(st)
        return picked


# -------------------------------------------------------------------- gmail

def _gmail_next(tag: str) -> Optional[dict]:
    if not GMAIL or not GMAIL_APP:
        return None
    # GMAIL_PREFIX from config may already carry a "+conol" suffix
    # ("yourname+conol"); tags are "conol<suffix>" — keep exactly one "+"
    # so addresses stay "yourname+conol<suffix>@gmail.com" like the legacy pool.
    base = GMAIL_PREFIX.split("+")[0]
    addr = "%s+%s@%s" % (base, tag, GMAIL_DOMAIN)
    return {"address": addr, "password": None, "provider": "gmail",
            "imap_host": "imap.gmail.com", "imap_user": GMAIL, "imap_pass": GMAIL_APP}


# --------------------------------------------------------------- catchall

def _catchall_next(tag: str) -> Optional[dict]:
    """Catch-all адрес @mail.example.com. Ящик создавать не нужно — сервер
    принимает любой локальный part, читаем через admin API."""
    local = "conol" + str(int(time.time() * 1000) % 10**10)[-10:]
    if tag and tag.startswith("conol"):
        local = tag
    return {"address": "%s@%s" % (local, CATCHALL_DOMAIN), "password": None,
            "provider": "catchall"}


def _catchall_list(address: str, limit: int = 10) -> list:
    import requests
    r = requests.get("%s/admin/mails" % CATCHALL_API,
                     params={"address": address, "limit": limit, "offset": 0},
                     headers={"x-admin-auth": CATCHALL_KEY, "User-Agent": "curl/8.5.0"},
                     timeout=25)
    if r.status_code != 200:
        raise RuntimeError("apimail %s: %s" % (r.status_code, r.text[:120]))
    return r.json().get("results", [])


def _catchall_wait_verify(res: dict, since_epoch: float, timeout: int,
                       pattern) -> Optional[str]:
    """Поллинг apimail до письма Conol со ссылкой верификации."""
    import requests  # noqa: F401  (импорт ради единообразия ошибок)
    address = res["address"]
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        try:
            mails = sorted(_catchall_list(address), key=lambda m: m.get("id", 0), reverse=True)
        except Exception:
            mails = []
        for m in mails:
            mid = m.get("id")
            if mid in seen:
                continue
            seen.add(mid)
            raw = m.get("raw", "")
            msg = email_module.message_from_string(raw)
            try:
                msg_ts = email_module.utils.mktime_tz(
                    email_module.utils.parsedate_tz(str(msg.get("Date", ""))))
            except Exception:
                msg_ts = None
            if msg_ts and msg_ts < since_epoch - 30:
                continue
            body = _plain_body(msg)
            match = pattern.search(body)
            if match:
                token = match.group(1).replace("=\r\n", "").replace("=\n", "")
                callback = match.group(2).replace("=\r\n", "").replace("=\n", "")
                return ("https://conol.ai/api/auth/verify-email?token=%s&callbackURL=%s"
                        % (token, callback))
        time.sleep(4)
    return None


def _plain_body(msg) -> str:
    """Склеить текст письма (html+plain), декодировав base64/quoted-printable."""
    out = []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if payload:
                out.append(payload.decode("utf-8", "ignore"))
    return "\n".join(out)


# ---------------------------------------------------------------- dispatcher

def next_address(tag: str, provider: str = None) -> Optional[dict]:
    """Reserve an address for a new conol account.

    provider: 'gmail' | 'tonline' | 'catchall' | None (first enabled).
    Returns dict with address/provider/imap creds, or None if exhausted/disabled.
    """
    order = [provider] if provider else providers()
    for p in order:
        if p == "gmail":
            r = _gmail_next(tag)
        elif p == "tonline":
            r = _tonline_next()
        elif p == "catchall":
            r = _catchall_next(tag)
        else:
            continue
        if r:
            return r
    return None


def mark_used(res: dict) -> None:
    """Confirm a reserved address is permanently consumed.

    t-online addresses are already written to the state file at reserve time, so
    this only matters for bookkeeping (e.g. an address that turned out to be
    already registered on conol must never be handed out again — it is not,
    because reserve() persisted it; this call is an explicit no-op hook)."""
    pass


def wait_for_verify_link(res: dict, since_epoch: float, timeout: int = 180,
                         url_re: str = None) -> Optional[str]:
    """Poll the provider mailbox for the conol verification link.

    res: the dict from next_address(). gmail matches on the alias in To:;
    tonline matches on any conol mail (the box is dedicated).
    """
    pattern = re.compile(url_re or (
        r"https://conol\.ai/api/auth/verify-email\?token=([^&\s\"'<>]+)"
        r"(?:&amp;|&)callbackURL=([^\s\"'<>]+)"), re.IGNORECASE)
    if res.get("provider") == "catchall":
        return _catchall_wait_verify(res, since_epoch, timeout, pattern)
    host = res.get("imap_host", "imap.gmail.com")
    user = res.get("imap_user") or res["address"]
    pwd = res.get("imap_pass") or res.get("password") or ""
    target = res["address"].lower()

    deadline = time.time() + timeout
    while time.time() < deadline:
        mail = None
        try:
            mail = imaplib.IMAP4_SSL(host, 993,
                                     ssl_context=ssl.create_default_context(), timeout=20)
            mail.login(user, pwd)
            mail.select("INBOX")
            status, data = mail.search(None, 'FROM "Conol"')
            if status != "OK" or not data or not data[0]:
                time.sleep(4)
                continue
            for message_id in reversed(data[0].split()[-30:]):
                status, rows = mail.fetch(message_id, "(RFC822)")
                if status != "OK" or not rows or not isinstance(rows[0], tuple):
                    continue
                raw = rows[0][1]
                message = email_module.message_from_bytes(raw)
                if res.get("provider") == "gmail":
                    to_header = str(message.get("To", ""))
                    if target not in to_header.lower():
                        continue
                message_ts = email_module.utils.mktime_tz(
                    email_module.utils.parsedate_tz(str(message.get("Date", ""))))
                if message_ts and message_ts < since_epoch - 30:
                    continue
                decoded = quopri.decodestring(raw).decode("utf-8", errors="replace")
                m = pattern.search(decoded)
                if m:
                    token = m.group(1).replace("=\r\n", "").replace("=\n", "")
                    callback = m.group(2).replace("=\r\n", "").replace("=\n", "")
                    return ("https://conol.ai/api/auth/verify-email?token=%s&callbackURL=%s"
                            % (token, callback))
        except Exception:
            pass
        finally:
            if mail is not None:
                try:
                    mail.logout()
                except Exception:
                    pass
        time.sleep(4)
    return None


if __name__ == "__main__":
    import sys
    print("providers:", providers())
    cmd = sys.argv[1] if len(sys.argv) > 1 else "peek"
    if cmd == "peek":
        for p in providers():
            r = next_address("peek%d" % int(time.time()), provider=p)
            print(p, "->", (r or {}).get("address"))
    elif cmd == "reserve":
        p = sys.argv[2] if len(sys.argv) > 2 else None
        r = next_address("t%d" % int(time.time() * 1000) % 10**8, provider=p)
        print(json.dumps({k: v for k, v in (r or {}).items() if "pass" not in k.lower()}))
