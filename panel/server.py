#!/usr/bin/env python3
"""server.py — панель conol-control-panel по PANEL-SPEC (stdlib, без CDN и зависимостей).

Запуск:
    python panel/server.py                # 127.0.0.1:9903 (порт зарезервирован, см. autoreg/docs/PANEL-PORTS.md)
    CONOL_PANEL_PORT=9903 python panel/server.py

Эндпоинты (JSON, только 127.0.0.1):
    GET  /                        index.html
    GET  /api/summary             счётчики пула, кредиты, капча, прокси, last_run
    GET  /api/accounts            строки пула + cookies: статус, кредиты, ключи (маскированно)
    GET  /api/accounts/token      ?email=... -> полный session_token (для кнопки «копировать»)
    POST /api/accounts/check      живая перепроверка (get-session + balance), атомарная запись пула
    POST /api/register            {count, verify, no_proxy?} -> {job_id}: фоновый AFK-воркер (до 200, дефолт 42)
    GET  /api/job                 {job_id, status, started_at, done, total, last_error, log_tail, proxy_mode}
    POST /api/job/stop            стоп текущего прогона (флаг + SIGTERM, слот не ломается)
    GET  /api/captcha             chrome_cdp + баланс anticaptcha, если ключи есть
    GET  /api/models              {models:[{id,name,status,note,last_checked}]} из docs/MODELS.md
    GET  /api/proxies             список прокси + статусы (ok/fail/не проверен) + режим
    POST /api/proxies             перепроверить все прокси через ip-echo (фоново)
    POST /api/proxies/mode        {direct: true|false} — чекбокс «без прокси», режим переживает рестарт
    GET  /api/keys                gateway api_key + agent apiKey + токены аккаунтов (маскированно)
    GET  /api/usage               расход (USAGE-SPEC): range=1h|24h|7d|30d|all, bucket=hour|day|month
    GET  /api/usage/raw?tail=N    сырой хвост ledger data/usage.jsonl
    GET  /api/logs?tail=200       хвост лога (?name=afk|register|scale|chain|gateway|panel)

Только stdlib: http.server + urllib + threading. Пул читается/пишется атомарно, а
запись в пул не пересекается с реггером (проверяется pid-слот conol_register).
Прокси-слой тоже stdlib (conol_proxy): панель не тянет requests.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PANEL_DIR = Path(__file__).resolve().parent
BASE_DIR = PANEL_DIR.parent
sys.path.insert(0, str(BASE_DIR))  # conol_*.py лежат в корне проекта

import conol_captcha    # noqa: E402
import conol_emails     # noqa: E402
import conol_proxy      # noqa: E402
import conol_register   # noqa: E402
import conol_usage      # noqa: E402
import afk_worker       # noqa: E402  (PANEL_DIR в sys.path[0] при запуске скриптом)

SERVICE = "conol.ai"
VERSION = "8.0"
HOST = "127.0.0.1"
DEFAULT_PORT = 9903          # авторег-реестр: autoreg/docs/PANEL-PORTS.md
PORT = int(os.environ.get("CONOL_PANEL_PORT", str(DEFAULT_PORT)))
STATIC = PANEL_DIR / "static" / "index.html"
MODELS_DOC = BASE_DIR / "docs" / "MODELS.md"
MODEL_STATUSES = ("verified", "available", "downgraded", "dead", "unknown")

DATA_DIR = conol_register.DATA_DIR
POOL_FILE = conol_register.POOL_FILE
COOKIE_NAME = "__Secure-better-auth.session_token"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/140.0 Safari/537.36")
CHECK_WORKERS = 4           # живая перепроверка: 4 параллельных GET'а, conol отдаёт 429 при большем
ACTIVE_JOB_STATUSES = ("starting", "running")   # job считается активным в обоих состояниях

LOG_FILES = {
    "afk": afk_worker.AFK_LOG,
    "register": DATA_DIR / "conol_register_run.log",
    "scale": DATA_DIR / "conol_scale_run.log",
    "chain": DATA_DIR / "conol_chain.log",
    "gateway": DATA_DIR / "gateway.log",
    "panel": DATA_DIR / "panel.log",
}

_gw_cache = {"ts": 0.0, "online": False}
_agent_cache = {"ts": 0.0, "data": None}
_captcha_cache = {"ts": 0.0, "balance": None}
_cache_lock = threading.Lock()

PROXY_STATE = conol_proxy.ProxyState()          # data/proxies.json: ротация + статусы
PANEL_LOG = DATA_DIR / "panel.log"

# ─── учёт расхода (USAGE-SPEC): источники conol ─────────────────────────────
USAGE_PREFIX = "conol"                     # префикс ключей дедупа в ledger
GATEWAY_DB = DATA_DIR / "conol_keystore.db"          # SQLite шлюза :9999 (таблица usage)
GATEWAY_STATE = DATA_DIR / "conol_gateway_state.json"
GATEWAY_ROWS_MAX = 20000                   # не вычитываем весь журнал шлюза за раз
SNAPSHOT_INTERVAL_SEC = 3600               # «раз в час, пока панель запущена» (USAGE-SPEC §1)
_last_snapshot = {"hour": None}


def plog(msg: str) -> str:
    """Строка в data/panel.log (её же показывает вкладка «Логи», имя panel)."""
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        PANEL_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(PANEL_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    return line


# ─── мелкие утилиты ─────────────────────────────────────────────────────────

def mask(value: str, keep: int = 6) -> str:
    """IxXDbR…x14%3D — достаточно, чтобы узнать ключ, мало, чтобы его утащить."""
    if not value:
        return ""
    if len(value) <= keep + 4:
        return value[:2] + "…" + value[-2:]
    return "%s…%s" % (value[:keep], value[-4:])


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def read_pool() -> list:
    try:
        return [json.loads(line) for line in POOL_FILE.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except FileNotFoundError:
        return []
    except ValueError:
        # хвостовая обрезанная строка (процесс убили посреди записи) — читаем что цело
        rows = []
        for line in POOL_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows


def config() -> dict:
    return _read_json(BASE_DIR / "config.json", {})


def cookie_file_for(row: dict):
    """Файл cookies строки пула. После рефактора путь в пуле может быть старым
    (записи до переезда) — тогда ищем тот же basename в data/."""
    raw = row.get("cookies_path") or ""
    if not raw:
        return None
    direct = Path(raw)
    if direct.exists():
        return direct
    alt = DATA_DIR / direct.name
    return alt if alt.exists() else None


def classify(row: dict, cookies_ok: bool) -> tuple[str, str]:
    """(status по спеке, note). Словарь спеки: ok|banned|no_credits|unverified|failed|unknown.

    Пул пишет `live`/`unverified`; 401 от get-session (в /api/accounts/check) переводит
    строку в banned, нулевой баланс — в no_credits.
    """
    raw = str(row.get("status") or "").lower()
    token = row.get("session_token") or ""
    notes = []
    if raw in ("banned", "dead", "blocked"):
        return "banned", "get-session больше не пускает (401)"
    if not token:
        if raw == "unverified":
            return "unverified", "email подтверждён не был — только очередь на добор"
        return "failed", "нет session_token"
    if raw == "unverified":
        return "unverified", "email не подтверждён (сессии нет)"
    credits = row.get("credits")
    if credits == 0:
        return "no_credits", "баланс 0 — аккаунт жив, но пуст"
    if not cookies_ok:
        notes.append("нет файла cookies (шлюз берёт токен из пула — работает)")
    if row.get("email_verified") is False:
        notes.append("emailVerified=false")
    if raw and raw != "live":
        notes.append("pool.status=%s" % raw)
    return "ok", "; ".join(notes)


def account_view(row: dict, gateway_key: str) -> dict:
    cookies_path = cookie_file_for(row)
    status, note = classify(row, bool(cookies_path))
    token = row.get("session_token") or ""
    expires = row.get("token_expires")
    return {
        "name": row.get("name") or "",
        "email": row.get("email") or "",
        "status": status,
        "pool_status": row.get("status") or "",
        "credits": row.get("credits"),
        "api_key": mask(token) if token else "",           # «ключ» аккаунта (маскированно)
        "api_key_full": False,
        "gateway_api_key": gateway_key,
        "token_masked": mask(token) if token else "",
        "token_len": len(token),
        "token_expires": expires,
        "created_at": row.get("created_at"),
        "last_login": row.get("last_login"),
        "last_check": row.get("last_check"),
        "email_provider": row.get("email_provider") or "",
        "cookies": bool(cookies_path),
        "cookies_path": str(cookies_path) if cookies_path else "",
        "note": note,
    }


def accounts() -> list:
    gateway_key = config().get("gateway", {}).get("api_key", "")
    return [account_view(row, gateway_key) for row in read_pool()]


def summarize_credits(views: list) -> float:
    return round(sum(v.get("credits") or 0 for v in views if isinstance(v.get("credits"), (int, float))), 2)


def _raw_pool_statuses() -> dict:
    """Сырые pool.status → сколько строк (для честной шапки «Ключей»)."""
    out = {}
    for row in read_pool():
        key = str(row.get("status") or "?")
        out[key] = out.get(key, 0) + 1
    return out


def count_statuses(views: list) -> dict:
    counts = {"total": len(views), "ok": 0, "banned": 0, "no_credits": 0,
              "failed": 0, "unverified": 0, "unknown": 0}
    for v in views:
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    return counts


# ─── conol.ai HTTP (stdlib) ─────────────────────────────────────────────────

def conol_get(path: str, token: str, timeout: int = 15, proxy=None):
    """(status_code|None, body|error_text). proxy — dict из conol_proxy (None → напрямую)."""
    req = urllib.request.Request(
        conol_register.BASE_URL + path,
        headers={"Accept": "application/json", "User-Agent": UA,
                 "Cookie": "%s=%s" % (COOKIE_NAME, token)},
    )
    try:
        with conol_proxy.urllib_opener(proxy).open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — сеть/таймаут не должны валить панель
        return None, "%s: %s" % (type(exc).__name__, exc)


def check_one(row: dict, proxy=None) -> dict:
    """Один живой прогон: get-session (кто/бан) + balance (кредиты). $0, без капчи.

    proxy передаётся и в get-session, и в balance — один exit-IP на проверку;
    строки пула перепроверяются через ротацию (как и регистрация).
    """
    token = row.get("session_token") or ""
    email = (row.get("email") or "").lower()
    out = {"email": email, "checked_at": time.time(),
           "proxy": (proxy or {}).get("raw"),
           "proxy_masked": conol_proxy.mask((proxy or {}).get("raw")) if proxy else None}
    if not token:
        out["status"] = "unverified" if str(row.get("status")) == "unverified" else "failed"
        return out
    code, body = conol_get("/api/auth/get-session", token, proxy=proxy)
    if code == 401:
        out.update({"status": "banned", "note": "get-session 401"})
    elif code == 200:
        try:
            user = json.loads(body).get("user") or {}
        except ValueError:
            user = {}
        got = (user.get("email") or "").lower()
        if got and got != email:
            # токен отвечает чужой почтой — строка пула испорчена, аккаунт не наш
            out.update({"status": "failed", "note": "email mismatch: %s" % user.get("email")})
        else:
            out["email_verified"] = bool(user.get("emailVerified"))
            out["status"] = "ok" if user.get("emailVerified") else "unverified"
            if user.get("banned"):
                out["status"] = "banned"
    elif code is None:
        out.update({"status": "unknown", "note": "сеть: %s" % body[:120]})
    else:
        out.update({"status": "unknown", "note": "get-session HTTP %s" % code})

    if out["status"] in ("ok", "no_credits", "unverified"):
        code, body = conol_get("/api/billing/balance", token, proxy=proxy)
        if code == 200:
            try:
                out["credits"] = json.loads(body).get("total")
            except ValueError:
                pass
        elif code == 401:
            out.update({"status": "banned", "note": "balance 401"})
    if out["status"] == "ok" and out.get("credits") == 0:
        out["status"] = "no_credits"
        out["note"] = "баланс 0 (daily не начислены)"
    return out


def apply_check(results: list) -> int:
    """Записать результаты перепроверки в пул. Перечитываем файл в момент записи:
    строки, дописанные реггером за время проверки, обязаны выжить."""
    by_email = {r["email"]: r for r in results if r.get("email")}
    rows = read_pool()
    updated = 0
    for row in rows:
        hit = by_email.get((row.get("email") or "").lower())
        if not hit:
            continue
        status = hit["status"]
        if status == "banned":
            row["status"] = "banned"
        elif status == "ok":
            row["status"] = "live"
        elif status == "no_credits":
            row["status"] = "live"          # аккаунт жив; пустота — это про кредиты
        elif status == "unverified":
            row["status"] = "unverified"
        elif status == "failed":
            row["status"] = "failed"
        if isinstance(hit.get("credits"), (int, float)):
            row["credits"] = hit["credits"]
        row["last_check"] = round(hit["checked_at"], 1)
        if hit.get("note"):
            row["last_check_note"] = hit["note"]
        else:
            row.pop("last_check_note", None)
        updated += 1
    tmp = POOL_FILE.with_name(POOL_FILE.name + ".tmp")
    tmp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")
    os.replace(tmp, POOL_FILE)
    return updated


def foreign_slot_holder() -> int:
    """Живой чужой держатель пул-слота (CLI-реггер, refresh, другой воркер). 0 — свободен."""
    pid_file = conol_register.PID_FILE
    try:
        holder = int(pid_file.read_text(encoding="utf-8").split("\n", 1)[0].strip())
    except (OSError, ValueError):
        return 0
    if not holder or holder == os.getpid():
        return 0
    try:
        age = time.time() - pid_file.stat().st_mtime
    except OSError:
        return 0
    if age >= conol_register.SLOT_MAX_HOLD_SEC:
        return 0
    return holder if conol_register._pid_alive(holder) else 0


# ─── прокси (проверка / панель) ─────────────────────────────────────────────

_proxy_lock = threading.Lock()
_proxy_check = {"checking": False, "started_at": None, "finished_at": None,
                "checked": 0, "total": 0}


def proxies_payload() -> dict:
    """GET /api/proxies: список + статусы + режим сети (честная пометка «напрямую»).

    Список берём через configured_proxies: режим «без прокси» не должен прятать
    настроенный пул — панель показывает его и пишет, что ротация выключена.
    """
    proxies, bad = conol_proxy.configured_proxies()
    payload = conol_proxy.describe(proxies, PROXY_STATE)
    with _proxy_lock:
        payload["checking"] = _proxy_check["checking"]
        payload["last_check_run"] = _proxy_check["finished_at"] or _proxy_check["started_at"]
        payload["checked"] = _proxy_check["checked"]
        payload["total_check"] = _proxy_check["total"]
    payload["bad_lines"] = bad
    payload["file"] = str(conol_proxy.proxies_file())
    payload["direct"] = payload["forced_direct"]     # чекбокс «без прокси» в UI
    if payload["count"] and payload["mode"] == "proxy":
        payload["user_note"] = (
            "Вставь прокси в data/proxies.txt (по строке) или config.json → \"proxies\" "
            "и нажми «Перепроверить». Прокси применяется и к Chrome (капча), и к HTTP "
            "(регистрация): один exit-IP на аккаунт, ротация по кругу."
        )
    elif payload["count"]:
        payload["user_note"] = (
            "Прокси заданы (%d шт), но включён режим «без прокси» — прогоны идут с "
            "домашнего IP. Снять галочку, чтобы вернуть ротацию." % payload["count"])
    else:
        payload["user_note"] = (
            "Прокси не заданы — работаем с домашнего IP, а conol режет серию sign-up "
            "по сети (429 RATE_LIMITED).")
    return payload


def start_proxy_check() -> bool:
    with _proxy_lock:
        if _proxy_check["checking"]:
            return False
        _proxy_check.update(checking=True, started_at=time.time(),
                            finished_at=None, checked=0, total=0)
    threading.Thread(target=_proxy_check_worker, name="conol-proxy-check", daemon=True).start()
    return True


def _proxy_check_worker() -> None:
    # Проверяем настроенный пул, даже когда включён режим «без прокси»:
    # «Перепроверить» — это и способ убедиться, что пул жив перед снятием галочки.
    proxies, _bad = conol_proxy.configured_proxies()
    with _proxy_lock:
        _proxy_check["total"] = len(proxies)
    plog("▶ проверка прокси: %d шт (ip-echo через каждый)" % len(proxies))
    results = {}
    for p in proxies:
        res = conol_proxy.check_proxy(p)
        results[p["raw"]] = res
        with _proxy_lock:
            _proxy_check["checked"] += 1
        plog("   %s %s%s" % ("ok  " if res["ok"] else "fail", res["masked"],
                             " → %s (%s ms)" % (res["ip"], res["ms"]) if res["ok"]
                             else " — %s" % res["error"]))
    PROXY_STATE.merge_status(results)
    PROXY_STATE.unban_all()          # перепроверка = чистый лист для подряд-фейлов
    with _proxy_lock:
        _proxy_check.update(checking=False, finished_at=time.time())
    if proxies:
        ok = sum(1 for r in results.values() if r["ok"])
        plog("■ проверка прокси: ok %d/%d" % (ok, len(proxies)))
    else:
        plog("   прокси не заданы: " + conol_proxy.DIRECT_NOTE)


def _proxy_check_running() -> bool:
    with _proxy_lock:
        return _proxy_check["checking"]


def proxy_mode_info() -> dict:
    """Режим сети для /api/summary: сколько прокси и честная пометка, если напрямую."""
    proxies, bad = conol_proxy.configured_proxies()
    forced = conol_proxy.direct_mode()
    mode = "direct" if (not proxies or forced) else "proxy"
    return {
        "count": len(proxies),
        "mode": mode,
        "forced_direct": forced,          # «без прокси» (чекбокс панели / CLI / env)
        "checking": _proxy_check_running(),
        "bad_lines": len(bad),
        "note": None if mode == "proxy" else conol_proxy.DIRECT_NOTE,
    }


# ─── job / AFK ──────────────────────────────────────────────────────────────

def reconcile_job(job: dict) -> dict:
    """Привести статус job к реальности.

    `starting` — состояние между «панель запустила процесс» и «воркер дошёл до первого
    аккаунта»: оно тоже АКТИВНО. Проверка только по `running` пропускала второй прогон
    (пойман 07.10: два воркера на одном job-файле; пул спасло то, что второй отказался
    брать занятый pid-слот). Живость определяется pid'ом: SIGKILL не оставил бы записи.
    """
    if job.get("status") in ACTIVE_JOB_STATUSES:
        pid = job.get("pid")
        if not pid or not conol_register._pid_alive(int(pid)):
            job["status"] = "stopped" if afk_worker.STOP_FLAG.exists() else "failed"
            job["last_error"] = job.get("last_error") or "воркер умер (pid %s не найден)" % pid
            job["finished_at"] = job.get("finished_at") or time.time()
    return job


def job_active(job: dict) -> bool:
    """Идёт ли прогон ПРЯМО СЕЙЧАС (starting/running + живой pid)."""
    if job.get("status") not in ACTIVE_JOB_STATUSES:
        return False
    pid = job.get("pid")
    return bool(pid) and conol_register._pid_alive(int(pid))


def log_tail(path: Path, tail: int, offset: int = 0) -> list:
    if not path.exists():
        return []
    try:
        with open(path, "rb") as fh:
            if offset:
                fh.seek(offset)
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[-tail:]


def job_view(tail: int = 60) -> dict:
    job = reconcile_job(afk_worker.read_job())
    if not job:
        return {"job_id": None, "status": "idle", "started_at": None, "done": 0,
                "total": 0, "last_error": None, "log_tail": []}
    job["log_tail"] = log_tail(afk_worker.AFK_LOG, tail, int(job.get("log_offset") or 0))
    job["log_file"] = str(afk_worker.AFK_LOG)
    return job


# ─── капча / ключи ──────────────────────────────────────────────────────────

def captcha_info() -> dict:
    keys = list(conol_captcha.ANTICAPTCHA_KEYS)
    balance = None
    fresh = False
    if keys:
        with _cache_lock:
            fresh = time.time() - _captcha_cache["ts"] < 60
            if fresh:
                balance = _captcha_cache["balance"]
        if not fresh:
            balance = None
            for key in keys:
                try:
                    req = urllib.request.Request(
                        "https://api.anti-captcha.com/getBalance",
                        data=json.dumps({"clientKey": key}).encode(),
                        headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read().decode())
                    if data.get("errorId") == 0:
                        balance = data.get("balance")
                        break
                except Exception:  # noqa: BLE001
                    continue
            with _cache_lock:
                _captcha_cache.update({"ts": time.time(), "balance": balance})
    cdp_alive = False
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % conol_captcha.CDP_PORT,
                                    timeout=2) as resp:
            cdp_alive = resp.status == 200
    except Exception:  # noqa: BLE001
        cdp_alive = False
    chrome_ok = Path(conol_captcha.CHROME_PATH).exists()
    return {
        "provider": ",".join(conol_captcha.PROVIDERS),
        "providers": list(conol_captcha.PROVIDERS),
        "configured": bool(chrome_ok or cdp_alive),
        "balance": balance,
        "chrome": {"path": conol_captcha.CHROME_PATH, "cdp_port": conol_captcha.CDP_PORT,
                   "cdp_alive": cdp_alive, "headless": conol_captcha.HEADLESS,
                   "cdp_headless": conol_captcha._live_browser_headless() if cdp_alive else None,
                   "display": conol_captcha.DISPLAY_OVERRIDE or os.environ.get("DISPLAY", ""),
                   "display_alive": conol_captcha.display_alive()},
        "anticaptcha": {"configured": bool(keys), "keys": len(keys), "balance": balance},
        "manual": {"needed": False,
                   "hint": "reCAPTCHA v3 решается автоматически (бесплатный chrome_cdp)",
                   "url": conol_register.BASE_URL},
        "solves_today": solves_today(),
    }


def solves_today() -> int:
    """Сколько капч решено с местной полуночи — по results-логу реггера."""
    import datetime
    midnight = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    total = 0
    path = conol_register.RESULTS_FILE
    if not path.exists():
        return 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if (row.get("ts") or 0) >= midnight:
            total += int(row.get("captcha_solves") or 0)
    return total


def gateway_online() -> bool:
    with _cache_lock:
        if time.time() - _gw_cache["ts"] < 5:
            return _gw_cache["online"]
    cfg = config().get("gateway", {})
    host = cfg.get("host", "127.0.0.1")
    port = cfg.get("port", 9999)
    online = False
    try:
        with urllib.request.urlopen("http://%s:%s/health" % (host, port), timeout=1.5) as resp:
            online = resp.status == 200
    except Exception:  # noqa: BLE001 — шлюз может быть не поднят, это не ошибка панели
        online = False
    with _cache_lock:
        _gw_cache.update({"ts": time.time(), "online": online})
    return online


def models_view() -> dict:
    """Модели сервиса из docs/MODELS.md (выписка из autoreg/docs/MODELS.md, живые проверки).

    Читаем документ, а не хардкод: список меняется (новые модели/даунгрейды), и
    единственный источник правды по нему — markdown, который правит оператор.
    """
    if not MODELS_DOC.exists():
        return {"models": [], "source": str(MODELS_DOC), "error": "docs/MODELS.md не найден"}
    models = parse_models_table(MODELS_DOC.read_text(encoding="utf-8", errors="replace"))
    by_status = {}
    for m in models:
        by_status[m["status"]] = by_status.get(m["status"], 0) + 1
    dates = [m["last_checked"] for m in models if m.get("last_checked")]
    return {
        "models": models,
        "source": "docs/MODELS.md",
        "source_ref": "autoreg/docs/MODELS.md (раздел conol.ai)",
        "source_date": max(dates) if dates else None,
        "by_status": by_status,
        "count": len(models),
    }


def parse_models_table(text: str) -> list:
    """Разобрать markdown-таблицу с шапкой id|name|status|note|checked.

    Парсер намеренно строгий к шапке (иначе поймает любую другую таблицу в документе)
    и терпимый к содержимому: лишние обратные кавычки и колонки не ломают строку.
    """
    header = None
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            header = None
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if header is None:
            if [c.lower() for c in cells[:3]] == ["id", "name", "status"]:
                header = [c.lower() for c in cells]
            continue
        if all(set(c) <= set("-: ") for c in cells):   # строка-разделитель |---|---|
            continue
        row = dict(zip(header, cells))
        model_id = row.get("id") or ""
        if not model_id:
            continue
        status = (row.get("status") or "unknown").lower()
        if status not in MODEL_STATUSES:
            status = "unknown"
        out.append({"id": model_id, "name": row.get("name") or model_id,
                    "status": status, "note": row.get("note") or "",
                    "last_checked": row.get("checked") or None})
    return out


def keys_sources() -> list:
    """Файлы data/, из которых вкладка «Ключи» реально берёт значения.

    Вкладка обязана быть честной: чего на диске нет — то «н/д», поэтому источники
    отдаются с признаком существования, а не списком «что должно быть».
    """
    items = [
        (POOL_FILE, "пул: email · пароль conol · session_token · кредиты"),
        (BASE_DIR / "config.json", "gateway.api_key · emails.*.admin_key (ключ почты)"),
        (conol_register.RESULTS_FILE, "журнал попыток (ok/ошибка) — не секреты"),
        (DATA_DIR / "usage_keys.json", "ключи ledger'а учёта (не секреты)"),
        (GATEWAY_DB, "SQLite шлюза :9999 (журнал запросов)"),
    ]
    out = []
    for path, what in items:
        try:
            st = path.stat()
        except OSError:
            out.append({"name": path.name, "exists": False, "what": what})
            continue
        out.append({"name": path.name, "exists": True, "bytes": st.st_size,
                    "mtime": st.st_mtime, "what": what})
    return out


def pool_token_files(row: dict) -> list:
    """Пул-токены строки: файлы, которые РЕАЛЬНО лежат в data/ по этому аккаунту."""
    out = []
    cookie = cookie_file_for(row)
    if cookie is not None:
        try:
            st = cookie.stat()
            out.append({"name": cookie.name, "exists": True, "bytes": st.st_size,
                        "mtime": st.st_mtime})
        except OSError:
            out.append({"name": cookie.name, "exists": False})
    elif row.get("cookies_path"):
        out.append({"name": Path(str(row["cookies_path"])).name, "exists": False})
    return out


def keys_view() -> dict:
    """GET /api/keys — всё, что оператор хочет уметь скопировать.

    Панель слушает только 127.0.0.1, поэтому здесь (в отличие от /api/summary)
    отдаются и полные секреты: пароль аккаунта, session_token, gateway api_key.
    Рядом с полным значением всегда идёт маска — UI показывает маску, а копирует
    полное по кнопке. В /api/summary секреты не попадают (проверяется selfcheck).
    """
    cfg = config()
    gw = cfg.get("gateway", {})
    rows = read_pool()
    account_keys = []
    live = 0
    credits = 0.0
    for row in rows:
        token = row.get("session_token") or ""
        password = row.get("password") or ""
        mailbox = row.get("mailbox_password") or ""
        expires = row.get("token_expires")
        status = classify(row, bool(cookie_file_for(row)))[0]
        if status == "ok":
            live += 1
        if isinstance(row.get("credits"), (int, float)):
            credits += row["credits"]
        account_keys.append({
            "name": row.get("name") or "",
            "email": row.get("email") or "",
            "status": status,
            "credits": row.get("credits"),
            # секреты (локальная панель + кнопка «копировать»)
            "password": password,
            "password_masked": mask(password) if password else "",
            "session_token": token,
            "token_masked": mask(token) if token else "",
            "token_len": len(token),
            "mailbox_password": mailbox,
            "email_provider": row.get("email_provider") or "",
            "pool_token_files": pool_token_files(row),
            "expires": expires,
            "expires_in_days": round((expires - time.time()) / 86400, 1)
            if isinstance(expires, (int, float)) else None,
        })
    gw_key = gw.get("api_key", "")
    return {
        "service": SERVICE,
        "gateway": {"host": gw.get("host", "127.0.0.1"), "port": gw.get("port", 9999),
                    "api_key": gw_key, "api_key_masked": mask(gw_key),
                    "api_key_present": bool(gw_key), "online": gateway_online()},
        "accounts": account_keys,
        "pool": {"accounts": len(rows), "live": live, "credits": round(credits, 2),
                 "raw_statuses": _raw_pool_statuses()},
        "agent": agent_key(rows),
        "sources": keys_sources(),
        "session_token_source": "GET /api/accounts/token?email=<email> — полный токен по кнопке",
        "secrets_note": "полные значения только на 127.0.0.1; в /api/summary секретов нет",
        "fetched_at": time.time(),
    }


def agent_key(rows: list) -> dict:
    """agent apiKey live-аккаунта: GET /api/agent-servers. Сервер отдаёт ключ УЖЕ
    замаскированным (6faee3ec****) — полного значения в API нет, поэтому показываем как есть."""
    with _cache_lock:
        cached = _agent_cache["data"]
        fresh = time.time() - _agent_cache["ts"] < 120
    if cached is not None and fresh:
        return cached
    token = next((r.get("session_token") for r in rows if r.get("session_token")), None)
    if not token:
        out = {"error": "нет live-аккаунта с session_token"}
    else:
        code, body = conol_get("/api/agent-servers", token)
        if code == 200:
            try:
                servers = json.loads(body)
            except ValueError:
                servers = []
            if isinstance(servers, list) and servers:
                first = servers[0] or {}
                out = {"name": first.get("name"), "url": first.get("url"),
                       "api_key_masked": first.get("apiKey"),
                       "enabled": first.get("enabled"), "is_default": first.get("isDefault"),
                       "servers": len(servers),
                       "note": "conol маскирует ключ на своей стороне"}
            else:
                out = {"error": "пустой список agent-servers"}
        else:
            out = {"error": "GET /api/agent-servers -> HTTP %s %s" % (code, str(body)[:120])}
    with _cache_lock:
        _agent_cache.update({"ts": time.time(), "data": out})
    return out


# ─── учёт расхода (USAGE-SPEC §1–2) ─────────────────────────────────────────

def _key_mask(raw: str) -> str:
    """api_key шлюза → «первые 8…»: в ledger попадает метка, не секрет."""
    if not raw:
        return "?"
    return (raw[:8] + "…") if len(raw) > 9 else (raw[:2] + "…")


def _free_captcha_only() -> bool:
    """Платный контур anticaptcha не настроен → каждое решение chrome_cdp бесплатно."""
    return not conol_captcha.ANTICAPTCHA_KEYS


def _results_events() -> list:
    """Регистрации + решения капчи из data/conol_register_results.jsonl.

    Одна строка = одна попытка аккаунта: `ok`, `email`, `error`, `elapsed_s` и
    `captcha_solves` (сколько решений ушло на попытку). Решения разворачиваются
    поштучно: один event = одно решение, иначе счётчик «решений капчи» врал бы.
    """
    path = conol_register.RESULTS_FILE
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    free = _free_captcha_only()
    src = "data/" + path.name
    events = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        ts = rec.get("ts") or rec.get("started_at")
        ok = bool(rec.get("ok"))
        email = rec.get("email")
        events.append({
            "kind": "registration", "ts": ts, "account": email, "ok": ok,
            "credits": None,          # 600 стартовых — остаток, а не расход
            "meta": {"src": src, "status": "ok" if ok else "failed",
                     "provider": rec.get("email_provider"),
                     "batch_index": rec.get("batch_index"),
                     "elapsed_s": rec.get("elapsed_s"), "mode": rec.get("mode"),
                     "error": (str(rec.get("error"))[:160] or None) if rec.get("error") else None},
            "event_key": "%s:reg:%d" % (USAGE_PREFIX, i),
        })
        solves = rec.get("captcha_solves")
        if isinstance(solves, int) and not isinstance(solves, bool) and 0 < solves <= 200:
            for j in range(solves):
                events.append({
                    "kind": "captcha_solve", "ts": ts, "account": email, "ok": True,
                    # chrome_cdp бесплатен; на платном пути стоимость в results-логе
                    # не отмечена — $ честно «н/д», а не выдуманный ноль
                    "cost_usd": 0.0 if free else None,
                    "meta": {"src": src, "who": "chrome_cdp", "precision": "results-log",
                             "solve_index": j + 1, "solves_in_attempt": solves},
                    "event_key": "%s:cap:%d:%d" % (USAGE_PREFIX, i, j),
                })
    return events


def _pool_snapshot_events() -> list:
    """Снапшоты остатка из пула (дельты GET /api/billing/balance).

    Пул общий с CLI-рефрешером: conol_refresh и панельная перепроверка пишут сюда
    `credits` + отметку времени, поэтому дельты баланса видны и без панели. Ключ
    включает отметку — одна проверка = один снапшот, история не переписывается.
    """
    events = []
    for i, row in enumerate(read_pool()):
        credits = row.get("credits")
        if isinstance(credits, bool) or not isinstance(credits, (int, float)):
            continue
        email = (row.get("email") or "").lower()
        if not email:
            continue
        stamp = row.get("last_check") or row.get("created_at") or row.get("last_login")
        events.append({
            "kind": "balance_snapshot", "ts": stamp, "account": email,
            "credits": float(credits),
            "meta": {"src": "data/conol_accounts_pool.jsonl", "line": i,
                     "status": row.get("status"), "precision": "pool-write"},
            "event_key": "%s:bal:%s:%s" % (USAGE_PREFIX, email, stamp),
        })
    return events


def _gateway_events() -> list:
    """LLM-запросы шлюза :9999 из его SQLite-журнала (data/conol_keystore.db).

    Шлюз пишет (key, ts, model, stream, tokens_est) на каждый вызов
    /v1/chat/completions. tokens_est — оценка «~4 символа на токен», это НЕ
    токены: в ledger кладём null (USAGE-SPEC §5), оценку оставляем в meta для
    отладки. Кредитов и $ шлюз не пишет вовсе.
    """
    if not GATEWAY_DB.exists():
        return []
    import sqlite3
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % GATEWAY_DB, uri=True, timeout=2)
        try:
            rows = conn.execute(
                "SELECT rowid, ts, key, model, stream, tokens_est FROM usage "
                "ORDER BY rowid DESC LIMIT ?", (GATEWAY_ROWS_MAX,)).fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — журнал шлюза не обязателен, панель не падает
        return []
    events = []
    for rowid, ts, key, model, stream, tokens_est in rows:
        events.append({
            "kind": "llm_request", "ts": ts, "model": model,
            "tokens_in": None, "tokens_out": None, "credits": None, "cost_usd": None,
            "account": _key_mask(key),
            "meta": {"src": "data/conol_keystore.db (шлюз :9999)", "stream": bool(stream),
                     "tokens_est": tokens_est, "precision": "gateway-log"},
            "event_key": "%s:gw:%d" % (USAGE_PREFIX, rowid),
        })
    return events


_usage_lock = threading.Lock()


def _hourly_pool_snapshot() -> int:
    """Один снапшот остатка пула в час, пока панель запущена (USAGE-SPEC §1).

    Ключ привязан к номеру часа — повторный вызов в тот же час не задваивает.
    """
    hour = int(time.time() // SNAPSHOT_INTERVAL_SEC)
    with _usage_lock:
        if _last_snapshot["hour"] == hour:
            return 0
        _last_snapshot["hour"] = hour
    rows = read_pool()
    total = summarize_credits([{"credits": r.get("credits")} for r in rows])
    return conol_usage.record_many([{
        "kind": "balance_snapshot", "ts": time.time(), "credits": total,
        "meta": {"src": "pool", "type": "pool-total", "pool_size": len(rows),
                 "precision": "hourly"},
        "event_key": "%s:pool:%d" % (USAGE_PREFIX, hour),
    }])


def usage_ingest() -> int:
    """Дозапись событий в data/usage.jsonl (идемпотентно: event_key + desup журнала)."""
    added = conol_usage.record_many(_results_events())
    added += conol_usage.record_many(_pool_snapshot_events())
    added += conol_usage.record_many(_gateway_events())
    added += _hourly_pool_snapshot()
    return added


def usage_payload(query: dict) -> dict:
    """GET /api/usage: ingest → роллап (USAGE-SPEC §2). Неизвестное — честно «н/д»."""
    range_ = (query.get("range") or ["7d"])[0]
    bucket = (query.get("bucket") or [None])[0]
    rows = read_pool()
    gw_db = GATEWAY_DB.exists()
    notes = [
        "Регистрации и капча — из data/conol_register_results.jsonl (одна строка = "
        "попытка): статус и ошибка каждой попытки в meta, капча развёрнута по числу "
        "решений chrome_cdp.",
        "Токенов у conol нет: шлюз :9999 логирует запрос/модель/стрим "
        "(SQLite data/conol_keystore.db), но не токены и не кредиты — в панели "
        "tokens = «н/д» (оценка шлюза лежит в meta.tokens_est, в суммы не идёт)."
        if gw_db else
        "Журнала шлюза (data/conol_keystore.db) нет — LLM-запросы не учтены; "
        "регистрации/капча/остатки считаются всё равно.",
        "Кредиты: снапшоты остатка из пула (last_check/created_at, дельты "
        "GET /api/billing/balance) — их пишут панельная перепроверка и conol_refresh; "
        "расход по аккаунту восстанавливается по дельтам между снапшотами.",
        "Капча бесплатная (chrome_cdp, $0)" + (
            "; платный контур anticaptcha настроен — стоимость его решений в "
            "results-логе не отмечена, поэтому $ = «н/д»" if not _free_captcha_only()
            else ""),
    ]
    return conol_usage.payload(range_, bucket, notes=notes, extras={
        "gateway_port": config().get("gateway", {}).get("port", 9999),
        "gateway_online": gateway_online(),
        "gateway_db": "data/" + GATEWAY_DB.name if gw_db else None,
        "pool_count": len(rows),
        "solves_today": solves_today(),
        "direct_mode": conol_proxy.direct_mode(),
        "ledger_note": "журнал data/usage.jsonl",
    }, ingest=usage_ingest)


def usage_heartbeat(interval: int = 300) -> None:
    """Фоновый ingest (в т.ч. часовой снапшот пула), пока панель запущена."""
    while True:
        time.sleep(interval)
        try:
            usage_ingest()
        except Exception:  # noqa: BLE001 — учёт не должен ронять панель
            pass


# ─── HTTP-слой ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "ConolPanel/%s" % VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 — компактный лог вместо дефолтного
        sys.stderr.write("[panel] %s %s\n" % (self.address_string(), fmt % args))

    # ── helpers ──
    def _send(self, payload, code: int = 200, ctype: str = "application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(
            payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, code: int = 400):
        self._send({"error": message}, code)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    # ── routing ──
    def do_GET(self):  # noqa: N802 — имя задано BaseHTTPRequestHandler
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if path in ("/", "/index.html"):
                return self._send(STATIC.read_bytes(), ctype="text/html; charset=utf-8")
            if path in ("/alt", "/alt.html"):
                # A/B: альтернативный вид (канон-шаблон), текущий index.html не тронут
                alt = STATIC.with_name("alt.html")
                return self._send(alt.read_bytes(), ctype="text/html; charset=utf-8")
            if path == "/favicon.ico":
                return self._send(b"", code=204, ctype="image/x-icon")
            if path == "/api/summary":
                return self._summary()
            if path == "/api/accounts":
                return self._send(accounts())
            if path == "/api/accounts/token":
                return self._token(query)
            if path == "/api/job":
                return self._send(job_view())
            if path == "/api/captcha":
                return self._send(captcha_info())
            if path == "/api/models":
                return self._send(models_view())
            if path == "/api/proxies":
                return self._send(proxies_payload())
            if path == "/api/usage":
                return self._send(usage_payload(query))
            if path == "/api/usage/raw":
                try:
                    tail = int((query.get("tail") or ["500"])[0])
                except ValueError:
                    tail = 500
                return self._send(conol_usage.raw_tail(tail))
            if path == "/api/keys":
                return self._send(keys_view())
            if path == "/api/logs":
                return self._logs(query)
            return self._error("unknown endpoint: %s" % path, 404)
        except Exception as exc:  # noqa: BLE001 — панель не должна падать от одного запроса
            return self._error("%s: %s" % (type(exc).__name__, exc), 500)

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            # Тело читаем ВСЕГДА: панель держит keep-alive (HTTP/1.1), и непрочитанные
            # байты уходят в парсер как начало следующего запроса («Bad request syntax»,
            # рассинхрон соединения). Пустой POST от панели — тоже валидный случай.
            body = self._body()
            if path == "/api/accounts/check":
                return self._check()
            if path == "/api/register":
                return self._register(body)
            if path == "/api/proxies":
                started = start_proxy_check()
                if not started:
                    return self._send({"checking": True, "note": "проверка уже идёт"})
                return self._send({"checking": True})
            if path == "/api/proxies/mode":
                # чекбокс «без прокси»: режим переживает перезапуск панели
                if "direct" not in body:
                    return self._error("нужно поле direct: true|false", 400)
                direct = conol_proxy.set_direct_mode(bool(body.get("direct")))
                plog("режим «без прокси» %s (чекбокс панели, переживает перезапуск)"
                     % ("включён" if direct else "выключен"))
                return self._send(proxies_payload())
            if path == "/api/job/stop":
                return self._stop()
            return self._error("unknown endpoint: %s" % path, 404)
        except Exception as exc:  # noqa: BLE001
            return self._error("%s: %s" % (type(exc).__name__, exc), 500)

    # ── handlers ──
    def _summary(self):
        views = accounts()
        counts = count_statuses(views)
        job = reconcile_job(afk_worker.read_job())
        if job:
            last_run = {"started_at": job.get("started_at"), "ok": job.get("ok") or 0,
                        "total": job.get("total") or 0, "status": job.get("status"),
                        "finished_at": job.get("finished_at"),
                        "proxy_mode": job.get("proxy_mode"), "proxies": job.get("proxies")}
        else:
            last_run = self._last_run_from_results()
        last_check = max((v["last_check"] for v in views if v.get("last_check")), default=None)
        cap = captcha_info()
        self._send({
            "service": SERVICE,
            "version": VERSION,
            "running": job_active(job),
            "port": PORT,
            "counts": counts,
            "pool_statuses": self._raw_statuses(),
            "credits_total": summarize_credits(views),
            "credits_last_refresh": last_check,
            "captcha": {"provider": cap["provider"], "configured": cap["configured"],
                        "balance": cap["balance"]},
            "last_run": last_run,
            "proxies": proxy_mode_info(),
            "gateway": {"port": config().get("gateway", {}).get("port", 9999),
                        "online": gateway_online()},
            "slot_holder": foreign_slot_holder(),
        })

    def _raw_statuses(self) -> dict:
        return _raw_pool_statuses()

    def _last_run_from_results(self) -> dict:
        path = conol_register.RESULTS_FILE
        if not path.exists():
            return {"started_at": None, "ok": 0, "total": 0, "status": "idle"}
        lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if not lines:
            return {"started_at": None, "ok": 0, "total": 0, "status": "idle"}
        try:
            row = json.loads(lines[-1])
        except ValueError:
            return {"started_at": None, "ok": 0, "total": 0, "status": "idle"}
        started = row.get("ts")
        if isinstance(started, (int, float)) and row.get("elapsed_s"):
            started = round(started - row["elapsed_s"], 1)
        return {"started_at": started, "ok": 1 if row.get("ok") else 0, "total": 1,
                "status": "done" if row.get("ok") else "failed"}

    def _token(self, query: dict):
        email = (query.get("email") or [""])[0].lower()
        if not email:
            return self._error("email required", 400)
        row = next((r for r in read_pool() if (r.get("email") or "").lower() == email), None)
        if not row:
            return self._error("account not found: %s" % email, 404)
        token = row.get("session_token") or ""
        if not token:
            return self._error("нет session_token (unverified)", 409)
        return self._send({"email": email, "session_token": token,
                           "token_masked": mask(token), "token_expires": row.get("token_expires")})

    def _check(self):
        job = reconcile_job(afk_worker.read_job())
        if job_active(job):
            return self._error("AFK-прогон идёт: пул перепроверим после остановки (два писателя "
                               "на один JSONL недопустимы)", 409)
        holder = foreign_slot_holder()
        if holder:
            return self._error("пул-слот занят живым процессом pid %s (реггер/refresh)" % holder, 409)
        rows = [r for r in read_pool() if r.get("session_token") or r.get("email")]
        # Проверки идут через тот же прокси-пул с ротацией, как и регистрация:
        # параллельно (CHECK_WORKERS), прокси выбирается потокобезопасно.
        proxies, _bad = conol_proxy.load_proxies()
        mode = "direct" if not proxies else "proxy"
        plog("▶ перепроверка пула: %d акк, сеть: %s" % (len(rows), mode))

        def run_one(row):
            proxy, idx, _warn = conol_proxy.pick_for_attempt(proxies, PROXY_STATE, row.get("email"))
            res = check_one(row, proxy=proxy)
            if proxy:
                PROXY_STATE.record_result(
                    proxy["raw"],
                    ok=not conol_proxy.looks_proxy_failed(res.get("note") or res.get("status")))
            return res

        with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
            results = list(pool.map(run_one, rows))
        updated = apply_check(results)
        summary = {}
        for r in results:
            summary[r["status"]] = summary.get(r["status"], 0) + 1
        for r in results:
            plog("   %-12s %s%s" % (r["status"], r.get("email"),
                                     " via %s" % r["proxy_masked"] if r.get("proxy_masked") else ""))
        self._send({"checked": updated, "by_status": summary, "network": mode,
                    "proxies": len(proxies), "checked_at": time.time(), "results": results})

    def _register(self, body: dict = None):
        body = body if isinstance(body, dict) else self._body()
        try:
            count = int(body.get("count", afk_worker.DEFAULT_COUNT))
        except (TypeError, ValueError):
            return self._error("count должен быть числом", 400)
        if count < 1:
            return self._error("count должен быть >= 1", 400)
        if body.get("verify") is False:
            return self._error("verify=false не поддерживается: аккаунт conol без подтверждённой "
                               "почты нерабочий (нет session_token)", 400)
        job = reconcile_job(afk_worker.read_job())
        if job_active(job):
            return self._error("прогон уже идёт: %s/%s (статус %s)"
                               % (job.get("done"), job.get("total"), job.get("status")), 409)
        holder = foreign_slot_holder()
        if holder:
            return self._error("пул-слот занят живым процессом pid %s (реггер/refresh)" % holder, 409)
        provider = str(body.get("provider") or "catchall")
        if provider not in ("gmail", "tonline", "catchall"):
            return self._error("unknown provider: %s" % provider, 400)
        paid = bool(body.get("paid_captcha"))
        if paid and not conol_captcha.ANTICAPTCHA_KEYS:
            return self._error("paid_captcha=true, но anticaptcha_keys в config.json пуст "
                               "(бесплатный путь — chrome_cdp)", 400)

        count = min(count, afk_worker.MAX_COUNT)
        # «без прокси» из панели: прогон идёт напрямую и честно помечается в job/логе
        no_proxy = bool(body.get("no_proxy") or body.get("direct"))
        proxies, _bad = conol_proxy.load_proxies()
        net = ("НАПРЯМУЮ (без прокси!)" if (no_proxy or not proxies)
               else "%d прокси, ротация по аккаунтам" % len(proxies))
        afk_worker.AFK_LOG.parent.mkdir(parents=True, exist_ok=True)
        offset = afk_worker.AFK_LOG.stat().st_size if afk_worker.AFK_LOG.exists() else 0
        job_id = "afk-%d" % int(time.time())
        afk_worker.STOP_FLAG.unlink(missing_ok=True)
        afk_worker.JOB_FILE.unlink(missing_ok=True)
        cmd = [sys.executable, "-X", "utf8", "-u", str(PANEL_DIR / "afk_worker.py"),
               "--count", str(count), "--provider", provider, "--job-id", job_id]
        if paid:
            cmd.append("--paid-captcha")
        if no_proxy:
            cmd.append("--no-proxy")
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        with open(afk_worker.AFK_LOG, "ab") as sink:
            sink.write(("\n=== job %s: %d аккаунтов, provider=%s, капча=%s, сеть: %s ===\n"
                        % (job_id, count, provider,
                           "anticaptcha-цепочка" if paid else "chrome_cdp (free)", net)).encode())
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=sink, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
        plog("▶ AFK-прогон %s: %d аккаунтов, сеть: %s" % (job_id, count, net))
        if no_proxy or not proxies:
            plog("   [!] " + conol_proxy.DIRECT_NOTE)
        afk_worker.write_job({
            "job_id": job_id, "status": "running", "started_at": time.time(), "finished_at": None,
            "done": 0, "total": count, "ok": 0, "failed": 0, "credits": 0,
            "last_error": None, "current": None, "provider": provider,
            "captcha": "anticaptcha-chain" if paid else "chrome_cdp",
            "proxy_mode": "direct" if (no_proxy or not proxies) else "proxy",
            "proxies": 0 if no_proxy else len(proxies),
            "no_proxy": no_proxy,
            "proxy_note": None if (proxies and not no_proxy) else conol_proxy.DIRECT_NOTE,
            "pid": proc.pid, "log_offset": offset, "log_file": str(afk_worker.AFK_LOG),
        })
        self._send({"job_id": job_id, "status": "running", "count": count, "provider": provider,
                    "pid": proc.pid, "verify": True, "no_proxy": no_proxy,
                    "network": net,
                    "captcha": "anticaptcha-chain" if paid else "chrome_cdp"})

    def _stop(self):
        job = reconcile_job(afk_worker.read_job())
        pid = job.get("pid")
        if not job_active(job) or not pid:
            return self._send({"stopped": False, "status": job.get("status") or "idle",
                               "note": "активного прогона нет"})
        afk_worker.request_stop()
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError) as exc:
            return self._send({"stopped": False, "note": "не смог отправить SIGTERM: %s" % exc})
        self._send({"stopped": True, "pid": int(pid), "status": "running",
                    "note": "SIGTERM: воркер доигрывает текущий аккаунт и выходит "
                            "(слот освобождается сам)"})

    def _logs(self, query: dict):
        name = (query.get("name") or ["afk"])[0]
        try:
            tail = int((query.get("tail") or ["200"])[0])
        except ValueError:
            tail = 200
        tail = max(1, min(tail, 5000))
        path = LOG_FILES.get(name)
        if path is None:
            return self._error("unknown log: %s (доступно: %s)" % (name, ",".join(LOG_FILES)), 404)
        self._send({"name": name, "file": str(path), "tail": tail,
                    "lines": log_tail(path, tail)})


def main(argv=None) -> int:
    import argparse
    global PORT
    parser = argparse.ArgumentParser(description="conol-control-panel: панель по PANEL-SPEC")
    parser.add_argument("--port", type=int, default=PORT,
                        help="порт панели (зарезервирован за этим реггером: 9903)")
    parser.add_argument("--host", default=HOST, help="адрес (только 127.0.0.1)")
    args = parser.parse_args(argv)

    PORT = args.port
    httpd = ThreadingHTTPServer((args.host, PORT), Handler)
    httpd.daemon_threads = True
    print("ENI :: Conol Panel v%s — http://%s:%d  (pool: %s)" % (VERSION, args.host, PORT, POOL_FILE))
    print("AFK-лог: %s | job: %s | стоп-флаг: %s"
          % (afk_worker.AFK_LOG, afk_worker.JOB_FILE, afk_worker.STOP_FLAG))
    print("модели: %s | капча: %s (headless=%s, display=%s)"
          % (MODELS_DOC, ",".join(conol_captcha.PROVIDERS), conol_captcha.HEADLESS,
             conol_captcha.DISPLAY_OVERRIDE or "inherit"))
    proxies, bad = conol_proxy.load_proxies()
    print("прокси: %d шт из %s" % (len(proxies), conol_proxy.proxies_file())
          + (" | битых строк: %d" % len(bad) if bad else "")
          + ("" if proxies else " — ВНИМАНИЕ: " + conol_proxy.DIRECT_NOTE))
    print("учёт (USAGE-SPEC): %s | шлюз :%s (журнал %s)"
          % (conol_usage.ledger_path(), PORT, GATEWAY_DB.name))
    threading.Thread(target=usage_heartbeat, name="conol-usage", daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[panel] остановлен")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())