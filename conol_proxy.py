# -*- coding: utf-8 -*-
"""conol_proxy.py — прокси для conol-реггера: разбор строк, валидация, ротация.

Зачем: conol режет серию sign-up по IP (429 RATE_LIMITED с домашнего адреса —
см. docs/README.md «Грабли»). Прокси раскидывают попытки по разным exit-IP.

Источники (оба сразу):
  1) config.json → "proxies": ["http://user:pass@host:port", ...]  (секреты, не в git)
  2) data/proxies.txt — по строке, вставка пачкой (# — комментарий)

Формат строки: scheme://[user:pass@]host:port (http/https/socks5).
Три потребителя — три вида представления:
  * Chrome (запускает conol_captcha вручную)  → chrome_proxy_arg(): --proxy-server=URL
  * requests (HTTP-часть реггера и панели)    → requests_proxies(): {"http":raw,"https":raw}
  * stdlib urllib (валидатор и panel-проверки) → urllib_opener(): ProxyHandler

Валидатор — на stdlib (urllib): панель не тянет requests, а результат одинаков
и для реггера, и для панели. Статусы/ротация/подряд-фейлы — data/proxies.json
(аналог data/proxy_state.json у github-register), запись атомарная.

Обход: CONOL_NO_PROXY=1, set_force_direct(True) (флаг --no-proxy в CLI) или
set_direct_mode(True) — персистентный переключатель «без прокси» из панели
(data/proxy_direct_state.json): включённый обход отдаёт пустой список и честную
пометку, но панель всё равно показывает настроенный пул (configured_proxies).
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATE_FILE = DATA_DIR / "proxies.json"          # индекс ротации + статусы проверок
DIRECT_STATE_FILE = DATA_DIR / "proxy_direct_state.json"   # чекбокс «без прокси» из панели
DEFAULT_PROXIES_FILE = DATA_DIR / "proxies.txt"
CONFIG_FILE = BASE_DIR / "config.json"

UA = "curl/8.5.0"
CHECK_TIMEOUT_DEFAULT = 12
# после стольких подряд неудач через прокси (429/сеть) он временно выключается из ротации
FAIL_THRESHOLD_DEFAULT = 3

# честная пометка «идём напрямую» для логов, панели и job-файла
DIRECT_NOTE = ("без прокси — попытки идут с домашнего IP, а conol режет серию "
               "sign-up по сети (429 RATE_LIMITED): вставь прокси в config.json → "
               "proxies / data/proxies.txt и нажми «Перепроверить»")

# ошибка попытки, которая указывает на прокси (её и считаем фейлом прокси):
# 429 от conol = лимит сети/exit-IP, сетевые исключения = прокси не работает
FAIL_MARKERS = ("RATE_LIMITED", "429", "PROXYERROR", "CONNECTIONERROR", "CONNECTTIMEOUT",
                "READTIMEOUT", "MAX RETRIES", "TUNNEL CONNECTION", "REMOTEDISCONNECTED",
                "SSLEOFERROR", "NEWCONNECTIONERROR", "BADSTATUSLINE")

_force_direct = False
_config_cache = {"mtime": None, "data": {}}
_direct_cache = {"mtime": None, "flag": False}
_cache_lock = threading.Lock()


# ── конфиг (перечитывается, оператор вставляет прокси без рестарта) ─────────

def _read_config() -> dict:
    try:
        mtime = CONFIG_FILE.stat().st_mtime
    except OSError:
        return {}
    with _cache_lock:
        if _config_cache["mtime"] == mtime:
            return _config_cache["data"]
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        data = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        data = {}
    with _cache_lock:
        _config_cache.update({"mtime": mtime, "data": data})
    return data


def _cfg(key, default):
    value = _read_config().get(key)
    return default if value is None else value


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def set_force_direct(flag: bool) -> None:
    """Обход прокси на время процесса (--no-proxy в CLI/воркере)."""
    global _force_direct
    _force_direct = bool(flag)


def _persisted_direct() -> bool:
    """Переключатель «без прокси» из панели (переживает её перезапуск)."""
    try:
        mtime = DIRECT_STATE_FILE.stat().st_mtime
    except OSError:
        with _cache_lock:
            _direct_cache.update(mtime=None, flag=False)
        return False
    with _cache_lock:
        if _direct_cache["mtime"] == mtime:
            return _direct_cache["flag"]
    flag = False
    try:
        data = json.loads(DIRECT_STATE_FILE.read_text(encoding="utf-8"))
        flag = bool(data.get("direct")) if isinstance(data, dict) else False
    except (OSError, ValueError):
        flag = False
    with _cache_lock:
        _direct_cache.update(mtime=mtime, flag=flag)
    return flag


def set_direct_mode(flag: bool) -> bool:
    """Включить/снять режим «без прокси» с сохранением на диск.

    Пишет и в память текущего процесса, и в data/proxy_direct_state.json — иначе
    режим терялся бы при перезапуске панели (а он про это честно говорит в UI).
    """
    flag = bool(flag)
    set_force_direct(flag)
    try:
        if flag:
            DIRECT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            DIRECT_STATE_FILE.write_text(
                json.dumps({"direct": True, "updated_at": round(time.time(), 1)},
                           ensure_ascii=False, indent=2),
                encoding="utf-8")
        else:
            DIRECT_STATE_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    with _cache_lock:
        _direct_cache.update(mtime=None, flag=flag)
    return flag


def direct_mode() -> bool:
    """True → работаем напрямую (чекбокс панели, CONOL_NO_PROXY=1 или --no-proxy)."""
    return (_force_direct or _truthy(os.environ.get("CONOL_NO_PROXY"))
            or _persisted_direct())


def proxy_check_urls() -> list:
    urls = _cfg("proxy_check_urls", None)
    if isinstance(urls, list) and urls:
        return [str(u) for u in urls]
    # третий — plain-HTTP: часть прокси не умеет CONNECT для https
    return ["https://api.ipify.org?format=json", "https://ifconfig.me/ip",
            "http://httpbin.org/ip"]


def proxy_check_timeout() -> int:
    try:
        return int(_cfg("proxy_check_timeout", CHECK_TIMEOUT_DEFAULT))
    except (TypeError, ValueError):
        return CHECK_TIMEOUT_DEFAULT


def fail_threshold() -> int:
    try:
        return int(_cfg("proxy_fail_threshold", FAIL_THRESHOLD_DEFAULT))
    except (TypeError, ValueError):
        return FAIL_THRESHOLD_DEFAULT


def proxies_file() -> Path:
    path = os.environ.get("CONOL_PROXIES_FILE") or _cfg("proxies_file", None)
    if not path:
        return DEFAULT_PROXIES_FILE
    p = Path(str(path))
    return p if p.is_absolute() else BASE_DIR / p

# ── Bright Data: сессионная ротация (свежий exit-IP на каждый аккаунт) ───────
# Датацентровые зоны BRD с суффиксом -session-<id> дают НОВЫЙ выходной IP на
# каждую сессию (проверено 09.10: 4 сессии → 4 разных IP). Это не список из N
# прокси, а ФАБРИКА: сколько аккаунтов — столько IP. Поэтому в пуле держим по
# одному «шаблону» на зону, а конкретный прокси минтим в момент попытки — тогда
# IP браузера (reCAPTCHA v3) и IP HTTP-регистрации совпадают по построению, и
# линковки фермы по одному IP не происходит.
#
# Конфиг: config.json → "brd_zones": [{"zone": "datacenter_proxy1", "password": "..."}].
# Обход: тот же direct_mode() (чекбокс панели / CONOL_NO_PROXY=1 / --no-proxy).
BRD_HOST = "brd.superproxy.io:44445"
BRD_CUSTOMER = "hl_XXXXXXXX"
BRD_SESSION_LEN = 12
_brd_counter = {"n": 0}
_brd_lock = threading.Lock()


def brd_zones() -> list:
    zones = _cfg("brd_zones", None) or []
    out = []
    for z in zones:
        if isinstance(z, dict) and z.get("zone") and z.get("password"):
            out.append({"zone": str(z["zone"]), "password": str(z["password"])})
    return out


def brd_enabled() -> bool:
    """Зоны заданы и обход прокси не включён."""
    return bool(brd_zones()) and not direct_mode()


def _brd_template(zone: dict) -> dict:
    """«Шаблон» зоны: сам по себе не рабочий прокси, с него минтится сессия.

    raw с literal-`*` вместо session-id: он и есть ключ записи в state (их всего
    по числу зон, так что state не разрастается), и по нему видно, что это BRD.
    """
    user = "brd-customer-%s-zone-%s-session-*" % (BRD_CUSTOMER, zone["zone"])
    raw = "http://%s:%s@%s" % (user, zone["password"], BRD_HOST)
    return {"raw": raw, "scheme": "http", "host": "brd.superproxy.io",
            "port": 44445, "username": user, "password": zone["password"],
            "server": "http://brd.superproxy.io:44445",
            "brd": True, "zone": zone["zone"]}


def brd_pool() -> list:
    """Список шаблонов (по одному на зону) — подставляется вместо статического пула."""
    return [_brd_template(z) for z in brd_zones()]


def mint_brd(template: dict) -> dict:
    """Шаблон → рабочий прокси со СВЕЖИМ session-id (новый exit-IP)."""
    import random as _r
    import string as _s
    with _brd_lock:
        _brd_counter["n"] += 1
        n = _brd_counter["n"]
    sess = "".join(_r.choices(_s.ascii_lowercase + _s.digits, k=BRD_SESSION_LEN))
    user = "brd-customer-%s-zone-%s-session-%s%03d" % (
        BRD_CUSTOMER, template.get("zone"), sess, n % 1000)
    raw = "http://%s:%s@%s" % (user, template.get("password"), BRD_HOST)
    p = parse_proxy(raw)
    if p:
        p["brd"] = True
        p["zone"] = template.get("zone")
        # ключ состояния = шаблон зоны, а не сессия: иначе health/status в
        # data/proxies.json пухли бы новой записью на каждый аккаунт.
        p["state_key"] = template.get("raw")
    return p


def is_brd(raw) -> bool:
    return "brd-customer-" in str(raw or "")


def state_key(proxy) -> str:
    """Ключ для state-файла: у BRD-сессии — шаблон зоны, иначе свой raw."""
    if not proxy:
        return None
    return proxy.get("state_key") or proxy.get("raw")


# ── разбор строк ────────────────────────────────────────────────────────────

def mask(raw):
    """Строка прокси → «http://user:***@host:port» для логов/UI (пароль не светим)."""
    if not raw:
        return None
    try:
        u = urlsplit(raw)
        host = u.hostname or ""
        if u.port:
            host += ":%d" % u.port
        if u.username:
            return "%s://%s:***@%s" % (u.scheme, unquote(u.username), host)
        return "%s://%s" % (u.scheme, host)
    except ValueError:
        return raw


def _server(raw):
    """«scheme://host:port» из сырой строки (для записей без разобранного объекта)."""
    p = parse_proxy(raw)
    return p["server"] if p else None


def _socks_available() -> bool:
    """requests умеет socks5 только с PySocks; ставить новые зависимости нельзя."""
    try:
        import socks  # noqa: F401
        return True
    except ImportError:
        return False


def parse_proxy(raw):
    """Строка → dict {raw, scheme, host, port, username, password, server} либо None."""
    if not raw:
        return None
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlsplit(raw)
    except ValueError:
        return None
    if not u.hostname or not u.port:
        return None
    scheme = (u.scheme or "http").lower()
    if scheme == "socks5h":
        scheme = "socks5"
    return {
        "raw": raw,
        "scheme": scheme,
        "host": u.hostname,
        "port": u.port,
        "username": unquote(u.username) if u.username else None,
        "password": unquote(u.password) if u.password else None,
        "server": "%s://%s:%d" % (scheme, u.hostname, u.port),
    }


def parse_proxy_list(lines):
    """Список строк → (валидные прокси, отброшенные строки с причиной)."""
    good, bad = [], []
    seen = set()
    socks_ok = _socks_available()
    for line in lines or []:
        text = (line or "").strip()
        if not text or text.startswith("#"):
            continue
        p = parse_proxy(text)
        if not p:
            bad.append("%s — не разобрал (нужно scheme://[user:pass@]host:port)" % text)
            continue
        if p["scheme"].startswith("socks") and not socks_ok:
            bad.append("%s — socks не поддержан: нет PySocks, а новые pip-зависимости "
                       "панели запрещены; возьми http-прокси" % mask(p["raw"]))
            continue
        if p["scheme"] not in ("http", "https", "socks4", "socks5"):
            bad.append("%s — схема %s не поддержана" % (mask(p["raw"]), p["scheme"]))
            continue
        if p["raw"] in seen:
            continue
        seen.add(p["raw"])
        good.append(p)
    return good, bad


def load_proxies(cfg=None, path=None, ignore_direct: bool = False):
    """Прокси из config.json + data/proxies.txt → (список, отброшенные строки).

    cfg — список строк «как в config» (по умолчанию config.json → "proxies"
    или env CONOL_PROXIES через запятую); path — файл по строке.
    Если включён обход (direct_mode) — прокси не грузим вовсе (ignore_direct=True
    нужен только панели: показать настроенный пул при включённом обходе).
    """
    if direct_mode() and not ignore_direct:
        return [], []
    # Приоритет источников:
    #   1) явный cfg/path от вызывающего (тест, --proxies-file) — уважаем как есть;
    #   2) env CONOL_PROXIES — ручной оверрайд;
    #   3) BRD-зоны из конфига — свежий exit-IP на каждый аккаунт;
    #   4) статический список config.proxies + data/proxies.txt.
    env_override = os.environ.get("CONOL_PROXIES") if cfg is None else None
    if brd_zones() and cfg is None and path is None and not env_override:
        return brd_pool(), []
    if cfg is None:
        if env_override:
            cfg = [chunk for chunk in env_override.split(",")]
        else:
            cfg = _cfg("proxies", []) or []
    lines = [str(x) for x in cfg]
    if path is None:
        path = proxies_file()
    path = Path(path)
    if path.exists():
        try:
            lines += path.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
    return parse_proxy_list(lines)


def configured_proxies():
    """Настроенный пул без учёта режима «без прокси» — для честного UI панели.

    Иначе включённый чекбокс прятал бы список, и панель писала бы «прокси не
    заданы» вместо «заданы, но выключены».
    """
    return load_proxies(ignore_direct=True)


# ── представления для потребителей ──────────────────────────────────────────

def requests_proxies(p):
    """dict прокси для requests (None → напрямую)."""
    if not p:
        return None
    return {"http": p["raw"], "https": p["raw"]}


def chrome_proxy_arg(p):
    """Значение для --proxy-server у Chrome; None → флаг не добавляется.

    Chrome логин/пароль в --proxy-server ИГНОРИРУЕТ (вырезает их), поэтому:
      * BRD-прокси (всегда с авторизацией) отдаём через локальный релей —
        `conol_brd_relay.relay_url()`; Chrome ходит на 127.0.0.1:<port> без
        авторизации, релей добавляет её и туннелирует в BRD. Каждой сессии —
        свой порт, поэтому `--proxy-server` меняется и Chrome перезапускается
        на новый аккаунт;
      * прокси без авторизации — как есть;
      * прокси с авторизацией, но не BRD — тоже через релей (иначе Chrome не
        сходит); если релей поднять не удалось, отдаём как есть и логируем.
    HTTP-часть (requests) авторизацию поддерживает всегда и релей ей не нужен.
    """
    if not p:
        return None
    if p.get("brd") or p.get("username"):
        try:
            import conol_brd_relay
            url = conol_brd_relay.relay_url(p["raw"])
            if url:
                return url
        except Exception:
            pass
        if p.get("brd"):
            return None  # без релея BRD в Chrome всё равно не сработает
    return "%s://%s:%d" % (p["scheme"], p["host"], p["port"])


def urllib_opener(p=None):
    """Opener для stdlib urllib: с прокси или явно без (env-прокси игнорируем)."""
    if p:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler(requests_proxies(p)))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _extract_ip(text: str):
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return None
        ip = data.get("ip") or data.get("origin") or data.get("query")
        return str(ip).split(",")[0].strip() if ip else None
    return text.splitlines()[0].strip()[:64] or None


# ── валидация (ip-echo через прокси) ────────────────────────────────────────

def check_proxy(p, timeout=None, urls=None):
    """Живой чек прокси через ip-echo → {ok, ip, ms, error, checked_at}."""
    timeout = timeout or proxy_check_timeout()
    urls = urls or proxy_check_urls()
    res = {"ok": False, "ip": None, "ms": None, "error": None,
           "checked_at": round(time.time(), 1),
           "raw": p["raw"] if p else None, "masked": mask(p["raw"] if p else None)}
    if not p:
        res["error"] = "пустая строка прокси"
        return res
    if p.get("brd"):
        # Шаблон зоны: для проверки минтим живую сессию (шаблон с `*` не рабочий)
        p = mint_brd(p) or p
    if p["scheme"].startswith("socks") and not _socks_available():
        res.update(ms=0, error="socks не поддержан (нет PySocks)")
        return res
    opener = urllib_opener(p)
    started = time.time()
    last_err = "нет ответа"
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
            with opener.open(req, timeout=timeout) as resp:
                code = getattr(resp, "status", None) or 200
                body = resp.read().decode("utf-8", "replace")
            if code != 200:
                last_err = "HTTP %s" % code
                continue
            ip = _extract_ip(body)
            if ip:
                res.update(ok=True, ip=ip[:64], error=None,
                           ms=int((time.time() - started) * 1000))
                return res
            last_err = "пустой ответ ip-echo"
        except urllib.error.HTTPError as exc:
            last_err = "HTTP %s" % exc.code
        except Exception as exc:  # noqa: BLE001 — сеть не должна валить проверку
            last_err = "%s: %s" % (type(exc).__name__, str(exc)[:110])
    res["error"] = last_err
    res["ms"] = int((time.time() - started) * 1000)
    return res


def check_proxies(proxies, on_result=None):
    """Проверить список последовательно → {raw: check_result}."""
    out = {}
    for p in proxies:
        res = check_proxy(p)
        out[p["raw"]] = res
        if on_result:
            on_result(p, res)
    return out


def looks_proxy_failed(error_text) -> bool:
    """Похоже ли, что попытка провалилась именно из-за прокси (429/сеть)."""
    text = str(error_text or "").upper()
    return any(marker in text for marker in FAIL_MARKERS)


def pick_for_attempt(proxies, state=None, email=None):
    """Прокси на одну попытку (ротация по кругу) → (proxy|None, index, warning|None).

    * index == -1  — прокси вообще не заданы (штатный режим «напрямую»);
    * index == -2  — пул есть, но все временно забанены подряд-фейлами: вызывающий
      сам решает, идти ли напрямую (warning объясняет это в логе и в UI).
    """
    state = state or ProxyState()
    proxy, index = state.next(proxies)
    warning = None
    if index == -2 and proxies:
        warning = ("все прокси временно забанены (%d подряд-фейлов на каждом) — "
                   "идём напрямую; перепроверь пул кнопкой «Перепроверить»" % fail_threshold())
        state.mark_used(None, email)
        return None, index, warning
    if proxy is not None and proxy.get("brd"):
        # Шаблон BRD → рабочий прокси со свежим session-id: у каждого аккаунта
        # свой exit-IP. В state пишем шаблон (их по числу зон), не саму сессию.
        template_raw = proxy["raw"]
        minted = mint_brd(proxy)
        state.mark_used(template_raw, email)
        return (minted or proxy), index, warning
    if proxy is not None:
        # последний известный exit-IP прокси: нужен, чтобы сверить с exit-IP браузера
        last = state.status_of(proxy["raw"]) or {}
        proxy = {**proxy, "ip": last.get("ip")}
    state.mark_used(proxy["raw"] if proxy else None, email)
    return proxy, index, warning


# ── состояние: статусы + ротация ────────────────────────────────────────────

class ProxyState:
    """data/proxies.json: индекс ротации, статусы проверок, подряд-фейлы.

    Файл пишется атомарно (.tmp + os.replace) — панель читает его параллельно
    с воркером/CLI, обрезанной строки быть не должно.
    """

    def __init__(self, path=None):
        self.path = Path(path or STATE_FILE)
        self.lock = threading.Lock()
        self.data = {"index": 0, "status": {}, "health": {}, "last_check": None}
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                self.data.update(saved)
        except (OSError, ValueError):
            pass

    def _flush(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass

    # статусы ip-echo
    def save_status(self, raw, result):
        with self.lock:
            self.data.setdefault("status", {})[raw] = result
            self.data["last_check"] = round(time.time(), 1)
            self._flush()

    def merge_status(self, results):
        with self.lock:
            self.data.setdefault("status", {}).update(results)
            self.data["last_check"] = round(time.time(), 1)
            self._flush()

    def status_of(self, raw):
        return (self.data.get("status") or {}).get(raw)

    def mark_used(self, raw, email=None):
        with self.lock:
            self.data["last_used"] = {"raw": raw, "masked": mask(raw), "email": email,
                                      "ts": round(time.time(), 1)}
            self._flush()

    # health: подряд-фейлы попыток через прокси (429/сеть)
    def record_result(self, raw, ok):
        """Итог попытки: подряд-фейлы копятся, порог → временный бан (ротация обходит)."""
        if not raw:
            return None
        threshold = fail_threshold()
        now = round(time.time(), 1)
        with self.lock:
            st = self.data.setdefault("health", {}).setdefault(raw, {"fails": 0, "banned": False})
            if ok:
                st["fails"] = 0
                st["banned"] = False
            else:
                st["fails"] = int(st.get("fails", 0)) + 1
                if st["fails"] >= threshold:
                    st["banned"] = True
                st["last_fail_ts"] = now
                st["last_error"] = None
            entry = self.data.setdefault("proxy_pool", {}).setdefault(raw, {"masked": mask(raw)})
            entry.update({"masked": mask(raw), "server": entry.get("server") or _server(raw),
                          "fails": st["fails"], "banned": st["banned"], "last_result_ts": now})
            self._flush()
            return dict(st)

    def health_of(self, raw):
        return (self.data.get("health") or {}).get(raw) or {}

    def is_banned(self, raw):
        return bool(self.health_of(raw).get("banned"))

    def unban_all(self):
        """Сбросить подряд-фейлы (после перепроверки панелью — чистый лист)."""
        with self.lock:
            for st in (self.data.get("health") or {}).values():
                st["fails"] = 0
                st["banned"] = False
            self._flush()

    # ротация
    def peek(self, proxies):
        """Следующий НЕ забаненный прокси, НЕ двигая индекс (для прогрева Chrome).

        BRD-шаблон минтится в рабочую сессию: Chrome должен получить валидный
        прокси, а не шаблон с literal-`*` вместо session-id.
        """
        if not proxies:
            return None, -1
        start = int(self.data.get("index", 0)) % len(proxies)
        for k in range(len(proxies)):
            idx = (start + k) % len(proxies)
            if not self.is_banned(proxies[idx]["raw"]):
                p = proxies[idx]
                if p.get("brd"):
                    return (mint_brd(p) or p), idx
                return p, idx
        return None, -2

    def next(self, proxies):
        """Следующий НЕ забаненный прокси по кругу → (proxy|None, index).

        Все забанены → (None, -2): вызывающий решает, идти ли напрямую.
        """
        if not proxies:
            return None, -1
        with self.lock:
            start = int(self.data.get("index", 0)) % len(proxies)
            for k in range(len(proxies)):
                idx = (start + k) % len(proxies)
                if not self.is_banned(proxies[idx]["raw"]):
                    self.data["index"] = (idx + 1) % len(proxies)
                    self._flush()
                    return proxies[idx], idx
            self.data["index"] = (start + 1) % len(proxies)
            self._flush()
        return None, -2

    def remember_pool(self, proxies):
        """Запомнить состав пула в state — панель показывает фейлы и по выпавшим прокси.

        Пишем на диск только когда состав изменился: панель дёргает describe()
        регулярно, а лишняя запись состояния на каждый GET не нужна.
        """
        live = {p["raw"] for p in proxies}
        with self.lock:
            pool = self.data.setdefault("proxy_pool", {})
            known = {raw for raw, e in pool.items() if not e.get("gone")}
            if known == live:
                return
            for p in proxies:
                entry = pool.setdefault(p["raw"], {})
                entry.update({"masked": mask(p["raw"]), "server": p["server"]})
                entry.pop("gone", None)
            for raw in list(pool):
                if raw not in live:
                    pool[raw]["gone"] = True
            self._flush()


def describe(proxies, state=None):
    """payload для панели: список + статусы + режим + пометка «напрямую»."""
    state = state or ProxyState()
    if proxies:
        state.remember_pool(proxies)
    items = []
    for i, p in enumerate(proxies):
        st = state.status_of(p["raw"]) or {}
        health = state.health_of(p["raw"])
        items.append({
            "index": i,
            "masked": mask(p["raw"]),
            "server": p["server"],
            "status": ("ok" if st.get("ok") else ("fail" if st else "unchecked")),
            "ip": st.get("ip"),
            "ms": st.get("ms"),
            "error": st.get("error"),
            "checked_at": st.get("checked_at"),
            "fails": int(health.get("fails", 0)),
            "banned": bool(health.get("banned")),
        })
    # прокси, выпавшие из файла/забаненные: накопленные фейлы видны и после правки списка.
    # Пустые (0 фейлов) записи не показываем — иначе список «вне пула» шумит после
    # каждой правки data/proxies.txt.
    pool = state.data.get("proxy_pool") or {}
    retired = [{"masked": e.get("masked"), "server": e.get("server"),
                "fails": int(e.get("fails", 0)), "banned": bool(e.get("banned")),
                "gone": bool(e.get("gone")), "last_result_ts": e.get("last_result_ts")}
               for e in pool.values()
               if e.get("banned") or int(e.get("fails", 0)) > 0]
    forced = direct_mode()
    return {
        "count": len(proxies),
        "mode": "direct" if (not proxies or forced) else "proxy",
        "forced_direct": forced,
        "note": None if proxies and not forced else DIRECT_NOTE,
        "proxies": items,
        "retired": sorted(retired, key=lambda x: -x["fails"]),
        "last_used": state.data.get("last_used"),
        "last_check": state.data.get("last_check"),
        "rotate_index": state.data.get("index"),
        "fail_threshold": fail_threshold(),
    }