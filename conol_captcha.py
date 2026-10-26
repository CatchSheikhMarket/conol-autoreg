"""conol_captcha.py — reCAPTCHA v3 solver chain for conol.ai registration.

Providers, tried in order:
  1. chrome_cdp  — FREE. Local Chrome with a warm profile renders conol.ai and
     executes window.grecaptcha.execute(siteKey, {action}) over CDP. A real
     browser + aged profile typically scores >= 0.3, which is all conol's
     minScore gate requires. No third-party service, no per-solve cost.
  2. anticaptcha — PAID fallback (existing behaviour), keys from config.json.

Public API (matches what conol_register.py needs):
    solve(action) -> Optional[str]      # token or None
    warmup() -> None                    # optional: pre-launch Chrome + load page
    set_proxy(proxy) -> None            # прокси попытки для Chrome (ротация по аккаунтам)

Proxy: Chrome is launched by us on a fixed CDP port, so the proxy is applied at
launch (--proxy-server=...) and a switch to another proxy relaunches the browser
(see set_proxy/_launch_chrome). ReCAPTCHA v3 token и HTTP-регистрация тогда идут
с одного exit-IP — иначе сервер видит разные адреса у токена и запроса.
`solve_anticaptcha` (paid, proxyless task) и панель ходят напрямую.

Chrome path/profile/port come from config.json -> captcha section:
    {"chrome_path": "...", "cdp_port": 9228, "profile_dir": "...", "providers": ["chrome_cdp","anticaptcha"]}
Defaults are sane; env overrides: CONOL_CAPTCHA_PROVIDERS (comma list), CONOL_CDP_PORT,
CONOL_CHROME_HEADLESS (0 to put the window back on screen — off by default).

Stdlib + playwright only. The browser is launched ONCE and reused across solves
(page kept on conol.ai); the token is minted per solve with the right action.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent

def _cfg() -> dict:
    p = _ROOT / "config.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        return {}

_C = _cfg().get("captcha", {}) or {}
CONOL = _cfg().get("conol", {}) or {}

SITE_KEY = os.environ.get("CONOL_SITE_KEY") or CONOL.get("site_key", "")
BASE_URL = os.environ.get("CONOL_BASE_URL") or CONOL.get("base_url", "https://conol.ai")

DEFAULT_CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_PATH = os.environ.get("CONOL_CHROME_PATH") or _C.get("chrome_path") or DEFAULT_CHROME
CDP_PORT = int(os.environ.get("CONOL_CDP_PORT") or _C.get("cdp_port") or 9228)
# Profile lives in data/ (runtime state, gitignored). A relative path in config.json is
# resolved against the project root, not the current working directory — the panel and the
# AFK worker launch from different cwds and must share ONE warm profile.
PROFILE_DIR = _C.get("profile_dir") or "data/chrome_cdp_profile"
if not os.path.isabs(PROFILE_DIR):
    PROFILE_DIR = str((_ROOT / PROFILE_DIR).resolve())


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# Headless Chrome by default here: the operator's desktop must not get browser windows
# from an unattended run, and --headless=new still mints usable reCAPTCHA v3 tokens.
HEADLESS = _truthy(os.environ.get("CONOL_CHROME_HEADLESS")
                   if os.environ.get("CONOL_CHROME_HEADLESS") is not None
                   else _C.get("headless", True))

# Display for a HEADFUL-but-invisible Chrome (gamescope --backend headless on this box).
# Measured 2026-10-07: conol's Enterprise verifier accepts enterprise.js tokens minted in
# a headful browser (200/200) and rejects the same tokens from --headless=new (403 x2) —
# so the free path needs a real renderer, just not a visible window. Set headless=false
# AND display=":1" (see start_panel.sh, which boots the virtual display for you).
DISPLAY_OVERRIDE = os.environ.get("CONOL_CHROME_DISPLAY") or _C.get("display") or ""


def display_alive(display: str = None) -> bool:
    """Есть ли X-сокет для указанного дисплея (":1" -> /tmp/.X11-unix/X1)."""
    display = display if display is not None else DISPLAY_OVERRIDE
    if not display:
        return bool(os.environ.get("DISPLAY", "").startswith(":"))
    num = display.lstrip(":").split(".")[0]
    return Path("/tmp/.X11-unix/X%s" % num).exists()

_env_providers = os.environ.get("CONOL_CAPTCHA_PROVIDERS")
if _env_providers:
    PROVIDERS = [p.strip() for p in _env_providers.split(",") if p.strip()]
else:
    PROVIDERS = list(_C.get("providers") or ["chrome_cdp", "anticaptcha"])

ANTICAPTCHA_KEYS = list(_C.get("anticaptcha_keys") or [])

# ---------------------------------------------------------------- chrome_cdp

_pw = None          # playwright instance
_browser = None     # CDP browser handle
_page = None        # tab parked on conol.ai
_browser_ws = None  # webSocketDebuggerUrl инстанса, к которому подключён _browser
LAST_PROVIDER = None  # which solver minted the last successful token
LAST_EXIT_IP = None   # exit-IP последнего поднятого Chrome (проверка, что прокси применился)

# ── прокси для браузера ─────────────────────────────────────────────────────
# Chrome НЕ умеет менять прокси на лету: он получает --proxy-server при старте,
# поэтому при смене прокси (ротация по аккаунтам) инстанс перезапускается.
# Какой прокси у ЖИВОГО Chrome — помним в маркере профиля: панель, воркер и CLI
# запускаются разными процессами и обязаны видеть одно состояние.
_desired_proxy = None          # разобранный прокси (dict из conol_proxy) либо None


def _proxy_marker() -> Path:
    return Path(PROFILE_DIR) / ".eni_proxy"


def _live_proxy():
    """Прокси, с которым запущен живой Chrome (маркер профиля) или None."""
    try:
        text = _proxy_marker().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def set_proxy(proxy) -> None:
    """Прокси попытки для браузера. Другая сеть → Chrome перезапустится сам.

    proxy — dict из conol_proxy.parse_proxy()/ProxyState.next() либо None (напрямую).
    """
    global _desired_proxy
    _desired_proxy = proxy or None


def current_proxy():
    """Прокси, который должен использовать браузер (dict | None)."""
    return _desired_proxy


def _proxy_arg():
    """--proxy-server для разобранного прокси (None → флага нет)."""
    import conol_proxy  # локальный импорт: модуль не тянет requests и не циклится
    return conol_proxy.chrome_proxy_arg(_desired_proxy)


def _reset_handles() -> None:
    """Сбросить playwright-хендлы после перезапуска Chrome (старые ведут в мёртвый CDP).

    LAST_EXIT_IP сбрасывается вместе с ними: он относится к конкретному инстансу
    Chrome, и после переподключения старое значение врало бы («прокси применился»).
    """
    global _page, _browser, _browser_ws, LAST_EXIT_IP
    _page = None
    _browser = None
    _browser_ws = None
    LAST_EXIT_IP = None


def _log(msg: str) -> None:
    print("[captcha] %s" % msg, flush=True)


def _cdp_alive() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % CDP_PORT, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def _cdp_ws_url() -> Optional[str]:
    """webSocketDebuggerUrl живого Chrome на CDP_PORT (None — не спросилось).

    Нужен, чтобы отличить «наш» Chrome от перезапущенного: после рестарта порт тот
    же, но WS-эндпоинт другой, и старый _browser ведёт в никуда.
    """
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % CDP_PORT, timeout=3) as r:
            return (json.loads(r.read().decode("utf-8", "replace")) or {}).get("webSocketDebuggerUrl")
    except Exception:
        return None


def _page_alive(page) -> bool:
    """Живая ли страница НА САМОМ ДЕЛЕ (короткий round-trip в таргет).

    page.url и page.is_closed() — локальные свойства playwright: после смерти
    Chrome/страницы url отдаёт кэш, is_closed() возвращает False, и ошибка
    вылезает только на первом реальном вызове (Page.evaluate → "Target page,
    context or browser has been closed"). Проверено 08.10 на этой машине, см.
    docs/BUGFIX-CDP-2026-10-08.md. Поэтому живость подтверждаем вызовом.
    """
    if page is None:
        return False
    try:
        if page.is_closed():
            return False
        page.evaluate("1")
        return True
    except Exception:
        return False


def _live_browser_headless():
    """True/False по строке Browser из /json/version; None если не спросить."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % CDP_PORT, timeout=3) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        browser = str(data.get("Browser") or "")
        return "Headless" in browser
    except Exception:
        return None


def _cmdline_tokens(pid: int) -> list:
    """Аргументы процесса. /proc/<pid>/cmdline обычно NUL-раздельный, но в части
    окружений (песочницы, обёртки над procfs) ядро отдаёт его пробелами — держим
    оба случая, а матчинг ниже делаем подстрокой, а не точным равенством."""
    try:
        raw = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace")
    except OSError:
        return []
    return raw.split("\x00") if "\x00" in raw else raw.split(" ")


def chrome_pids() -> list:
    """Pids БРАУЗЕРНОГО процесса нашего Chrome (порт + наш профиль).

    Дочерние процессы (--type=renderer/...) отсеиваем: порт у них в cmdline не
    повторяется, но фильтр по --type надёжнее. Нужен для честного «погасить только
    своё»: порт 9228 держим мы, чужие процессы не трогаем.
    """
    port_arg = "--remote-debugging-port=%d" % CDP_PORT
    out = []
    for pid in [int(p) for p in os.listdir("/proc") if p.isdigit()]:
        toks = _cmdline_tokens(pid)
        if not toks:
            continue
        joined = " ".join(toks)          # терпимо и к пробелам, и к NUL-разделителям
        if port_arg not in joined or PROFILE_DIR not in joined:
            continue
        if "--type=" in joined:          # renderer/gpu/utility/crashpad — не браузер
            continue
        out.append(pid)
    return sorted(out)


def stop_chrome(timeout: float = 10.0) -> bool:
    """Погасить НАШ Chrome (точные pids) и дождаться, пока погаснет CDP.

    Для тестов и уборки: `fuser -k -n tcp 9228` убил бы любого, кто занял порт,
    а здесь мы бьём ровно те процессы, что несут наш порт И наш профиль.
    """
    pids = chrome_pids()
    if not pids:
        _reset_handles()
        return True
    for pid in pids:
        try:
            os.kill(pid, 15)
        except OSError:
            continue
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.3)
        if not _cdp_alive():
            _reset_handles()
            return True
    return not _cdp_alive()


def _stop_foreign_chrome() -> bool:
    """Убить Chrome, слушающий наш CDP-порт, чтобы поднять его в нужном режиме.

    Только POSIX (/proc): на этой машине панель живёт на Linux. Мы НЕ трогаем чужие
    процессы — матчим ровно `--remote-debugging-port=<наш порт>` И наш профиль.
    """
    if os.name == "nt":
        _log("режим живого Chrome не совпадает с конфигом — на Windows перезапусти его вручную")
        return False
    killed = chrome_pids()
    if not killed:
        return False
    for pid in killed:
        try:
            os.kill(pid, 15)
        except OSError:
            continue
    for _ in range(20):
        time.sleep(0.5)
        if not _cdp_alive():
            return True
    _log("старый Chrome на :%d не завершился за 10s (pids=%s)" % (CDP_PORT, killed))
    return False


def _launch_chrome() -> bool:
    """Launch Chrome with remote debugging on CDP_PORT. Reuses a warm profile dir.

    Прокси задаётся здесь и только здесь (--proxy-server): живой Chrome с ДРУГИМ
    прокси перезапускается — иначе ротация по аккаунтам не работает, а токен
    капчи уедет серверу с одного IP, пока регистрация идёт с другого.
    """
    want_proxy = _proxy_arg()
    if _cdp_alive():
        live_headless = _live_browser_headless()
        live_proxy = _live_proxy()
        headless_ok = live_headless is not None and live_headless == bool(HEADLESS)
        if headless_ok and live_proxy == want_proxy:
            return True
        # Живой браузер не того режима: токены из headless сервер режет 403, и подхватить
        # такой Chrome — верный способ «сломать» капчу посреди AFK-прогона (ровно это
        # случилось 07.10: воркер унаследовал headless-инстанс от ручного теста).
        # Тот же перезапуск нужен при смене прокси (ротация по аккаунтам).
        reasons = []
        if not headless_ok and live_headless is not None:
            reasons.append("режим %s вместо %s" % ("headless" if live_headless else "headful",
                                                   "headless" if HEADLESS else "headful"))
        if live_proxy != want_proxy:
            reasons.append("прокси %s вместо %s" % (live_proxy or "нет",
                                                    want_proxy or "нет"))
        _log("живой Chrome на :%d не подходит (%s) — перезапускаю"
             % (CDP_PORT, "; ".join(reasons) or "режим не определён"))
        if not _stop_foreign_chrome():
            _log("не смог перезапустить — использую живой Chrome как есть")
            return True
        _reset_handles()
    if not HEADLESS and DISPLAY_OVERRIDE and not display_alive(DISPLAY_OVERRIDE):
        # headful Chrome без дисплея падает мгновенно и выглядит как «капча не работает».
        # Скажем прямо, что не поднят виртуальный дисплей (см. start_panel.sh).
        _log("display %s не поднят — headful Chrome не стартует "
             "(запусти start_panel.sh или подними gamescope --backend headless)"
             % DISPLAY_OVERRIDE)
        return False
    Path(PROFILE_DIR).mkdir(parents=True, exist_ok=True)
    # SingletonLock от убитого инстанса мешает старту того же профиля
    for lock in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        try:
            (Path(PROFILE_DIR) / lock).unlink(missing_ok=True)
        except OSError:
            pass
    cmd = [
        CHROME_PATH,
        "--remote-debugging-port=%d" % CDP_PORT,
        "--user-data-dir=%s" % PROFILE_DIR,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
        "--window-size=1280,900",
        # Стартуем сразу на conol.ai, а не на about:blank: иначе в видимом окне
        # (ручной запуск / headful без gamescope) открывается пустая страница —
        # ровно та жалоба «открывается пустое окно, tab url: about:blank».
        BASE_URL,
    ]
    if want_proxy:
        # Локальные адреса (наш CDP) Chrome не проксирует по умолчанию — bypass не нужен.
        cmd.insert(1, "--proxy-server=%s" % want_proxy)
    if HEADLESS:
        cmd.insert(1, "--headless=new")
    env = dict(os.environ)
    if DISPLAY_OVERRIDE and not HEADLESS:
        env["DISPLAY"] = DISPLAY_OVERRIDE
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) |
                                       getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    except FileNotFoundError:
        _log("chrome not found at %s" % CHROME_PATH)
        return False
    for _ in range(30):
        time.sleep(1)
        if _cdp_alive():
            try:
                _proxy_marker().write_text(want_proxy or "", encoding="utf-8")
            except OSError:
                pass
            _log("chrome CDP up on :%d (%s, прокси %s)" % (
                CDP_PORT, "headless" if HEADLESS else "headful, DISPLAY=%s" % env.get("DISPLAY", "?"),
                want_proxy or "нет — напрямую"))
            _reset_handles()
            return True
    return False


def browser_exit_ip(page=None, timeout_ms: int = 8000):
    """Exit-IP браузера через ip-echo из самой страницы (None — не спросилось).

    Честная проверка «прокси реально применился к Chrome»: --proxy-server с
    логином/паролем Chrome может проигнорировать, и тогда браузер молча пойдёт
    напрямую. Ошибку не поднимаем: без ip-echo капча всё равно решается.
    """
    global LAST_EXIT_IP
    page = page if page is not None else _page
    if page is None:
        return None
    try:
        ip = page.evaluate("""(ms) => new Promise((resolve, reject) => {
            const t = setTimeout(() => reject(new Error('timeout')), ms);
            fetch('https://api.ipify.org?format=json')
              .then(r => r.json())
              .then(d => { clearTimeout(t); resolve(d && d.ip ? d.ip : null); })
              .catch(e => { clearTimeout(t); reject(e); });
        })""", timeout_ms)
    except Exception as exc:  # noqa: BLE001 — проба не должна ломать капчу
        _log("exit-IP браузера не определён: %s" % str(exc)[:120])
        return None
    ip = str(ip) if ip else None
    LAST_EXIT_IP = ip
    _log("exit-IP браузера: %s (прокси %s)" % (ip or "?", _proxy_arg() or "нет — напрямую"))
    return ip


_READY_GATE = (
    "typeof window.grecaptcha !== 'undefined' && !!window.grecaptcha.enterprise"
    " && typeof window.grecaptcha.enterprise.execute === 'function'"
    " && (typeof window.grecaptcha.enterprise.ready === 'function'"
    "     || typeof window.grecaptcha.ready === 'function')"
)


def _reset_playwright() -> None:
    """Убить playwright-драйвер, если он сам умер (тогда и connect не сработает)."""
    global _pw
    pw, _pw = _pw, None
    if pw is not None:
        try:
            pw.stop()
        except Exception:  # noqa: BLE001 — драйвер уже мёртв, это ожидаемо
            pass


def _pick_page(ctx):
    """Живой таб из контекста: сперва не-blank, иначе любой живой, иначе новый.

    Пустые (about:blank) табы, которые нам не достались, закрываем — иначе в
    видимом окне Chrome остаётся ровно то «пустое окно», на которое жаловался
    оператор (start на about:blank + новый таб под работу).
    """
    pages = []
    for p in list(ctx.pages):
        try:
            if not p.is_closed():
                pages.append(p)
        except Exception:  # noqa: BLE001 — мёртвый хендл просто не берём
            continue
    page = None
    for p in pages:
        if "conol.ai" in (p.url or ""):
            page = p
            break
    if page is None:
        page = pages[0] if pages else None
    if page is None:
        return ctx.new_page()
    for p in pages:
        if p is page:
            continue
        try:
            if not (p.url or "").strip() or p.url == "about:blank":
                p.close()
        except Exception:  # noqa: BLE001 — чужой/мёртвый таб не трогаем дальше
            continue
    return page


def _connect(force: bool = False):
    """Live page parked on BASE_URL. Живость проверяем делом, а не кэшем.

    Хендл переиспользуется, только если страница реально ОТВЕЧАЕТ (_page_alive) и
    Chrome на порту — тот самый инстанс (сверка webSocketDebuggerUrl). Любая
    потеря (страница закрылась, Chrome перезапустился, драйвер playwright умер)
    ведёт к полному переподключению: _launch_chrome() поднимет Chrome, если порт
    мёртв, дальше — новый connect_over_cdp и живой таб (или новый).
    """
    global _pw, _browser, _page, _browser_ws
    if not force and _page is not None:
        if _page_alive(_page):
            ws = _cdp_ws_url()
            if ws is not None and (_browser_ws is None or ws == _browser_ws):
                return _page
            _log("Chrome на :%d перезапустился (WS-эндпоинт сменился) — переподключаюсь"
                 % CDP_PORT)
        else:
            _log("страница-хендл мёртв (Target closed) — переподключаюсь")
        _reset_handles()
    elif force:
        _reset_handles()

    if not _launch_chrome():
        return None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _log("playwright not installed — chrome_cdp provider unavailable")
        return None

    for attempt in (1, 2):
        try:
            if _pw is None:
                _pw = sync_playwright().start()
            if _browser is None:
                # timeout is mandatory here: connect_over_cdp without it can hang
                # forever when Chrome's WS endpoint accepts but never completes the
                # handshake (observed 12-min wedge in an unattended run).
                _browser = _pw.chromium.connect_over_cdp(
                    "http://127.0.0.1:%d" % CDP_PORT, timeout=30000)
                _browser_ws = _cdp_ws_url()
            ctx = _browser.contexts[0] if _browser.contexts else _browser.new_context()
            page = _pick_page(ctx)
            page.set_default_timeout(30000)
            if "conol.ai" not in (page.url or ""):
                page.goto(BASE_URL, wait_until="domcontentloaded", timeout=45000)
            # make sure grecaptcha is present (conol loads it lazily on auth pages).
            # ENTERPRISE build on purpose: conol's key is reCAPTCHA Enterprise, and tokens
            # minted through the standard api.js are rejected by their verifier with
            # CAPTCHA_VERIFICATION_FAILED even though they are well-formed and carry the 0c
            # prefix. Measured 2026-10-07 on this box: api.js tokens 403 x9 (headless,
            # gamescope-headful and warm-profile runs alike); enterprise.js tokens 200/200
            # on the same page and profile. The readiness gate below therefore checks the
            # enterprise namespace too — plain `grecaptcha` alone would pass on the standard
            # build and silently reproduce the rejected-token path. `enterprise` appears as
            # a stub BEFORE ready/execute are attached, so the gate waits for the functions
            # (иначе api.ready → "TypeError: api.ready is not a function").
            page.evaluate("""(siteKey) => new Promise((resolve, reject) => {
                const g = window.grecaptcha;
                if (g && g.enterprise && typeof g.enterprise.execute === 'function') return resolve('already');
                const old = document.getElementById('eni-recaptcha');
                if (old) old.remove();
                const s = document.createElement('script');
                s.id = 'eni-recaptcha';
                s.src = 'https://www.recaptcha.net/recaptcha/enterprise.js?render=' + encodeURIComponent(siteKey);
                s.onload = () => resolve('loaded');
                s.onerror = () => reject(new Error('recaptcha load failed'));
                document.head.appendChild(s);
            })""", SITE_KEY)
            page.wait_for_function(_READY_GATE, timeout=20000)
            _page = page
            _log("решатель на живой странице %s (табов: %d)"
                 % (page.url or "?", len(ctx.pages)))
            browser_exit_ip(page)      # одна проверка на инстанс: прокси применился к Chrome?
            return page
        except Exception as e:
            msg = str(e)[:160]
            if attempt == 1 and ("Target page" in msg or "Target closed" in msg
                                 or "has been closed" in msg or "Browser closed" in msg
                                 or "Connection closed" in msg):
                # Соединение умерло между проверкой и использованием (Chrome закрыли
                # посреди connect) — перезапускаем драйвер и хендлы, пробуем ещё раз.
                _log("connect потерял таргет (%s) — перезапускаю playwright и пробую снова" % msg)
                _reset_handles()
                _reset_playwright()
                continue
            _log("connect failed: %s" % msg)
            _reset_handles()
            return None
    _log("connect failed: не удалось переподключиться к Chrome на :%d" % CDP_PORT)
    return None


_MINT_JS = """([siteKey, action]) => new Promise((resolve, reject) => {
    const g = window.grecaptcha;
    if (!g) return reject(new Error('grecaptcha missing'));
    const ent = g.enterprise;
    const exec = (ent && typeof ent.execute === 'function') ? ent.execute.bind(ent)
               : (typeof g.execute === 'function') ? g.execute.bind(g) : null;
    if (!exec) return reject(new Error('grecaptcha.execute missing'));
    const ready = (ent && typeof ent.ready === 'function') ? ent.ready.bind(ent)
                : (typeof g.ready === 'function') ? g.ready.bind(g) : null;
    let fired = false;
    const fire = (why) => {
        if (fired) return;
        fired = true;
        try { Promise.resolve(exec(siteKey, {action: action})).then(resolve).catch(reject); }
        catch (e) { reject(e); }
    };
    if (!ready) return fire('no-ready');
    // ready() на enterprise-сборке есть не всегда, и колбэк может не прийти:
    // через 8s запускаем execute сами, иначе solve висел бы до таймаута.
    setTimeout(() => fire('ready-timeout'), 8000);
    try { ready(() => fire('ready')); } catch (e) { fire('ready-threw'); }
})"""


def _mint_once(page, action: str) -> Optional[str]:
    """Один вызов execute на проверенно живой странице (None — не получилось/короткий токен)."""
    if page is None or page.is_closed():
        return None
    token = page.evaluate(_MINT_JS, [SITE_KEY, action])
    if isinstance(token, str) and len(token) > 50:
        return token
    _log("chrome_cdp returned a short/odd token (%r)" % str(token)[:40])
    return None


def solve_chrome_cdp(action: str) -> Optional[str]:
    """Mint one reCAPTCHA v3 token in the live Chrome tab. Returns token or None.

    Prefers the ENTERPRISE namespace (`grecaptcha.enterprise.execute`) — see the
    injection note in _connect(): the standard namespace mints tokens conol's verifier
    rejects. `ready` берётся с того же namespace, а если его там нет — с grecaptcha
    (на коноловской сборке grecaptcha.enterprise есть, а g.ready/g.execute нет;
    вызов api.ready наугад падал с "api.ready is not a function").

    evaluate вызывается ТОЛЬКО на живой странице: сначала _connect() (который сам
    проверяет живость round-trip'ом), и один ретрай с полным переподключением, если
    таргет умер между проверкой и вызовом.
    """
    for attempt in (1, 2):
        page = _connect(force=(attempt == 2))
        if page is None:
            return None
        try:
            if attempt == 1 and not _page_alive(page):
                # хендл умер между _connect и вызовом — сразу на реконнект
                _log("страница умерла перед solve — переподключаюсь")
                continue
            _log("solve action=%s на живой странице %s" % (action, (page.url or "?")[:80]))
            token = _mint_once(page, action)
            if token:
                return token
            return None
        except Exception as e:
            msg = str(e)[:160]
            _log("chrome_cdp solve error: %s" % msg)
            if attempt == 1 and ("Target page" in msg or "Target closed" in msg
                                 or "has been closed" in msg or "closed" in msg
                                 or "Execution context was destroyed" in msg):
                _reset_handles()   # следующий проход переподключится с нуля
                continue
            return None
    return None


def warmup() -> None:
    """Pre-launch Chrome + load conol.ai so the first solve is fast."""
    _connect()


# -------------------------------------------------------------- anticaptcha

def solve_anticaptcha(action: str) -> Optional[str]:
    """Existing paid path: RecaptchaV3TaskProxyless via api.anti-captcha.com."""
    import requests
    for key in ANTICAPTCHA_KEYS:
        try:
            resp = requests.post("https://api.anti-captcha.com/createTask", json={
                "clientKey": key,
                "task": {
                    "type": "RecaptchaV3TaskProxyless",
                    "websiteURL": BASE_URL,
                    "websiteKey": SITE_KEY,
                    "pageAction": action,
                    "minScore": 0.3,
                }
            }, timeout=30)
            data = resp.json()
            if data.get("errorId") != 0:
                _log("createTask fail (%s...): %s" % (key[:8], data.get("errorDescription", "?")))
                continue
            task_id = data["taskId"]
            deadline = time.time() + 90
            while time.time() < deadline:
                r = requests.post("https://api.anti-captcha.com/getTaskResult", json={
                    "clientKey": key, "taskId": task_id
                }, timeout=15).json()
                if r.get("status") == "ready":
                    token = r["solution"].get("gRecaptchaResponse", "")
                    if token:
                        return token
                elif r.get("errorId", 0) != 0:
                    _log("getTaskResult error: %s" % r.get("errorDescription", ""))
                    break
                time.sleep(3)
        except Exception as e:
            _log("anticaptcha exception (%s...): %s" % (key[:8], str(e)[:120]))
    return None


# ------------------------------------------------------------------- chain

_SOLVERS = {"chrome_cdp": solve_chrome_cdp, "anticaptcha": solve_anticaptcha}


def solve(action: str, skip: "set|None" = None) -> Optional[str]:
    """Try each configured provider in order; first non-empty token wins.

    `skip` names providers to bypass this round — used to ESCALATE when the
    server rejects a token (CAPTCHA_VERIFICATION_FAILED): a freshly-created
    Chrome profile mints a low reCAPTCHA-v3 score, so we skip chrome_cdp and
    fall through to the paid AntiCaptcha path instead of burning attempts on
    tokens the server keeps rejecting. The provider that produced the last
    token is exposed via LAST_PROVIDER so the caller knows whom to skip.
    """
    skip = skip or set()
    for name in PROVIDERS:
        if name in skip:
            continue
        fn = _SOLVERS.get(name)
        if fn is None:
            _log("unknown captcha provider %r — skipped" % name)
            continue
        tok = fn(action)
        if tok:
            global LAST_PROVIDER
            LAST_PROVIDER = name
            return tok
        _log("provider %s returned nothing for action=%s" % (name, action))
    # every non-skipped provider failed — retry ignoring the skip list once
    if skip:
        _log("all non-skipped providers exhausted; retrying full chain")
        return solve(action, skip=None)
    return None


if __name__ == "__main__":
    # self-test: python conol_captcha.py [action]
    act = sys.argv[1] if len(sys.argv) > 1 else "sign_up"
    t0 = time.time()
    tok = solve(act)
    if tok:
        print("OK action=%s len=%d time=%.1fs providers=%s token=%s...%s"
              % (act, len(tok), time.time() - t0, PROVIDERS, tok[:24], tok[-12:]))
    else:
        print("FAIL action=%s time=%.1fs providers=%s" % (act, time.time() - t0, PROVIDERS))
