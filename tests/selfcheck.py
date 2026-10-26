#!/usr/bin/env python3
"""selfcheck.py — офлайн-проверки conol-панели и путей после рефактора.

Без сети и без денег. exit 0 = все проверки прошли.

Покрывает то, что легко сломать молча:
  * парсер docs/MODELS.md (источник /api/models) и словарь статусов;
  * маппинг статусов аккаунтов (live/unverified/banned/no_credits -> ok/banned/...);
  * маскирование токенов (панель не должна светить полный токен в разметке);
  * разрешение cookies по basename (после переезда данные лежат в data/);
  * пути всех модулей реггера внутри data/ (регресс на рефактор папок);
  * job-файл AFK-воркера: атомарная запись/чтение и хвост лога по offset;
  * enterprise.js в капче — регресс на главный фикс 07.10 (api.js-токены сервер режет 403);
  * прокси-слой: конфиг/файл/валидация/ротация, --proxy-server в Chrome, эндпоинты панели;
  * учёт расхода USAGE-SPEC: conol_usage (дедуп/роллап/сырой хвост) и /api/usage в панели;
  * UI панели: канон-шаблон (APP_CONFIG), спец-блоки «Прокси» и «Использование», id из JS;
  * start.sh: существует, исполняемый, порт 9903, лог в data/panel.log.

Запуск: python tests/selfcheck.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "panel"))

import afk_worker    # noqa: E402
import conol_brd_relay  # noqa: E402
import conol_captcha  # noqa: E402
import conol_proxy   # noqa: E402
import conol_register  # noqa: E402
import server        # noqa: E402  (panel/server.py)

fails: list[str] = []
checks = 0


def check(name: str, cond: bool, extra: str = ""):
    global checks
    checks += 1
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else " — " + str(extra)))
    if not cond:
        fails.append(name)


# ── 1. модели ───────────────────────────────────────────────────────────────
doc = ROOT / "docs" / "MODELS.md"
check("docs/MODELS.md существует", doc.exists(), doc)
models = server.parse_models_table(doc.read_text(encoding="utf-8")) if doc.exists() else []
check("парсер нашёл >= 20 моделей", len(models) >= 20, len(models))
check("у каждой модели есть id/name/status/note",
      all(m["id"] and m["name"] and m["status"] and m["note"] for m in models))
check("статусы только из канонического словаря",
      all(m["status"] in server.MODEL_STATUSES for m in models),
      sorted({m["status"] for m in models}))
check("живые проверки 07.10 попали в verified",
      any(m["status"] == "verified" and m["last_checked"] == "2026-10-07" for m in models))
check("даунгрейды отделены от available",
      any(m["id"] == "claude-opus-5" and m["status"] == "downgraded" for m in models))
check("парсер не ловит таблицу без шапки id|name|status",
      server.parse_models_table("| a | b |\n|---|---|\n| x | y |") == [])
mview = server.models_view()
check("models_view отдаёт источник и дату",
      mview.get("source") == "docs/MODELS.md" and mview.get("source_date") == "2026-10-07",
      mview.get("source"))

# ── 2. статусы аккаунтов ────────────────────────────────────────────────────
def row(**kw):
    base = {"email": "a@b.c", "name": "N", "session_token": "t" * 60, "status": "live", "credits": 10}
    base.update(kw)
    return base

check("live+токен+кредиты -> ok", server.classify(row(), True)[0] == "ok")
check("credits=0 -> no_credits", server.classify(row(credits=0), True)[0] == "no_credits")
check("status=banned -> banned", server.classify(row(status="banned"), True)[0] == "banned")
check("status=unverified -> unverified", server.classify(row(status="unverified"), True)[0] == "unverified")
check("нет токена и не unverified -> failed", server.classify(row(session_token=""), True)[0] == "failed")
check("битый cookies_path всё ещё ok (шлюз берёт токен из пула)",
      server.classify(row(), False)[0] == "ok")
check("метка о пропавшем cookies в note",
      "cookies" in server.classify(row(), False)[1])
check("счётчики знают словарь спеки",
      {"total", "ok", "banned", "no_credits", "failed", "unverified"} <=
      set(server.count_statuses([{"status": "ok"}]).keys()))
# `starting` обязан считаться активным прогоном: проверка только по `running` пропустила
# второй воркер (поймано 07.10), и второй процесс взялся бы за тот же пул.
check("starting считается активным job'ом",
      server.job_active({"status": "starting", "pid": os.getpid()}) is True)
check("running считается активным job'ом",
      server.job_active({"status": "running", "pid": os.getpid()}) is True)
check("мёртвый pid активным не считается",
      server.job_active({"status": "running", "pid": 0}) is False)
check("done/stopped/failed не активны",
      not any(server.job_active({"status": s, "pid": os.getpid()})
              for s in ("done", "stopped", "failed", "idle")))
check("reconcile переводит starting с мёртвым pid в терминальный статус",
      server.reconcile_job({"status": "starting", "pid": 0})["status"] in ("failed", "stopped"))

# ── 3. маскирование и cookies ───────────────────────────────────────────────
token = "IxXDbRTWpWeDv9fmXgWxKL1gymyNNJRH.fqaU3GidASmzPDJ5rX5lOiSzee%2FXRj9T86Fz9Bvxr14%3D"
masked = server.mask(token)
check("маска не содержит середину токена", masked.endswith(token[-4:]) and "%2F" not in masked, masked)
check("короткое значение маскируется по краям", server.mask("abc") == "ab…bc", server.mask("abc"))
check("маска заметно короче токена", len(masked) < len(token) / 2, len(masked))

real_cookie = ROOT / "data" / "cookies_conol1397490503.json"
if real_cookie.exists():
    stale = {"email": "conol<id>@mail.example.com",
             "cookies_path": "/old/root/cookies_conol1397490503.json"}
    check("cookies резолвятся по basename из data/",
          server.cookie_file_for(stale) == real_cookie, server.cookie_file_for(stale))
else:
    check("файл cookies из пула на месте (data/)", False, real_cookie)
check("нет cookies_path -> None", server.cookie_file_for({"email": "x"}) is None)

# ── 4. пути после рефактора папок ───────────────────────────────────────────
data_dir = ROOT / "data"
for name, path in (("пул", conol_register.POOL_FILE), ("pid-слот", conol_register.PID_FILE),
                   ("results-лог", conol_register.RESULTS_FILE)):
    check("%s лежит в data/" % name, Path(path).parent == data_dir, path)
check("data/ существует", data_dir.is_dir())
check("панель читает тот же пул, что и реггер", server.POOL_FILE == conol_register.POOL_FILE)
check("рабочие каталоги панели на месте",
      (ROOT / "panel" / "server.py").exists() and (ROOT / "panel" / "static" / "index.html").exists()
      and (ROOT / "docs" / "README.md").exists())

# ── 5. job-файл и хвост лога ────────────────────────────────────────────────
with tempfile.TemporaryDirectory(prefix="conol_selfcheck_") as tmp:
    tmp_path = Path(tmp)
    orig_job, orig_log = afk_worker.JOB_FILE, afk_worker.AFK_LOG
    afk_worker.JOB_FILE = tmp_path / "afk_job.json"
    afk_worker.AFK_LOG = tmp_path / "afk.log"
    try:
        afk_worker.write_job({"job_id": "t1", "status": "running", "done": 0, "total": 2})
        afk_worker.write_job({"done": 1, "ok": 1})
        job = afk_worker.read_job()
        check("write_job сливает поля, а не затирает", job["job_id"] == "t1" and job["done"] == 1, job)
        check("write_job оставляет файл после перезаписи", afk_worker.JOB_FILE.exists())
        check("нет .tmp-мусора после атомарной записи",
              not afk_worker.JOB_FILE.with_name("afk_job.json.tmp").exists())
        check("битый job-файл читается как пустой",
              (afk_worker.JOB_FILE.write_text("{oops"), afk_worker.read_job() == {})[1])

        afk_worker.AFK_LOG.write_text("line1\nline2\nline3\nline4\n", encoding="utf-8")
        check("log_tail берёт последние N строк", server.log_tail(afk_worker.AFK_LOG, 2) == ["line3", "line4"],
              server.log_tail(afk_worker.AFK_LOG, 2))
        check("log_tail с offset отдаёт только новое",
              server.log_tail(afk_worker.AFK_LOG, 10, offset=12) == ["line3", "line4"],
              server.log_tail(afk_worker.AFK_LOG, 10, offset=12))
        check("log_tail на отсутствующем файле -> []",
              server.log_tail(tmp_path / "nope.log", 5) == [])
    finally:
        afk_worker.JOB_FILE, afk_worker.AFK_LOG = orig_job, orig_log

# ── 6. капча (регресс на фикс 07.10) ────────────────────────────────────────
src = (ROOT / "conol_captcha.py").read_text(encoding="utf-8")
check("капча грузит enterprise.js (api.js-токены сервер режет 403)", "recaptcha/enterprise.js" in src)
check("капча вызывает grecaptcha.enterprise.execute", "g.enterprise" in src and "enterprise.execute" in src)
check("капча умеет headful-дисплей (gamescope-путь)", "DISPLAY_OVERRIDE" in src
      and "display_alive" in src)
check("несуществующий дисплей честно мёртв", conol_captcha.display_alive(":9999") is False)
check("headless/headful берётся из config/env",
      isinstance(conol_captcha.HEADLESS, bool) and os.environ.get("CONOL_CHROME_HEADLESS") is None
      or os.environ.get("CONOL_CHROME_HEADLESS") in ("0", "1", "true", "false"))
check("провайдеры капчи по умолчанию — бесплатный chrome_cdp",
      conol_captcha.PROVIDERS == ["chrome_cdp"] or conol_captcha.PROVIDERS[0] == "chrome_cdp",
      conol_captcha.PROVIDERS)

# ── 7. запуск ───────────────────────────────────────────────────────────────
start = ROOT / "start.sh"
check("start.sh на месте", start.exists())
check("start.sh исполняемый", bool(start.stat().st_mode & 0o111) if start.exists() else False)
if start.exists():
    text = start.read_text(encoding="utf-8")
    check("start.sh снимает PYTHONHOME/PYTHONPATH/LD_LIBRARY_PATH",
          all(v in text for v in ("unset PYTHONHOME", "PYTHONPATH", "LD_LIBRARY_PATH")))
    check("start.sh знает свой порт 9903", "9903" in text)
    check("start.sh логирует в data/panel.log", "data/panel.log" in text)
    # Сокет остаётся после убитого gamescope; проверка «дисплей жив» обязана быть клиентской,
    # иначе Chrome получит мёртвый DISPLAY и капча молча не заработает.
    check("start.sh проверяет дисплей настоящим X-клиентом",
          "probe_display" in text and "xdpyinfo" in text)

# ── 8. прокси (регресс на «изначально и везде») ─────────────────────────────
# Статус: conol ловит 429 RATE_LIMITED с домашнего IP — прокси обязаны применяться
# и к браузеру (--proxy-server), и к HTTP (requests), с ротацией по аккаунтам.
proxies, bad = conol_proxy.load_proxies()
# С 09.10 в config.json прописаны BRD-зоны, и они приоритетнее статического
# списка: дают свежий exit-IP на каждый аккаунт. Пустой конфиг (без зон и без
# файла) по-прежнему обязан давать пустой пул — это проверяем на изолированной
# копии модуля, подменив чтение конфига.
check("load_proxies: BRD-зоны дают пул шаблонов",
      bool(proxies) and all(p.get("brd") for p in proxies) and bad == [],
      [conol_proxy.mask(p["raw"]) for p in proxies])
check("BRD-шаблон минтится в рабочую сессию со свежим session-id",
      (lambda t: (lambda m: m is not None
                  and "session-*" not in m["raw"]
                  and m["raw"] != t["raw"]
                  and m.get("state_key") == t["raw"])(conol_proxy.mint_brd(t)))(
          conol_proxy.brd_pool()[0]))
check("пустой пул -> mode=direct и честная пометка про 429",
      conol_proxy.describe([])["mode"] == "direct"
      and "429" in (conol_proxy.describe([])["note"] or ""))
check("DIRECT_NOTE объясняет риск прямого режима", "429" in conol_proxy.DIRECT_NOTE)
# Chrome игнорирует логин/пароль в --proxy-server, поэтому BRD-прокси обязан
# отдаваться браузеру через локальный релей авторизации, а не как есть.
_brd_session = conol_proxy.mint_brd(conol_proxy.brd_pool()[0])
check("chrome_proxy_arg для BRD отдаёт локальный релей (не BRD-хост)",
      "127.0.0.1" in (conol_proxy.chrome_proxy_arg(_brd_session) or "")
      and "brd.superproxy.io" not in (conol_proxy.chrome_proxy_arg(_brd_session) or ""))
check("HTTP-часть идёт напрямую в BRD (авторизация поддерживается)",
      "brd.superproxy.io" in (conol_proxy.requests_proxies(_brd_session) or {}).get("https", ""))
check("релей: строка BRD разбирается в host/port/auth",
      (lambda h, p, a: h == "brd.superproxy.io" and p == 44445 and a.startswith("Basic "))
      (*conol_brd_relay._upstream_parts(_brd_session["raw"])))
conol_brd_relay.close_all()
check("состояние прокси — в data/ (proxies.json)",
      conol_proxy.STATE_FILE.parent == ROOT / "data"
      and conol_proxy.STATE_FILE.name == "proxies.json", conol_proxy.STATE_FILE)
check("файл-пул по умолчанию — data/proxies.txt",
      conol_proxy.proxies_file() == ROOT / "data" / "proxies.txt", conol_proxy.proxies_file())
check("файл-пул создан и не пуст (инструкция внутри)",
      conol_proxy.proxies_file().exists()
      and "scheme://" in conol_proxy.proxies_file().read_text(encoding="utf-8"))
check("config.example.json показывает ключ proxies",
      "proxies" in json.loads((ROOT / "config.example.json").read_text(encoding="utf-8")))
gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
check(".gitignore прячет список и статусы прокси",
      "data/proxies.txt" in gi and "data/proxies.json" in gi)

reg_src = (ROOT / "conol_register.py").read_text(encoding="utf-8")
check("register_one принимает proxy (ротация по аккаунтам)",
      "def register_one(suffix: int, provider: str = None, proxy=None)" in reg_src)
check("HTTP-сессия реггера умеет прокси", "def new_client(proxy=None)" in reg_src
      and "conol_proxy.requests_proxies(proxy)" in reg_src)
check("verify_session/get_balance ходят через прокси попытки",
      reg_src.count("proxies=conol_proxy.requests_proxies(proxy)") >= 2)
check("внутри попытки браузер переводится на тот же прокси",
      "conol_captcha.set_proxy(proxy)" in reg_src)
check("CLI умеет --no-proxy и --proxies-file",
      "--no-proxy" in reg_src and "--proxies-file" in reg_src)
check("фейлы попыток пишутся в health прокси (накопление)",
      "conol_proxy.looks_proxy_failed" in reg_src)

cap_src = (ROOT / "conol_captcha.py").read_text(encoding="utf-8")
check("Chrome получает --proxy-server", "--proxy-server=" in cap_src)
check("смена прокси перезапускает Chrome (маркер профиля)",
      "_proxy_marker" in cap_src and "set_proxy" in cap_src
      and "_live_proxy" in cap_src)
check("set_proxy присутствует в API капчи", callable(conol_captcha.set_proxy))
check("exit-IP браузера проверяется (прокси реально применился)",
      "browser_exit_ip" in cap_src and "api.ipify.org" in cap_src)

afk_src = (ROOT / "panel" / "afk_worker.py").read_text(encoding="utf-8")
check("AFK-воркер: ротация по аккаунтам + --no-proxy",
      "pick_for_attempt" in afk_src and "--no-proxy" in afk_src)
check("AFK-воркер пишет режим сети в job (панель показывает «напрямую»)",
      '"proxy_mode": mode' in afk_src or '"proxy_mode"' in afk_src)

srv_src = (ROOT / "panel" / "server.py").read_text(encoding="utf-8")
check("панель: GET/POST /api/proxies", '/api/proxies' in srv_src
      and srv_src.count('"/api/proxies"') >= 2)
check("панель: summary несёт блок proxies", '"proxies": proxy_mode_info()' in srv_src)
check("панель: register понимает no_proxy (чекбокс)", '"no_proxy"' in srv_src
      and "cmd.append(\"--no-proxy\")" in srv_src)
check("панель: перепроверка пула идёт через ротацию прокси",
      "pick_for_attempt" in srv_src and "check_one(row, proxy=proxy)" in srv_src)
check("панель: фоновая перепроверка прокси и unban_all (кнопка «Перепроверить»)",
      "start_proxy_check" in srv_src and "unban_all()" in srv_src)
check("панель: plog пишет в data/panel.log", 'PANEL_LOG = DATA_DIR / "panel.log"' in srv_src)

# ── 9. учёт расхода (USAGE-SPEC) ────────────────────────────────────────────
# Панель не дублирует ledger: модуль conol_usage.py пишет data/usage.jsonl,
# сервер доливает источники conol (results-лог, балансы пула, журнал шлюза).
import conol_usage  # noqa: E402
check("учёт: панель импортирует conol_usage", "import conol_usage" in srv_src)
check("учёт: GET /api/usage в сервере", srv_src.count('"/api/usage"') >= 1)
check("учёт: GET /api/usage/raw в сервере", '"/api/usage/raw"' in srv_src
      and "conol_usage.raw_tail" in srv_src)
check("учёт: контракт USAGE-SPEC (payload/rollup/raw_tail/record/snapshot)",
      all(callable(getattr(conol_usage, f, None))
          for f in ("payload", "rollup", "raw_tail", "record", "snapshot", "ingest_log")))
check("учёт: источники conol — results-лог, балансы пула, журнал шлюза",
      all(name in srv_src for name in ("_results_events", "_pool_snapshot_events", "_gateway_events")))
check("учёт: часовой снапшот пула в фоновом потоке",
      "usage_heartbeat" in srv_src and "Thread(target=usage_heartbeat" in srv_src)
check("учёт: токенов у conol нет — tokens честно н/д, оценка только в meta",
      "tokens_in\": None" in srv_src and "tokens_est" in srv_src)
check("учёт: selftest модуля зелёный (дедуп/роллап/сырой хвост)", conol_usage.selftest() is True)

# ── 10. UI (канон-шаблон дизайн-модели + спец-блоки conol) ───────────────────
import re  # noqa: E402
ui_src = (ROOT / "panel" / "static" / "index.html").read_text(encoding="utf-8")
check("UI: APP_CONFIG канона (conol / 9903 / API_BASE / без заглушек)",
      'SERVICE_NAME: "conol"' in ui_src and "DEFAULT_PORT: 9903" in ui_src
      and 'API_BASE: "/api"' in ui_src and "MOCK_FALLBACK: false" in ui_src)
check("UI: 100% офлайн — без внешних CDN/URL",
      not re.findall(r'https?://(?!127\.0\.0\.1|localhost)[A-Za-z0-9.-]+', ui_src)
      and not re.findall(r'(?:src|href)="https?://', ui_src) and "<link" not in ui_src)
check("UI: тёмная тема канона (CSS-переменные шаблона)",
      "--bg-base" in ui_src and "--text-primary" in ui_src and "tabs-nav" in ui_src)
check("UI: блок «Прокси» с таблицей статусов", "Прокси-пул (ротация по аккаунтам)" in ui_src
      and 'id="proxy-rows"' in ui_src)
check("UI: чекбокс «без прокси»", 'id="noProxy"' in ui_src)
check("UI: кнопка «Перепроверить» прокси", 'id="btn-proxy-recheck"' in ui_src)
check("UI: честная пометка прямого режима (429)", "429" in ui_src and "loadProxies" in ui_src)
check("UI: чекбокс сохраняется через POST /api/proxies/mode",
      '"/proxies/mode"' in ui_src and "{ direct: direct }" in ui_src)
check("UI: регистрация передаёт no_proxy", "no_proxy: noProxy" in ui_src)
check("UI: вкладка «Использование» читает /api/usage (+ сырой хвост)",
      'id="tab-use"' in ui_src and '"/usage?range="' in ui_src
      and '"/usage/raw?tail=50"' in ui_src and "renderUsage" in ui_src)
check("UI: неизвестное поле = «н/д», не выдуманные числа",
      "н/д" in ui_src and "fmtNum" in ui_src)
check("UI: капча без ручного слайдера-заглушки (chrome_cdp честно)",
      "chrome_cdp" in ui_src and 'id="slider-track"' not in ui_src
      and 'id="slider-thumb"' not in ui_src)
# JS обращается к элементам по id — опечатка в разметке рвёт весь рендер молча
_ids_in_html = set(re.findall(r'id="([^"]+)"', ui_src))
_used_ids = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', ui_src)) | set(
    re.findall(r'getElementById\("([^"]+)"\)', ui_src)) | set(
    re.findall(r'querySelector\("#([A-Za-z0-9_-]+)"\)', ui_src))
check("UI: все id, к которым обращается JS, есть в разметке",
      not (_used_ids - _ids_in_html), sorted(_used_ids - _ids_in_html))
check("UI: вкладки совпадают с секциями",
      set(re.findall(r'data-tab="([^"]+)"', ui_src)) ==
      set(re.findall(r'id="tab-([a-z]+)"', ui_src)))

check("no_proxy из панели доходит до API",
      "no_proxy" in json.dumps(json.loads('{"count":1,"verify":true,"no_proxy":true}')))

# ── 11. вкладка «Ключи»: UI + GET /api/keys ─────────────────────────────────
check("UI: вкладка «Ключи» (навигация + секция + загрузка)",
      'data-tab="keys"' in ui_src and 'id="tab-keys"' in ui_src
      and 'id="tab-btn-keys"' in ui_src and "loadKeys" in ui_src)
check("UI: шапка «аккаунтов N · живых M · кредитов SUM»",
      'id="keys-head"' in ui_src and "аккаунтов " in ui_src and "живых " in ui_src
      and "кредитов " in ui_src)
check("UI: кнопки «копировать всё» и экспорт txt/json",
      all(('id="%s"' % i) in ui_src for i in
          ("btn-keys-copy-all", "btn-keys-export-txt", "btn-keys-export-json")))
check("UI: маска + «показать» + «копировать» для секретов",
      "data-key-reveal" in ui_src and "data-key-copy" in ui_src
      and "function keySecret" in ui_src and "toggleKeysReveal" in ui_src)
check("UI: построчный формат email|password|token и «н/д» вместо выдумок",
      "email|password|token" in ui_src and "н/д" in ui_src and "keysLines" in ui_src)
check("сервер: GET /api/keys + keys_view", '"/api/keys"' in srv_src and "def keys_view" in srv_src)
_summary_src = srv_src.split("def _summary(")[1].split("def _raw_statuses(")[0]
check("сервер: в /api/summary нет паролей/токенов/api_key",
      not any(k in _summary_src for k in ("password", "session_token", "api_key")))

# keys_view на живом пуле; сеть выключаем — selfcheck остаётся офлайн
_orig_conol_get = server.conol_get
_orig_agent_cache = dict(server._agent_cache)
server.conol_get = lambda *a, **kw: (0, "selfcheck: сеть выключена")
server._agent_cache.update({"ts": 0.0, "data": None})
try:
    kv = server.keys_view()
finally:
    server.conol_get = _orig_conol_get
    server._agent_cache.update(_orig_agent_cache)
_pool_rows = server.read_pool()
check("keys: статистика шапки (аккаунтов/живых/кредитов)",
      isinstance(kv.get("pool"), dict) and kv["pool"]["accounts"] == len(_pool_rows)
      and 0 <= kv["pool"]["live"] <= kv["pool"]["accounts"]
      and isinstance(kv["pool"]["credits"], (int, float)), kv.get("pool"))
check("keys: по аккаунту отдаются пароль и session_token вместе с маской",
      len(kv["accounts"]) == len(_pool_rows)
      and all(all(f in a for f in ("password", "password_masked", "session_token",
                                   "token_masked", "pool_token_files"))
              for a in kv["accounts"]))
check("keys: маска не равна полному секрету",
      all(a["token_masked"] != a["session_token"]
          for a in kv["accounts"] if a["session_token"]))
check("keys: пул-токены — фактическое наличие файлов в data/",
      all(isinstance(a.get("pool_token_files"), list) for a in kv["accounts"])
      and all(f.get("name") and "exists" in f
              for a in kv["accounts"] for f in a["pool_token_files"]))
check("keys: источники data/ с признаком существования",
      isinstance(kv.get("sources"), list) and bool(kv["sources"])
      and all("exists" in s and s.get("name") for s in kv["sources"]))
check("keys: gateway api_key — полное значение + маска",
      kv["gateway"]["api_key"] == server.config().get("gateway", {}).get("api_key", "")
      and kv["gateway"]["api_key_masked"] == server.mask(kv["gateway"]["api_key"]))

# ── итог ────────────────────────────────────────────────────────────────────
print()
print("%d/%d проверок прошло" % (checks - len(fails), checks) if not fails
      else "ПРОВАЛЫ: %s" % fails)
sys.exit(1 if fails else 0)