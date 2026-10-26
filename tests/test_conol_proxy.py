"""Self-check для прокси-слоя conol-реггера (conol_proxy.py).

Run: python tests/test_conol_proxy.py

Офлайн: сеть не трогаем, живых регистраций нет. Прокси-валидатор проверяется на
заведомо мёртвом локальном адресе (127.0.0.1:PORТ_ЗАКРЫТ) — это честный fail без
выхода в интернет. Состояние/ротация гоняются на временном файле, живой
data/proxies.json не трогается (его может читать панель/воркер).

Почему это важно: ротация и «вне ротации» — единственное, что мешает прогону
долбить один и тот же мёртвый exit-IP (и ловить 429 пачкой на весь аккаунт-лист).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import conol_proxy as cp  # noqa: E402

fails: list[str] = []
checks = 0


def check(name: str, cond: bool, extra: str = ""):
    global checks
    checks += 1
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else " — " + str(extra)))
    if not cond:
        fails.append(name)


TMP = Path(tempfile.mkdtemp(prefix="conol_proxy_test_"))

# Чекбокс «без прокси» из панели (data/proxy_direct_state.json) переживает рестарт
# панели, поэтому на машине, где его включали руками, этот self-check падал на
# живом состоянии машины (payload: mode=direct, load_proxies → []). Снимок
# состояния возвращаем на место в конце, а сам тест гоняем как в режиме прокси.
_DIRECT_SNAPSHOT = (cp.DIRECT_STATE_FILE.read_bytes()
                    if cp.DIRECT_STATE_FILE.exists() else None)


def _restore_direct_state() -> None:
    try:
        if _DIRECT_SNAPSHOT is None:
            cp.DIRECT_STATE_FILE.unlink(missing_ok=True)
        else:
            cp.DIRECT_STATE_FILE.write_bytes(_DIRECT_SNAPSHOT)
    except OSError:
        pass


cp.DIRECT_STATE_FILE.unlink(missing_ok=True)
cp.set_force_direct(False)


def closed_port() -> int:
    """Свободный порт на localhost: соединение к нему отбивается сразу (fail без сети)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


try:
    # ── 1. разбор строк ────────────────────────────────────────────────────
    p1 = cp.parse_proxy("http://user:p%40ss@1.2.3.4:8000")
    check("parse: схема/хост/порт/логин/пароль", p1 and p1["scheme"] == "http"
          and p1["host"] == "1.2.3.4" and p1["port"] == 8000
          and p1["username"] == "user" and p1["password"] == "p@ss", p1)
    check("parse: без схемы → http", cp.parse_proxy("1.2.3.4:3128")["scheme"] == "http")
    check("parse: socks5h нормализуется в socks5",
          cp.parse_proxy("socks5h://1.2.3.4:1080")["scheme"] == "socks5")
    check("parse: мусор → None", cp.parse_proxy("просто текст") is None)
    check("parse: пусто/комментарий → None",
          cp.parse_proxy("") is None and cp.parse_proxy("  # прокси") is None)
    check("mask прячет пароль", cp.mask("http://user:secret@1.2.3.4:8000")
          == "http://user:***@1.2.3.4:8000", cp.mask("http://user:secret@1.2.3.4:8000"))
    check("mask без логина", cp.mask("http://1.2.3.4:8000") == "http://1.2.3.4:8000")

    good, bad = cp.parse_proxy_list([
        "http://a:b@1.1.1.1:8000",
        "http://a:b@1.1.1.1:8000",        # дубль
        "# комментарий",
        "",
        "мусор",
        "http://a:b@2.2.2.2:8000",
    ])
    check("дедуп и отброс мусора", len(good) == 2 and len(bad) == 1, (len(good), bad))
    check("битая строка названа в отчёте", "мусор" in bad[0], bad)
    socks_good, socks_bad = cp.parse_proxy_list(["socks5://1.2.3.4:1080"])
    check("socks5 без PySocks честно отброшен с причиной",
          (not socks_good and "PySocks" in socks_bad[0]) or socks_good,
          (socks_good, socks_bad))

    # ── 2. представления для потребителей ─────────────────────────────────
    req = cp.requests_proxies(good[0])
    check("requests: обе схемы на один прокси",
          req == {"http": good[0]["raw"], "https": good[0]["raw"]}, req)
    check("requests: None → None (напрямую)", cp.requests_proxies(None) is None)
    # Chrome вырезает логин/пароль из --proxy-server, поэтому прокси с
    # авторизацией отдаём браузеру через локальный релей (127.0.0.1:<port>),
    # который сам добавляет Proxy-Authorization. Без авторизации — как есть.
    check("chrome-флаг с креденшелами → локальный релей (креды не утекают в флаг)",
          (cp.chrome_proxy_arg(p1) or "").startswith("http://127.0.0.1:")
          and "user" not in (cp.chrome_proxy_arg(p1) or ""), cp.chrome_proxy_arg(p1))
    check("chrome-флаг без креденшелов — прокси как есть",
          cp.chrome_proxy_arg(cp.parse_proxy("http://1.2.3.4:3128")) == "http://1.2.3.4:3128")
    check("chrome-флаг для None → None", cp.chrome_proxy_arg(None) is None)
    check("urllib-opener строится и с прокси, и без", cp.urllib_opener(good[0]) and cp.urllib_opener(None))

    # ── 3. валидация через ip-echo (мёртвый прокси = честный fail) ────────
    dead = cp.parse_proxy("http://127.0.0.1:%d" % closed_port())
    res = cp.check_proxy(dead, timeout=3, urls=["https://api.ipify.org?format=json"])
    check("мёртвый прокси → ok=False", res["ok"] is False, res)
    check("мёртвый прокси → есть текст ошибки", bool(res["error"]), res)
    check("мёртвый прокси: raw/masked заполнены", res["raw"] == dead["raw"] and res["masked"], res)
    check("check_proxy(None) не падает", cp.check_proxy(None)["ok"] is False)
    check("_extract_ip: ipify-json", cp._extract_ip('{"ip":"9.9.9.9"}') == "9.9.9.9")
    check("_extract_ip: httpbin-origin (первый из списка)",
          cp._extract_ip('{"origin":"9.9.9.9, 8.8.8.8"}') == "9.9.9.9")
    check("_extract_ip: plain text", cp._extract_ip("9.9.9.9\n") == "9.9.9.9")

    # ── 3b. успешный путь валидатора: локальный прокси + localhost ip-echo ──
    # Полностью локально: поднимаем свой forward-proxy (с Basic-авторизацией, как у
    # реальных residential) и «ip-echo»-заглушку. Проверяем и ok-путь, и то, что
    # логин/пароль из строки прокси реально уезжает в Proxy-Authorization.
    import base64 as _b64          # noqa: E402
    import http.client as _http    # noqa: E402
    import threading as _th        # noqa: E402
    from http.server import BaseHTTPRequestHandler as _BH, ThreadingHTTPServer as _Srv  # noqa: E402

    PROXY_AUTH = "Basic " + _b64.b64encode(b"u:p").decode()

    class _Echo(_BH):
        def do_GET(self):
            body = b'{"ip": "203.0.113.7"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class _FwdProxy(_BH):
        def do_GET(self):
            if self.headers.get("Proxy-Authorization") != PROXY_AUTH:
                self.send_response(407)
                self.send_header("Proxy-Authenticate", 'Basic realm="test"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            u = cp.urlsplit(self.path)  # абсолютная форма запроса к прокси
            conn = _http.HTTPConnection(u.hostname, u.port or 80, timeout=5)
            conn.request("GET", u.path or "/", headers={"Host": u.netloc})
            r = conn.getresponse()
            body = r.read()
            self.send_response(r.status)
            self.send_header("Content-Type", r.getheader("Content-Type") or "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    echo_srv = _Srv(("127.0.0.1", 0), _Echo)
    proxy_srv = _Srv(("127.0.0.1", 0), _FwdProxy)
    for srv in (echo_srv, proxy_srv):
        _th.Thread(target=srv.serve_forever, daemon=True).start()
    echo_url = "http://127.0.0.1:%d/ip" % echo_srv.server_port
    auth_proxy = cp.parse_proxy("http://u:p@127.0.0.1:%d" % proxy_srv.server_port)
    bad_proxy = cp.parse_proxy("http://u:wrong@127.0.0.1:%d" % proxy_srv.server_port)
    try:
        res = cp.check_proxy(auth_proxy, timeout=5, urls=[echo_url])
        check("успешный путь: ok + IP из ip-echo", res["ok"] is True and res["ip"] == "203.0.113.7", res)
        check("успешный путь: ms заполнен", isinstance(res["ms"], int) and res["error"] is None, res)
        bad = cp.check_proxy(bad_proxy, timeout=5, urls=[echo_url])
        check("неверный пароль прокси → fail с HTTP 407", bad["ok"] is False and "407" in str(bad["error"]),
              bad)
        check("credentials из строки прокси уезжают в прокси (ok-путь выше это доказал)",
              cp.requests_proxies(auth_proxy)["http"].startswith("http://u:p@"))
    finally:
        for srv in (echo_srv, proxy_srv):
            srv.shutdown()
            srv.server_close()

    # ── 4. классификация фейла попытки ────────────────────────────────────
    check("429/RATE_LIMITED = фейл прокси", cp.looks_proxy_failed("HTTP 429 RATE_LIMITED"))
    check("requests-сетевое исключение = фейл прокси",
          cp.looks_proxy_failed("ProxyError: Cannot connect to proxy"))
    check("обычная ошибка аккаунта — не фейл прокси",
          not cp.looks_proxy_failed("email mismatch: x@y.z"))
    check("пустая ошибка — не фейл", not cp.looks_proxy_failed(None))

    # ── 5. состояние: статусы, ротация, подряд-фейлы ──────────────────────
    state_path = TMP / "proxies.json"
    st = cp.ProxyState(state_path)
    pool, _ = cp.parse_proxy_list(["http://u:p@10.0.0.1:8000",
                                   "http://u:p@10.0.0.2:8000",
                                   "http://u:p@10.0.0.3:8000"])
    check("пул разобран", len(pool) == 3, len(pool))

    order = []
    for _ in range(4):
        pr, idx, warn = cp.pick_for_attempt(pool, st, email="a@b.c")
        order.append(idx)
        check("pick возвращает прокси и предупреждений нет", pr is not None and warn is None)
    check("ротация по кругу 0,1,2,0", order == [0, 1, 2, 0], order)
    check("индекс ротации сохраняется в файл", cp.ProxyState(state_path).data.get("index") == 1)
    check("last_used записан", (st.data.get("last_used") or {}).get("email") == "a@b.c"
          or (st.data.get("last_used") or {}).get("masked"), st.data.get("last_used"))

    # порог подряд-фейлов: 3 фейла → вне ротации, успех сбрасывает
    for _ in range(2):
        st.record_result(pool[1]["raw"], ok=False)
    check("2 фейла — ещё в ротации", st.is_banned(pool[1]["raw"]) is False)
    st.record_result(pool[1]["raw"], ok=False)
    check("3 фейла (порог) → вне ротации", st.is_banned(pool[1]["raw"]) is True)
    st.record_result(pool[1]["raw"], ok=True)
    check("успешная попытка сбрасывает фейлы",
          st.is_banned(pool[1]["raw"]) is False and st.health_of(pool[1]["raw"])["fails"] == 0)

    # забаненный прокси обходится ротацией; все забанены → (None, -2) с предупреждением
    st2 = cp.ProxyState(TMP / "proxies2.json")
    for p in pool[:2]:
        for _ in range(3):
            st2.record_result(p["raw"], ok=False)
    seen = set()
    for _ in range(4):
        pr, idx, _warn = cp.pick_for_attempt(pool, st2)
        seen.add(idx)
    check("вне ротации обходится, работает только живой", seen == {2}, seen)
    for p in pool:
        for _ in range(3):
            st2.record_result(p["raw"], ok=False)
    pr, idx, warn = cp.pick_for_attempt(pool, st2)
    check("все вне ротации → напрямую (-2) и предупреждение",
          pr is None and idx == -2 and "забанены" in warn, (pr, idx, warn))
    check("пустой пул → напрямую (-1) без предупреждения",
          cp.pick_for_attempt([], st2) == (None, -1, None))
    st2.unban_all()
    check("unban_all (кнопка «Перепроверить») возвращает всех в ротацию",
          not any(st2.is_banned(p["raw"]) for p in pool))
    check("peek не двигает индекс",
          st2.peek(pool)[1] == cp.ProxyState(st2.path).data.get("index"))

    # ── 6. статусы проверок и payload панели ──────────────────────────────
    st3 = cp.ProxyState(TMP / "proxies3.json")
    ok_result = {"ok": True, "ip": "5.5.5.5", "ms": 120, "error": None, "checked_at": 111.0,
                 "raw": pool[0]["raw"], "masked": cp.mask(pool[0]["raw"])}
    st3.save_status(pool[0]["raw"], ok_result)
    st3.record_result(pool[1]["raw"], ok=False)
    payload = cp.describe(pool, st3)
    check("payload: count/mode прокси", payload["count"] == 3 and payload["mode"] == "proxy")
    check("payload: note пуст в режиме прокси", payload["note"] is None)
    check("статус ok для проверенного", payload["proxies"][0]["status"] == "ok")
    check("фейл попытки — это НЕ провал ip-чека: статус остаётся unchecked",
          payload["proxies"][1]["status"] == "unchecked")
    check("статус unchecked по умолчанию", payload["proxies"][2]["status"] == "unchecked")
    check("ip/ms попали в payload",
          payload["proxies"][0]["ip"] == "5.5.5.5" and payload["proxies"][0]["ms"] == 120)
    check("фейлы видны в payload", payload["proxies"][1]["fails"] == 1)
    check("паспорт состояния: rotate_index/fail_threshold",
          "rotate_index" in payload and "last_check" in payload
          and isinstance(payload["fail_threshold"], int), sorted(payload))

    empty = cp.describe([], cp.ProxyState(TMP / "proxies4.json"))
    check("пустой пул: mode=direct и честная пометка", empty["mode"] == "direct"
          and "429" in (empty["note"] or ""), empty["note"])

    # ── 7. force-direct («без прокси») ────────────────────────────────────
    cp.set_force_direct(True)
    try:
        check("force_direct: прокси не грузятся",
              cp.load_proxies(cfg=["http://1.2.3.4:8000"], path=TMP / "nope.txt") == ([], []))
        check("force_direct: direct_mode True", cp.direct_mode() is True)
        forced = cp.describe([], cp.ProxyState(TMP / "proxies5.json"))
        check("force_direct: forced_direct в payload", forced["forced_direct"] is True
              and forced["mode"] == "direct")
    finally:
        cp.set_force_direct(False)
    check("force_direct снят", cp.direct_mode() is False)

    # ── 8. загрузка из конфига + файла ────────────────────────────────────
    pf = TMP / "proxies.txt"
    pf.write_text("# список\nhttp://u:p@20.0.0.2:8000\nhttp://u:p@20.0.0.1:8000\n", encoding="utf-8")
    loaded, lbad = cp.load_proxies(cfg=["http://u:p@20.0.0.1:8000"], path=pf)
    check("конфиг + файл склеиваются без дублей", len(loaded) == 2 and not lbad, (len(loaded), lbad))
    check("порядок: сначала конфиг, потом файл",
          loaded[0]["host"] == "20.0.0.1" and loaded[1]["host"] == "20.0.0.2")
    check("комментарии в файле не считаются прокси", all(p["scheme"] == "http" for p in loaded))
    missing, _ = cp.load_proxies(cfg=[], path=TMP / "нет-такого.txt")
    check("отсутствующий файл не роняет загрузку", missing == [])

    # ── 9. выпавшие прокси не теряют накопленные фейлы ────────────────────
    st4 = cp.ProxyState(TMP / "proxies6.json")
    cp.describe(pool, st4)
    for _ in range(3):
        st4.record_result(pool[2]["raw"], ok=False)
    shrunk = cp.describe(pool[:2], st4)
    retired = {r["masked"]: r for r in shrunk["retired"]}
    check("убранный из файла прокси виден в retired с фейлами",
          cp.mask(pool[2]["raw"]) in retired and retired[cp.mask(pool[2]["raw"])]["fails"] >= 3,
          shrunk["retired"])
    check("retired помечен gone", retired[cp.mask(pool[2]["raw"])]["gone"] is True)

    # ── 10. атомарность записи состояния ──────────────────────────────────
    check("после flush нет .tmp-мусора", not state_path.with_name("proxies.json.tmp").exists())
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    check("состояние — валидный JSON с ключами",
          {"index", "status", "health"} <= set(saved), sorted(saved))
    check("битый state читается как пустой",
          (TMP / "broken.json").write_text("{oops", encoding="utf-8") is not None
          and cp.ProxyState(TMP / "broken.json").data.get("index") == 0)

    # ── 11. браузер: прокси попытки доходит до Chrome ─────────────────────
    # Chrome получает прокси ТОЛЬКО при старте (--proxy-server) — проверяем, что
    # модуль капчи принимает proxy попытки и отдаёт его в аргумент запуска,
    # а маркер профиля помнит, с чем поднят живой инстанс (по нему он ротируется).
    import conol_captcha as cc  # noqa: E402

    orig_profile = cc.PROFILE_DIR
    cc.PROFILE_DIR = str(TMP / "profile")
    try:
        (TMP / "profile").mkdir(exist_ok=True)
        # Прокси с авторизацией доходит до Chrome через локальный релей: флаг —
        # это 127.0.0.1:<port>, а сам прокси остаётся в _desired_proxy.
        cc.set_proxy(cp.parse_proxy("http://u:p@1.2.3.4:8000"))
        check("set_proxy/current_proxy: прокси попытки принят",
              (cc.current_proxy() or {}).get("host") == "1.2.3.4", cc.current_proxy())
        check("_proxy_arg отдаёт локальный релей для прокси с авторизацией",
              (cc._proxy_arg() or "").startswith("http://127.0.0.1:")
              and "u:p@" not in (cc._proxy_arg() or ""), cc._proxy_arg())
        relay_flag = cc._proxy_arg()
        check("маркер профиля живёт в профиле Chrome",
              cc._proxy_marker() == TMP / "profile" / ".eni_proxy", cc._proxy_marker())
        check("нет маркера -> прокси живого Chrome неизвестен", cc._live_proxy() is None)
        cc._proxy_marker().write_text(relay_flag, encoding="utf-8")
        check("маркер читается (Chrome поднят с этим прокси)",
              cc._live_proxy() == relay_flag, cc._live_proxy())
        cc.set_proxy(None)
        check("set_proxy(None) -> напрямую (без флага)", cc._proxy_arg() is None)
        cap_src = (ROOT / "conol_captcha.py").read_text(encoding="utf-8")
        check("Chrome реально получает флаг при старте", 'cmd.insert(1, "--proxy-server=%s"' in cap_src)
        check("смена прокси = перезапуск (сравнение маркера в _launch_chrome)",
              "live_proxy != want_proxy" in cap_src and "_stop_foreign_chrome" in cap_src)
        check("после перезапуска хендлы playwright сброшены",
              "_reset_handles()" in cap_src)
    finally:
        cc.PROFILE_DIR = orig_profile
        cc.set_proxy(None)

    # ── 12. воркер: ротация по аккаунтам, --no-proxy, job-файл ────────────
    # Настоящий afk_worker.run, но register_one/Chrome/пул-слот/пути — заглушки:
    # ни одного сетевого вызова и ни одной живой регистрации.
    import panel.afk_worker as aw  # noqa: E402  (папка panel в sys.path)
    import conol_register as cr    # noqa: E402

    wdir = TMP / "worker"
    wdir.mkdir(exist_ok=True)

    def _wire_worker():
        aw.JOB_FILE = wdir / "afk_job.json"
        aw.AFK_LOG = wdir / "afk.log"
        aw.STOP_FLAG = wdir / "afk_stop.flag"
        cr.PID_FILE = wdir / "conol_register_run.pid"
        cr.RESULTS_FILE = wdir / "results.jsonl"
        cp.STATE_FILE = wdir / "proxies.json"
        aw.conol_captcha.warmup = lambda: None          # Chrome не поднимаем
        aw.conol_captcha.set_proxy = lambda p: calls_browser.append(p)

    calls_browser, calls_http = [], []

    def _stub_register(suffix, provider=None, proxy=None):
        calls_http.append(proxy)
        return {"name": "Conol%s" % suffix, "email": "x@y.z", "ok": False,
                "proxy": (proxy or {}).get("raw"), "mode": "proxy" if proxy else "direct",
                "error": "HTTP 429 RATE_LIMITED (stub)"}

    orig = {
        "aw_job": aw.JOB_FILE, "aw_log": aw.AFK_LOG, "aw_stop": aw.STOP_FLAG,
        "cr_pid": cr.PID_FILE, "cr_results": cr.RESULTS_FILE, "cp_state": cp.STATE_FILE,
        "warmup": aw.conol_captcha.warmup, "set_proxy": aw.conol_captcha.set_proxy,
        "register_one": cr.register_one, "providers": list(cr.conol_captcha.PROVIDERS),
    }
    try:
        _wire_worker()
        cr.register_one = _stub_register
        fake_pool = ["http://u:p@10.0.1.1:8000", "http://u:p@10.0.1.2:8000"]
        os.environ["CONOL_PROXIES"] = ",".join(fake_pool)
        cp.set_force_direct(False)

        aw.run(1, provider="catchall", free_captcha=True, job_id="t-proxy")
        job = aw.read_job()
        check("worker: job знает режим proxy и размер пула",
              job.get("proxy_mode") == "proxy" and job.get("proxies") == 2, job)
        check("worker: прокси попытки передан в реггер", calls_http and calls_http[0] is not None,
              calls_http)
        check("worker: браузер получил тот же прокси, что HTTP (один exit-IP)",
              calls_browser and calls_http
              and (calls_browser[0] or {}).get("raw") == (calls_http[0] or {}).get("raw"),
              (calls_browser, calls_http))
        check("worker: 429 записан прокси как фейл (накопление)",
              cp.ProxyState(wdir / "proxies.json").health_of(calls_http[0]["raw"]).get("fails") == 1,
              cp.ProxyState(wdir / "proxies.json").data.get("health"))

        # второй аккаунт берёт СЛЕДУЮЩИЙ прокси (ротация, а не тот же самый)
        calls_http.clear()
        aw.run(1, provider="catchall", free_captcha=True, job_id="t-rotate")
        check("worker: ротация — второй аккаунт идёт через другой прокси",
              calls_http and calls_http[0]["raw"] == fake_pool[1], calls_http)

        # чекбокс «без прокси»: пул игнорируется, режим честно помечен
        calls_http.clear()
        aw.run(1, provider="catchall", free_captcha=True, job_id="t-direct", no_proxy=True)
        job = aw.read_job()
        check("worker --no-proxy: режим direct в job-файле",
              job.get("proxy_mode") == "direct" and job.get("no_proxy") is True, job)
        check("worker --no-proxy: попытка идёт без прокси и с пометкой",
              calls_http == [None] and "429" in (job.get("proxy_note") or ""), calls_http)
        cp.set_force_direct(False)
    finally:
        cr.register_one = orig["register_one"]
        aw.JOB_FILE, aw.AFK_LOG, aw.STOP_FLAG = orig["aw_job"], orig["aw_log"], orig["aw_stop"]
        cr.PID_FILE, cr.RESULTS_FILE = orig["cr_pid"], orig["cr_results"]
        cp.STATE_FILE = orig["cp_state"]
        aw.conol_captcha.warmup = orig["warmup"]
        aw.conol_captcha.set_proxy = orig["set_proxy"]
        cr.conol_captcha.PROVIDERS = orig["providers"]
        os.environ.pop("CONOL_PROXIES", None)
        cp.set_force_direct(False)
        cr.release_pid_slot()
finally:
    shutil.rmtree(TMP, ignore_errors=True)
    cp.set_force_direct(False)
    _restore_direct_state()

print()
print("%d/%d проверок прошло" % (checks - len(fails), checks) if not fails
      else "ПРОВАЛЫ: %s" % fails)
sys.exit(1 if fails else 0)