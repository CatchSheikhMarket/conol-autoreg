#!/usr/bin/env python3
"""afk_worker.py — AFK-регистрация conol.ai для панели (фоновый воркер).

Крутит conol_register.register_one() в цикле: адрес берётся у провайдера почты
(по умолчанию catchall, catch-all), капча — только бесплатная chrome_cdp.
Каждый аккаунт сразу пишется в пул (append_to_pool внутри register_one), прогресс —
атомарно в data/afk_job.json, лог — в data/afk.log (stdout воркера).

Запуск вручную:
    python -X utf8 panel/afk_worker.py --count 42 --provider catchall

Прокси: пул из config.json → proxies / data/proxies.txt, ротация по аккаунтам
(и браузер, и HTTP — один exit-IP); `--no-proxy` (чекбокс «без прокси» в панели)
работает напрямую и честно помечает это в job-файле и логе.

Панель (panel/server.py) импортирует этот модуль ради JOB_FILE/write_job/read_job,
поэтому файл обязан быть import-safe: ничего не стартует на уровне модуля.

Гварды (унаследованы от реггера, ломать нельзя):
  * acquire_pid_slot() — на пул может писать только ОДИН процесс; если слот занят
    живым чужим pid'ом (CLI-реггер, conol_refresh, другой воркер), воркер не стартует;
  * заявка периодически обновляется (mtime), иначе возрастной гвард сочтёт её брошенной;
  * circuit breaker: 10 подряд фейлов — стоп, а не «жгём час впустую»;
  * стоп-кнопка: data/afk_stop.flag + SIGTERM; воркер доигрывает текущий аккаунт
    (account уже создан на conol — бросать его на середине незачем) и выходит.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import sys
import time
from pathlib import Path

PANEL_DIR = Path(__file__).resolve().parent
BASE_DIR = PANEL_DIR.parent
sys.path.insert(0, str(BASE_DIR))  # conol_*.py лежат в корне проекта

import conol_captcha   # noqa: E402
import conol_proxy     # noqa: E402
import conol_register  # noqa: E402

DATA_DIR = conol_register.DATA_DIR
JOB_FILE = DATA_DIR / "afk_job.json"
AFK_LOG = DATA_DIR / "afk.log"
STOP_FLAG = DATA_DIR / "afk_stop.flag"

DEFAULT_COUNT = 42          # канон панели: 42 аккаунта в одном AFK-прогоне
MAX_COUNT = 200             # предел самого реггера (conol_register.main)
PAUSE_SEC = 30              # пауза между аккаунтами — как в conol_register.main()
CIRCUIT_BREAKER = conol_register.MAX_CONSECUTIVE_FAILURES

_stop_requested = False


# ─── job-файл (единственный источник прогресса для панели) ───────────────────

def read_job() -> dict:
    try:
        return json.loads(JOB_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_job(patch: dict) -> dict:
    """Атомарно обновить data/afk_job.json (панель читает его параллельно)."""
    job = read_job()
    job.update(patch)
    tmp = JOB_FILE.with_name(JOB_FILE.name + ".tmp")
    tmp.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, JOB_FILE)
    return job


def stop_requested() -> bool:
    return _stop_requested or STOP_FLAG.exists()


def request_stop() -> None:
    """Выставить стоп-флаг (вызывает панель перед SIGTERM воркеру)."""
    STOP_FLAG.write_text(str(time.time()), encoding="utf-8")


# ─── сам прогон ──────────────────────────────────────────────────────────────

def _on_signal(signum, _frame):
    # fatal-signal handler: только флаг, никаких исключений в середине транзакции
    global _stop_requested
    _stop_requested = True
    print("[afk] signal %s — останавливаюсь после текущего аккаунта" % signum, flush=True)


def _refresh_slot() -> None:
    """Освежить mtime своей заявки — иначе возрастной гвард сочтёт её брошенной.

    Ровно та же логика, что в conol_register.main(): трогаем файл только пока он
    наш, чтобы не затирать заявку нового владельца.
    """
    try:
        pid_file = conol_register.PID_FILE
        if (pid_file.exists()
                and pid_file.read_text(encoding="utf-8").split("\n", 1)[0].strip() == str(os.getpid())):
            os.utime(pid_file, None)
    except OSError as exc:
        print("[afk] не смог обновить slot-заявку: %s" % exc, flush=True)


def run(count: int, provider: str = "catchall", free_captcha: bool = True,
        job_id: str | None = None, no_proxy: bool = False) -> int:
    started = time.time()
    job_id = job_id or ("afk-%d" % int(started))
    if free_captcha:
        conol_captcha.PROVIDERS = ["chrome_cdp"]
    if no_proxy:
        conol_proxy.set_force_direct(True)
    STOP_FLAG.unlink(missing_ok=True)

    # Прокси-пул: ротация по аккаунтам (браузер + HTTP одним exit-IP). Режим пишем
    # в job-файл сразу: панель обязана честно показывать «идём напрямую».
    proxy_state = conol_proxy.ProxyState()
    proxies, bad_lines = conol_proxy.load_proxies()
    mode = "direct" if (not proxies or conol_proxy.direct_mode()) else "proxy"
    if bad_lines:
        print("[afk] отброшены строки прокси: %d (пример: %s)"
              % (len(bad_lines), bad_lines[0][:90]), flush=True)
    print("[afk] сеть: %s" % ("%d прокси, ротация по аккаунтам" % len(proxies)
                              if mode == "proxy" else "НАПРЯМУЮ (без прокси) — "
                              "с домашнего IP conol отдаёт 429 RATE_LIMITED"), flush=True)

    write_job({
        "job_id": job_id, "status": "starting", "started_at": started,
        "finished_at": None, "done": 0, "total": count, "ok": 0, "failed": 0,
        "credits": 0, "last_error": None, "provider": provider,
        "captcha": ",".join(conol_captcha.PROVIDERS), "pid": os.getpid(),
        "proxy_mode": mode, "proxies": len(proxies), "no_proxy": bool(no_proxy),
        "proxy_note": None if mode == "proxy" else conol_proxy.DIRECT_NOTE,
    })

    # Слот берём ДО первой сетевой операции: два писателя на один JSONL пул теряют строки.
    if not conol_register.acquire_pid_slot(owner="panel AFK worker"):
        write_job({"status": "failed", "finished_at": time.time(),
                   "last_error": "пул-слот занят другим реггером/refresh — прогон не начат"})
        print("[afk] slot busy — отказ (exit 3)", flush=True)
        return 3
    atexit.register(conol_register.release_pid_slot)

    if "chrome_cdp" in conol_captcha.PROVIDERS:
        # Прогрев на том же прокси, что отдаст ротация первому аккаунту: иначе первый
        # аккаунт перезапустит Chrome ради смены прокси (это секунды, но лишние).
        first, _idx = proxy_state.peek(proxies)
        conol_captcha.set_proxy(first)
        print("[afk] warmup Chrome CDP (headless=%s, прокси %s)"
              % (conol_captcha.HEADLESS, conol_proxy.mask(first["raw"]) if first else "нет"),
              flush=True)
        conol_captcha.warmup()

    print("[afk] job %s: %d аккаунтов, провайдер=%s, капча=%s"
          % (job_id, count, provider, ",".join(conol_captcha.PROVIDERS)), flush=True)
    write_job({"status": "running"})

    ok = failed = 0
    credits_total = 0.0
    consecutive = 0
    stopped = False
    breaker_tripped = False

    for i in range(count):
        if stop_requested():
            stopped = True
            break
        suffix = int(time.time() * 1000) % 10_000_000_000
        name = "Conol" + str(suffix).zfill(10)[-10:]
        # Прокси на аккаунт: круговая ротация, забаненные (порог подряд-фейлов) обходятся
        proxy, idx, proxy_warning = conol_proxy.pick_for_attempt(proxies, proxy_state)
        if proxy_warning:
            print("[afk] [!] " + proxy_warning, flush=True)
        write_job({"current": name, "done": i, "ok": ok, "failed": failed,
                   "credits": credits_total, "status": "running",
                   "current_proxy": conol_proxy.mask(proxy["raw"]) if proxy else None,
                   "current_proxy_index": (idx + 1) if proxy else None,
                   "mode": "proxy" if proxy else "direct"})
        if proxy:
            print("[afk] %s → прокси %s (#%d/%d)"
                  % (name, conol_proxy.mask(proxy["raw"]), idx + 1, len(proxies)), flush=True)
        try:
            result = conol_register.register_one(suffix, provider=provider, proxy=proxy)
        except Exception as exc:  # noqa: BLE001 — падение одного аккаунта не должно убивать прогон
            result = {"name": name, "email": None, "ok": False,
                      "proxy": (proxy or {}).get("raw"),
                      "mode": "proxy" if proxy else "direct",
                      "error": "%s: %s" % (type(exc).__name__, exc)}
        result["batch_index"] = i
        if proxy:
            # 429/сетевые ошибки этого прокси = его фейл (накопление → временный бан).
            # У BRD-сессий ключ состояния — шаблон зоны (state_key), не сама сессия.
            proxy_state.record_result(conol_proxy.state_key(proxy),
                                      ok=not conol_proxy.looks_proxy_failed(result.get("error")))
        conol_register.append_result_line(result)
        _refresh_slot()

        if result.get("ok"):
            ok += 1
            consecutive = 0
            credits_total += result.get("credits") or 0
        else:
            failed += 1
            consecutive += 1
        write_job({"done": i + 1, "ok": ok, "failed": failed, "credits": credits_total,
                   "last_email": result.get("email"), "last_error": result.get("error"),
                   "last_result": result})

        if consecutive >= CIRCUIT_BREAKER:
            breaker_tripped = True
            write_job({"last_error": "CIRCUIT BREAKER: %d подряд фейлов — стоп" % consecutive})
            print("[afk] CIRCUIT BREAKER after %d consecutive failures" % consecutive, flush=True)
            break

        if i < count - 1:
            print("[afk] пауза %ds перед следующим аккаунтом" % PAUSE_SEC, flush=True)
            slept = 0.0
            while slept < PAUSE_SEC:
                if stop_requested():
                    stopped = True
                    break
                time.sleep(0.5)
                slept += 0.5
            if stopped:
                break

    # Итог: стоп-кнопка -> stopped; breaker без единого аккаунта -> failed; иначе done.
    # (Флаг, пришедший на последнем аккаунте, прогон не обрывает — все count сделаны.)
    if stopped:
        status = "stopped"
    elif breaker_tripped and ok == 0:
        status = "failed"
    else:
        status = "done"
    write_job({"status": status, "finished_at": time.time(), "done": ok + failed,
               "ok": ok, "failed": failed, "credits": credits_total, "current": None,
               "current_proxy": None, "proxy_mode": mode, "proxies": len(proxies),
               "proxy_usage": proxy_usage(proxy_state, len(proxies))})
    print("[afk] %s: ok=%d failed=%d credits=%.1f за %.0fs"
          % (status, ok, failed, credits_total, time.time() - started), flush=True)
    return 0


def proxy_usage(proxy_state, pool_size: int) -> dict:
    """Сколько фейлов накопил каждый прокси — видно в job-файле и панели."""
    if not pool_size:
        return {}
    health = (proxy_state.data.get("health") or {})
    return {"fails": {conol_proxy.mask(raw): int(st.get("fails", 0))
                      for raw, st in health.items()},
            "banned": [conol_proxy.mask(raw) for raw, st in health.items() if st.get("banned")]}


def main() -> int:
    parser = argparse.ArgumentParser(description="conol.ai AFK-регистрация (панельный воркер)")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--provider", default="catchall",
                        choices=["gmail", "tonline", "catchall"])
    parser.add_argument("--paid-captcha", action="store_true",
                        help="разрешить платную цепочку (по умолчанию только бесплатный chrome_cdp)")
    parser.add_argument("--no-proxy", action="store_true",
                        help="работать напрямую (чекбокс «без прокси» в панели)")
    parser.add_argument("--job-id", default=None)
    args = parser.parse_args()

    count = max(1, min(args.count, MAX_COUNT))
    if count != args.count:
        print("[afk] count %d урезан до %d (предел реггера)" % (args.count, count), flush=True)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    return run(count, provider=args.provider, free_captcha=not args.paid_captcha,
               job_id=args.job_id, no_proxy=args.no_proxy)


if __name__ == "__main__":
    sys.exit(main())