# -*- coding: utf-8 -*-
"""Учёт расхода — канон USAGE-SPEC.md: data/usage.jsonl, append-only, одна строка = событие.

Контракт (одинаковый во всех панелях; модуль копируется в каждый реггер, stdlib):
  record(kind, ...)                        — записать событие (дедуп по event_key)
  record_many(events)                      — пакетная запись
  snapshot(credits=..., account=..., meta=...) — снапшот остатка (kind=balance_snapshot)
  ingest_log(source_id, path, parse)       — инкрементальный импорт append-лога (курсор)
  payload(range, bucket, notes, extras)    — роллап для GET /api/usage
  raw_tail(n)                              — хвост журнала для GET /api/usage/raw

Источники conol (что даёт какое поле):
  * регистрации — data/conol_register_results.jsonl (ts, ok, email, elapsed, error);
  * капча — счётчик captcha_solves того же results-лога (chrome_cdp, $0);
  * остаток — дельты GET /api/billing/balance: пул (data/conol_accounts_pool.jsonl,
    пишут панельная перепроверка и conol_refresh) → kind=balance_snapshot;
  * LLM-запросы — журнал шлюза :9999 (SQLite data/conol_keystore.db, таблица usage):
    модель и число запросов есть, токенов/кредитов шлюз не пишет → tokens = null.

Правила (USAGE-SPEC §5):
  * неизвестное поле = None → в UI «н/д»; ничего не дооцениваем молча;
  * «расход» (tokens_*/credits/cost_usd) не смешивается с «остатком»:
    balance_snapshot в суммы не входит, у него свои счётчик и последнее значение;
  * период считается от ts события, бакеты hour/day/month — локальное время сервера;
  * журнал только append, ротация по размеру (архив usage-YYYYMM.jsonl после 20 МБ).
"""
import json
import math
import os
import threading
import time

SERVICE = "conol"               # каждый реггер переопределяет под своим именем
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

ROTATE_BYTES = 20 * 1024 * 1024      # 20 МБ → архив usage-YYYYMM.jsonl
KINDS = ("llm_request", "registration", "captcha_solve", "balance_snapshot", "other")
SUM_FIELDS = ("tokens_in", "tokens_out", "credits", "cost_usd")

_lock = threading.RLock()
_key_cache = {"keys": None, "src_size": -1}


# ── пути ──────────────────────────────────────────────────────────────────
def ledger_path():
    return os.path.join(DATA_DIR, "usage.jsonl")


def keys_path():
    return os.path.join(DATA_DIR, "usage_keys.json")


def cursors_path():
    return os.path.join(DATA_DIR, "usage_cursors.json")


def daily_path():
    return os.path.join(DATA_DIR, "usage_daily.json")


def archive_paths():
    out = []
    try:
        for name in sorted(os.listdir(DATA_DIR)):
            if name.startswith("usage-") and name.endswith(".jsonl") and name != "usage.jsonl":
                out.append(os.path.join(DATA_DIR, name))
    except OSError:
        pass
    return out


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (ValueError, OSError):
        return default


def _write_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
    os.replace(tmp, path)


# ── запись ────────────────────────────────────────────────────────────────
def _num(v):
    """Число или None: bool/строки не считаем числами (не выдумываем точность)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v


def _normalize(ev):
    kind = ev.get("kind")
    if kind not in KINDS:
        kind = "other"
    out = {
        "ts": _num(ev.get("ts")),
        "service": ev.get("service") or SERVICE,
        "kind": kind,
        "model": ev.get("model"),
        "tokens_in": _num(ev.get("tokens_in")),
        "tokens_out": _num(ev.get("tokens_out")),
        "credits": _num(ev.get("credits")),
        "cost_usd": _num(ev.get("cost_usd")),
        "account": ev.get("account"),
        "meta": ev.get("meta") if isinstance(ev.get("meta"), dict) else {},
    }
    if out["ts"] is None:
        # floor, не round: округление вверх «уносило» событие в будущее и роллап
        # с границей until=time.time() его терял
        out["ts"] = math.floor(time.time() * 1000) / 1000
    if isinstance(ev.get("ok"), bool):
        out["ok"] = ev["ok"]
    if ev.get("event_key"):
        out["key"] = str(ev["event_key"])
    return out


def _iter_events(paths):
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(ev, dict):
                        yield ev
        except OSError:
            continue


def read_events(include_archives=True, tail=None):
    """Все события журнала (при include_archives — и архивы ротации)."""
    paths = archive_paths() + [ledger_path()] if include_archives else [ledger_path()]
    events = list(_iter_events(paths))
    if tail:
        events = events[-max(1, int(tail)):]
    return events


def keys():
    """Индекс ключей дедупликации. Перестраивается, если журнал менялся не нами."""
    path = ledger_path()
    size = os.path.getsize(path) if os.path.exists(path) else 0
    with _lock:
        if _key_cache["keys"] is not None and _key_cache["src_size"] == size:
            return _key_cache["keys"]
        stored = _read_json(keys_path(), None)
        if (isinstance(stored, dict) and stored.get("src_size") == size
                and isinstance(stored.get("keys"), list)):
            _key_cache.update(keys=set(stored["keys"]), src_size=size)
            return _key_cache["keys"]
        found = {ev["key"] for ev in _iter_events([path]) if ev.get("key")}
        _key_cache.update(keys=found, src_size=size)
        return found


def _rotate_locked(known_keys):
    """Журнал > 20 МБ → архив usage-YYYYMM.jsonl; ключи дедупа сохраняются."""
    path = ledger_path()
    if not os.path.exists(path) or os.path.getsize(path) < ROTATE_BYTES:
        return
    archive = os.path.join(DATA_DIR, "usage-%s.jsonl" % time.strftime("%Y%m"))
    try:
        with open(path, "rb") as src:
            data = src.read()
        with open(archive, "ab") as dst:
            dst.write(data if data.endswith(b"\n") else data + b"\n")
        with open(path, "wb"):
            pass
    except OSError:
        return
    _write_json_atomic(keys_path(), {"src_size": 0, "keys": sorted(known_keys)})
    _key_cache.update(keys=known_keys, src_size=0)


def record_many(events, service=None):
    """Пакетная запись. События с event_key, уже лежащим в журнале, пропускаются.

    Возвращает число реально добавленных строк.
    """
    if not events:
        return 0
    norm = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if service:
            ev = dict(ev, service=service)
        norm.append(_normalize(ev))
    if not norm:
        return 0
    with _lock:
        known = keys()
        fresh = [ev for ev in norm if not ev.get("key") or ev["key"] not in known]
        if not fresh:
            return 0
        _rotate_locked(known)
        path = ledger_path()
        os.makedirs(DATA_DIR, exist_ok=True)
        try:
            with open(path, "a", encoding="utf-8") as f:
                for ev in fresh:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                f.flush()
        except OSError:
            return 0
        for ev in fresh:
            if ev.get("key"):
                known.add(ev["key"])
        try:
            size = os.path.getsize(path)
        except OSError:
            size = -1
        _write_json_atomic(keys_path(), {"src_size": size, "keys": sorted(known)})
        _key_cache.update(keys=known, src_size=size)
    return len(fresh)


def record(kind, ts=None, model=None, tokens_in=None, tokens_out=None, credits=None,
           cost_usd=None, account=None, ok=None, meta=None, event_key=None, service=None):
    """Одно событие в журнал. Возвращает True, если строка добавлена."""
    ev = {"kind": kind, "ts": ts, "model": model, "tokens_in": tokens_in,
          "tokens_out": tokens_out, "credits": credits, "cost_usd": cost_usd,
          "account": account, "ok": ok, "meta": meta, "event_key": event_key}
    return record_many([ev], service=service) == 1


def snapshot(credits=None, account=None, meta=None, model=None, ts=None, event_key=None):
    """Снапшот остатка (kind=balance_snapshot): credits = остаток, не расход."""
    return record("balance_snapshot", ts=ts, credits=credits, account=account,
                  model=model, meta=meta, event_key=event_key)


# ── импорт логов по курсору ───────────────────────────────────────────────
def cursors():
    data = _read_json(cursors_path(), {})
    return data if isinstance(data, dict) else {}


def ingest_log(source_id, path, parse, start_line=0):
    """Импорт append-лога: читает только новые строки (курсор = номер строки).

    parse(line, line_no) → событие-словарь или None. Курсор двигается только
    после успешной записи, так что повторный вызов не задваивает события.
    """
    if not path or not os.path.exists(path):
        return 0
    with _lock:
        cur = cursors()
        pos = int(cur.get(source_id) or 0)
        if start_line and pos < start_line:
            pos = start_line
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return 0
        if len(lines) < pos:          # лог перезаписан/ротирован — читаем с начала
            pos = start_line
        new = lines[pos:]
        events = []
        for i, line in enumerate(new, start=pos):
            try:
                ev = parse(line, i)
            except Exception:         # noqa: BLE001 — парсер не должен ронять панель
                ev = None
            if ev:
                ev.setdefault("meta", {})
                ev.setdefault("event_key", "%s:%d" % (source_id, i))
                events.append(ev)
        added = record_many(events)
        cur[source_id] = len(lines)
        try:
            _write_json_atomic(cursors_path(), cur)
        except OSError:
            pass
        return added


# ── роллап ────────────────────────────────────────────────────────────────
RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}
BUCKETS = ("hour", "day", "month")
_FMT = {"hour": "%Y-%m-%dT%H:00", "day": "%Y-%m-%d", "month": "%Y-%m"}


def parse_range(range_="24h"):
    """→ (range, since|None, until). Неизвестный range → 24h."""
    range_ = (range_ or "24h").strip().lower()
    if range_ not in RANGES:
        range_ = "24h"
    until = time.time()
    span = RANGES[range_]
    return range_, (None if span is None else until - span), until


def resolve_bucket(range_, bucket=None):
    if bucket in BUCKETS:
        return bucket
    return "hour" if range_ in ("1h", "24h") else "day"


def bucket_key(ts, bucket):
    return time.strftime(_FMT[bucket], time.localtime(ts))


def _align(ts, bucket):
    lt = time.localtime(ts)
    if bucket == "hour":
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, 0, 0, 0, 0, -1))
    if bucket == "day":
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
    return time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))


def bucket_sequence(start_ts, end_ts, bucket, cap=400):
    """Ключи бакетов от start_ts до end_ts включительно (пустые — тоже, для графика)."""
    out = []
    if bucket in ("hour", "day"):
        step = 3600 if bucket == "hour" else 86400
        t = _align(start_ts, bucket)
        while t <= end_ts and len(out) < cap:
            out.append(bucket_key(t, bucket))
            t += step
    else:
        lt = time.localtime(start_ts)
        y, m = lt.tm_year, lt.tm_mon
        while len(out) < cap:
            t = time.mktime((y, m, 1, 0, 0, 0, 0, 0, -1))
            if t > end_ts:
                break
            out.append(bucket_key(t, bucket))
            m += 1
            if m > 12:
                y, m = y + 1, 1
    return out


def _empty(key):
    b = {"bucket": key, "events": 0, "llm_requests": 0, "tokens_in": None, "tokens_out": None,
         "credits": None, "cost_usd": None, "registrations": 0, "registrations_ok": 0,
         "captcha_solves": 0, "captcha_ok": 0, "balance_snapshots": 0, "other_events": 0,
         "balance_last": None, "balance_last_ts": None}
    return b


def _add(b, ev):
    b["events"] += 1
    kind = ev.get("kind")
    if kind == "llm_request":
        b["llm_requests"] += 1
    elif kind == "registration":
        b["registrations"] += 1
        if ev.get("ok"):
            b["registrations_ok"] += 1
    elif kind == "captcha_solve":
        b["captcha_solves"] += 1
        if ev.get("ok") is not False:
            b["captcha_ok"] += 1
    elif kind == "balance_snapshot":
        # остаток, а не расход: в суммы не входит
        b["balance_snapshots"] += 1
        if _num(ev.get("credits")) is not None:
            b["balance_last"] = ev["credits"]
            b["balance_last_ts"] = ev.get("ts")
        return
    elif kind == "other":
        b["other_events"] += 1
    for f in SUM_FIELDS:
        v = _num(ev.get(f))
        if v is not None:
            b[f] = (b[f] or 0) + v


def _fill_empty(series, start_ts, end_ts, bucket, seen_keys):
    """Пустые бакеты внутри периода — нулями (честное «в этот день ничего не было»)."""
    if start_ts is None or end_ts is None:
        return series
    have = {b["bucket"] for b in series}
    fill = [k for k in bucket_sequence(start_ts, end_ts, bucket) if k not in have]
    if not fill:
        return series
    merged = {b["bucket"]: b for b in series}
    for k in fill:
        merged[k] = _empty(k)
    return [merged[k] for k in sorted(merged)]


def _totals(series):
    t = _empty(None)
    t.pop("bucket", None)
    for b in series:
        for f in ("events", "llm_requests", "registrations", "registrations_ok",
                  "captcha_solves", "captcha_ok", "balance_snapshots", "other_events"):
            t[f] += b[f]
        for f in SUM_FIELDS:
            if b[f] is not None:
                t[f] = (t[f] or 0) + b[f]
        if b["balance_last_ts"] and (t["balance_last_ts"] or 0) <= b["balance_last_ts"]:
            t["balance_last"] = b["balance_last"]
            t["balance_last_ts"] = b["balance_last_ts"]
    return t


def rollup(range_="24h", bucket=None, since=None, until=None, events=None):
    """Роллап событий: series (по бакетам) + totals + by_model/by_account/by_status."""
    range_, auto_since, auto_until = parse_range(range_)
    if since is None:
        since = auto_since
    if until is None:
        until = auto_until
    bucket = resolve_bucket(range_, bucket)
    if events is None:
        events = read_events(include_archives=True)
    evs = [e for e in events
           if isinstance(e, dict) and isinstance(e.get("ts"), (int, float))
           and e["ts"] <= until + 1e-6 and (since is None or e["ts"] >= since)]
    evs.sort(key=lambda e: e["ts"])
    buckets = {}
    by_model, by_account, by_status = {}, {}, {}
    # «н/д»: сколько LLM/капча-событий пришло без поля (мост токенов не пишет).
    # Считаем по событиям, а не по бакетам: не теряется на пустых бакетах.
    missing = {f: 0 for f in SUM_FIELDS}
    for ev in evs:
        key = bucket_key(ev["ts"], bucket)
        b = buckets.setdefault(key, _empty(key))
        _add(b, ev)
        kind = ev.get("kind")
        if kind in ("llm_request", "captcha_solve"):
            for f in SUM_FIELDS:
                if _num(ev.get(f)) is None:
                    missing[f] += 1
        model = ev.get("model")
        if model:
            m = by_model.setdefault(model, {"model": model, "events": 0, "llm_requests": 0,
                                            "tokens_in": None, "tokens_out": None,
                                            "credits": None, "cost_usd": None})
            m["events"] += 1
            if kind == "llm_request":
                m["llm_requests"] += 1
            for f in SUM_FIELDS:
                v = _num(ev.get(f))
                if v is not None:
                    m[f] = (m[f] or 0) + v
        acct = ev.get("account")
        if acct:
            a = by_account.setdefault(acct, {"account": acct, "events": 0, "llm_requests": 0,
                                             "registrations": 0, "captcha_solves": 0,
                                             "balance_snapshots": 0, "balance_last": None,
                                             "balance_last_ts": None,
                                             "tokens_in": None, "tokens_out": None,
                                             "credits": None})
            a["events"] += 1
            if kind == "llm_request":
                a["llm_requests"] += 1
            elif kind == "registration":
                a["registrations"] += 1
            elif kind == "captcha_solve":
                a["captcha_solves"] += 1
            elif kind == "balance_snapshot":
                # остаток аккаунта, а не расход: в credits не суммируем
                a["balance_snapshots"] += 1
                v = _num(ev.get("credits"))
                if v is not None and (a["balance_last_ts"] or 0) <= ev["ts"]:
                    a["balance_last"] = v
                    a["balance_last_ts"] = ev["ts"]
            if kind != "balance_snapshot":
                for f in ("tokens_in", "tokens_out", "credits"):
                    v = _num(ev.get(f))
                    if v is not None:
                        a[f] = (a[f] or 0) + v
        if kind == "registration":
            st = (ev.get("meta") or {}).get("status") or ("ok" if ev.get("ok") else "unknown")
            s = by_status.setdefault(st, {"status": st, "events": 0})
            s["events"] += 1

    series = [buckets[k] for k in sorted(buckets)]
    if evs:
        first = since if since is not None else _align(evs[0]["ts"], bucket)
        series = _fill_empty(series, first, until, bucket, set(buckets))
    elif since is not None:
        series = _fill_empty(series, since, until, bucket, set())
    totals = _totals(series)
    totals.update({"events": len(evs), "first_ts": evs[0]["ts"] if evs else None,
                   "last_ts": evs[-1]["ts"] if evs else None})
    totals["unknown"] = missing
    by_model_list = sorted(by_model.values(), key=lambda x: (-x["events"], str(x["model"])))
    by_account_list = sorted(by_account.values(), key=lambda x: (-x["events"], str(x["account"])))
    return {
        "range": range_, "bucket": bucket, "since": since, "until": until,
        "series": series, "totals": totals,
        "by_model": by_model_list, "by_account": by_account_list,
        "by_status": sorted(by_status.values(), key=lambda x: (-x["events"], str(x["status"]))),
        "accounts_total": len(by_account),
    }


def _daily_cache_events():
    """data/usage_daily.json — кэш дневного роллапа (USAGE-SPEC §1), обновляется по mtime."""
    path = ledger_path()
    try:
        stamp = [os.path.getmtime(path), os.path.getsize(path)]
    except OSError:
        stamp = [0, 0]
    for extra in archive_paths():
        try:
            stamp[0] = max(stamp[0], os.path.getmtime(extra))
            stamp[1] += os.path.getsize(extra)
        except OSError:
            pass
    cached = _read_json(daily_path(), None)
    if isinstance(cached, dict) and cached.get("stamp") == stamp:
        return None
    return stamp


def refresh_daily_cache():
    """Пересобрать кэш-роллап по дням (вызывается из payload, дёшево)."""
    stamp = _daily_cache_events()
    if stamp is None:
        return
    day = rollup("all", "day")
    try:
        _write_json_atomic(daily_path(), {
            "stamp": stamp,
            "generated_at": round(time.time(), 1),
            "service": SERVICE,
            "days": [{k: b[k] for k in ("bucket", "events", "llm_requests", "registrations",
                                        "captcha_solves", "tokens_in", "tokens_out",
                                        "credits", "cost_usd", "balance_last")}
                     for b in day["series"]],
            "by_model": day["by_model"],
        })
    except OSError:
        pass


def payload(range_="24h", bucket=None, notes=None, extras=None, ingest=None):
    """Полный ответ GET /api/usage (USAGE-SPEC §2). ingest — колбэк дозаписи событий."""
    if callable(ingest):
        try:
            ingest()
        except Exception:      # noqa: BLE001 — учёт не должен ронять эндпоинт
            pass
    data = rollup(range_, bucket)
    try:
        refresh_daily_cache()
    except Exception:          # noqa: BLE001
        pass
    data["service"] = SERVICE
    data["notes"] = list(notes or [])
    data["extras"] = dict(extras or {})
    data["ledger"] = {
        "path": os.path.relpath(ledger_path(), os.path.dirname(DATA_DIR)) if os.path.isabs(DATA_DIR) else ledger_path(),
        "events_total": None, "archives": [os.path.basename(p) for p in archive_paths()],
    }
    try:
        data["ledger"]["events_total"] = sum(1 for _ in _iter_events(archive_paths() + [ledger_path()]))
        data["ledger"]["size"] = os.path.getsize(ledger_path())
    except OSError:
        pass
    return data


def raw_tail(n=500):
    """Хвост журнала для GET /api/usage/raw?tail=N (отладка)."""
    n = max(1, min(int(n or 500), 5000))
    events = read_events(include_archives=True, tail=n)
    return {"count": len(events), "events": events}


def selftest():
    """Офлайн-проверка модуля (используется в tests/selfcheck.py): exit 0 = pass."""
    import tempfile
    global DATA_DIR
    saved = DATA_DIR
    with tempfile.TemporaryDirectory() as tmp:
        DATA_DIR = tmp
        _key_cache.update(keys=None, src_size=-1)
        now = time.time()
        assert record("registration", ts=now - 60, account="a@x", ok=True,
                      meta={"status": "complete"}, event_key="t:1")
        assert not record("registration", ts=now - 60, account="a@x", ok=True,
                          meta={"status": "complete"}, event_key="t:1"), "дедуп не сработал"
        record("llm_request", ts=now - 120, model="m-1", tokens_in=10, tokens_out=5,
               event_key="t:2")
        record("captcha_solve", ts=now - 120, event_key="t:3")
        snapshot(credits=100.0, account="a@x", event_key="t:4")
        p = payload("24h", "hour")
        assert p["totals"]["registrations"] == 1, p["totals"]
        assert p["totals"]["registrations_ok"] == 1
        assert p["totals"]["llm_requests"] == 1
        assert p["totals"]["tokens_in"] == 10
        assert p["totals"]["balance_snapshots"] == 1
        assert p["totals"]["credits"] is None, "снапшот не должен попадать в расход"
        assert p["totals"]["balance_last"] == 100.0
        assert p["by_model"] and p["by_model"][0]["model"] == "m-1"
        assert p["by_status"] and p["by_status"][0]["status"] == "complete"
        assert len(raw_tail(10)["events"]) == 4
        day = rollup("all", "day")
        assert len(day["series"]) >= 1
        assert daily_path().endswith("usage_daily.json")
        refresh_daily_cache()
        assert os.path.exists(daily_path())
        # импорт лога по курсору: второй прогон не задваивает
        log = os.path.join(tmp, "src.log")
        with open(log, "w", encoding="utf-8") as f:
            f.write("x 1\ny 2\n")
        parse = lambda line, i: {"kind": "other", "ts": now, "meta": {"line": line.strip()}}  # noqa: E731
        assert ingest_log("t-src", log, parse) == 2
        assert ingest_log("t-src", log, parse) == 0
        with open(log, "a", encoding="utf-8") as f:
            f.write("z 3\n")
        assert ingest_log("t-src", log, parse) == 1
    DATA_DIR = saved
    _key_cache.update(keys=None, src_size=-1)
    return True


if __name__ == "__main__":
    import sys
    print("usage.selftest:", "OK" if selftest() else "FAIL")
    sys.exit(0)