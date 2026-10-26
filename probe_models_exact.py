"""Точная проверка моделей conol: читаем И preview, И logs (финальный текст)."""
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
TOK = None
for line in (ROOT / "data/conol_accounts_pool.jsonl").read_text().strip().splitlines():
    d = json.loads(line)
    if d.get("status") == "live":
        TOK = d["session_token"]
        break
if not TOK:
    sys.exit("нет живого аккаунта")

CK = {"__Secure-better-auth.session_token": TOK}
PROMPT = "Reply with exactly: PROBE_OK"


def probe(model: str, wait: float = 75.0) -> dict:
    out = {"model": model, "downgraded": None, "effective": None,
           "preview": "", "logs": "", "final_status": "", "sec": 0.0,
           "events": 0, "http": 0}
    t0 = time.time()
    try:
        with httpx.Client(cookies=CK, timeout=120) as c:
            r = c.post("https://conol.ai/api/sessions", json={
                "source": {"type": "home"},
                "messages": [{"type": "text", "content": PROMPT}],
                "timezone": "Europe/Kyiv",
                "agentModel": model,
                "agentEffort": "low",
            })
            out["http"] = r.status_code
            if r.status_code != 201:
                out["logs"] = r.text[:100]
                return out
            body = r.json()
            out["downgraded"] = body.get("modelDowngraded")
            out["effective"] = body.get("effectiveModel")
            sid = body["sessionId"]

            with c.stream("GET", f"https://conol.ai/api/sessions/{sid}/messages?logDeltas=1") as s:
                for line in s.iter_lines():
                    if time.time() - t0 > wait:
                        break
                    if not line or not line.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(line[5:].strip())
                    except Exception:
                        continue
                    if ev.get("type") in ("done", "error"):
                        break
                    if ev.get("type") != "history_delta":
                        continue
                    out["events"] += 1
                    for stage in ev.get("stages") or []:
                        if stage.get("status"):
                            out["final_status"] = stage["status"]
                        for pv in (stage.get("preview") or []):
                            if pv.get("role") != "assistant":
                                continue
                            for part in (pv.get("content") or []):
                                if isinstance(part, dict) and part.get("type") == "text":
                                    t = part.get("text") or ""
                                    if t:
                                        out["preview"] = t
                        for lg in (stage.get("logs") or []):
                            if lg.get("role") != "assistant":
                                continue
                            for part in (lg.get("content") or []):
                                if isinstance(part, dict) and part.get("type") == "text":
                                    t = part.get("text") or ""
                                    if t:
                                        out["logs"] = t
    except Exception as e:
        out["logs"] = f"ERR {type(e).__name__}: {e}"
    out["sec"] = round(time.time() - t0, 1)
    return out


if __name__ == "__main__":
    models = sys.argv[1:] or [
        "claude-haiku-5.5", "claude-haiku-4-5",
        "deepseek/deepseek-v4.1-flash", "deepseek/deepseek-v4.1-pro",
        "deepseek-v4.1-flash", "deepseek-v4.1-pro",
    ]
    for m in models:
        r = probe(m)
        text = r["logs"] or r["preview"]
        if "PROBE_OK" in text:
            mark = "OK"
        elif text:
            mark = "TEXT"
        else:
            mark = "EMPTY"
        dg = f"  DOWNGRADED->{r['effective']}" if r["downgraded"] else ""
        print(f"{mark:<6} {r['model']:<32} http={r['http']} {r['sec']:>6}s "
              f"ev={r['events']:<3} status={r['final_status'] or '-':<10}{dg}")
        if text:
            print(f"       {text[:160]!r}")
        time.sleep(1)