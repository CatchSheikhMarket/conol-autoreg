"""Проверка моделей conol: создаём сессию, стримим SSE, смотрим реальный текст."""
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
    sys.exit("нет живого аккаунта в пуле")

CK = {"__Secure-better-auth.session_token": TOK}
PROMPT = "Reply with exactly: PROBE_OK"

MODELS = [
    "claude-haiku-5.5",
    "claude-haiku-4-5",
    "deepseek/deepseek-v4.1-flash",
    "deepseek/deepseek-v4.1-pro",
    "deepseek/deepseek-v4-flash",
    "deepseek/deepseek-v4-pro",
    "gpt-5.6-luna",
    "gpt-6-luna",
    "z-ai/glm-5.3",
    "z-ai/glm-5.3-flash",
    "qwen/qwen3.7-max",
    "moonshotai/kimi-k2.7-code",
]


def probe(model: str) -> dict:
    out = {"model": model, "downgraded": None, "effective": None,
           "text": "", "status": "", "sec": 0.0}
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
            if r.status_code != 201:
                out["status"] = f"HTTP {r.status_code}"
                out["text"] = r.text[:80]
                return out
            body = r.json()
            out["downgraded"] = body.get("modelDowngraded")
            out["effective"] = body.get("effectiveModel")
            sid = body["sessionId"]
            last = ""
            with c.stream("GET", f"https://conol.ai/api/sessions/{sid}/messages?logDeltas=1") as s:
                for line in s.iter_lines():
                    if time.time() - t0 > 110:
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
                    for stage in ev.get("stages") or []:
                        out["status"] = stage.get("status") or out["status"]
                        for pv in (stage.get("preview") or []):
                            if pv.get("role") != "assistant":
                                continue
                            for part in (pv.get("content") or []):
                                if isinstance(part, dict) and part.get("type") == "text":
                                    t = part.get("text", "")
                                    if t:
                                        last = t
    except Exception as e:
        out["status"] = f"ERR {type(e).__name__}"
        out["text"] = str(e)[:60]
    out["text"] = last.strip()
    out["sec"] = round(time.time() - t0, 1)
    return out


if __name__ == "__main__":
    models = sys.argv[1:] or MODELS
    for m in models:
        r = probe(m)
        mark = "OK " if "PROBE_OK" in r["text"] else ("EMPTY" if not r["text"] else "TEXT")
        dg = ""
        if r["downgraded"]:
            dg = f" DOWNGRADED->{r['effective']}"
        print(f"{mark:<6} {r['model']:<34} {r['sec']:>6}s  {r['status']:<10}{dg}")
        if r["text"]:
            print(f"       {r['text'][:110]!r}")
        elif r["status"]:
            print(f"       status={r['status']}")
        time.sleep(1)