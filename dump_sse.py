"""Дамп ВСЕХ событий SSE от conol: ищем tool-call события родного агента."""
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
ACC = None
for line in (ROOT / "data/conol_accounts_pool.jsonl").read_text().strip().splitlines():
    d = json.loads(line)
    if d.get("status") == "live":
        ACC = d
        break
TOK = ACC["session_token"]
CK = {"__Secure-better-auth.session_token": TOK}


async def main():
    prompt = "Создай файл hello.txt с текстом 'hi' в рабочей директории."
    async with httpx.AsyncClient(cookies=CK, timeout=180) as c:
        r = await c.post("https://conol.ai/api/sessions", json={
            "source": {"type": "home"},
            "messages": [{"type": "text", "content": prompt}],
            "timezone": "Europe/Kyiv",
            "agentModel": "claude-haiku-5-5",
            "agentEffort": "low",
        })
        print("create:", r.status_code, r.text[:300], flush=True)
        sid = r.json()["sessionId"]

        t0 = time.time()
        seen_types = {}
        async with c.stream("GET", f"https://conol.ai/api/sessions/{sid}/messages?logDeltas=1") as s:
            async for line in s.aiter_lines():
                if time.time() - t0 > 150:
                    print("TIMEOUT", flush=True)
                    break
                if not line or not line.startswith("data:"):
                    continue
                try:
                    ev = json.loads(line[5:].strip())
                except Exception:
                    continue
                t = ev.get("type", "?")
                seen_types[t] = seen_types.get(t, 0) + 1
                if t in ("done", "error"):
                    print(f"\nEVENT {t}: {json.dumps(ev)[:300]}", flush=True)
                    break
                for stage in ev.get("stages") or []:
                    keys = list(stage.keys())
                    print(f"\n--- STAGE keys={keys}", flush=True)
                    if stage.get("status"):
                        print(f"    status={stage['status']}", flush=True)
                    # логи: что делал агент (включая tool calls)
                    for lg in (stage.get("logs") or []):
                        role = lg.get("role")
                        typ = lg.get("type")
                        for part in (lg.get("content") or []):
                            if not isinstance(part, dict):
                                continue
                            ptype = part.get("type")
                            if ptype == "text":
                                txt = part.get("text") or ""
                                if txt:
                                    print(f"    [{role}/{typ}] text: {txt[:300]!r}", flush=True)
                            else:
                                print(f"    [{role}/{typ}] {ptype}: "
                                      f"{json.dumps(part, ensure_ascii=False)[:400]}", flush=True)
                    for pv in (stage.get("preview") or []):
                        pass
        print(f"\n=== event types: {seen_types}", flush=True)


asyncio.run(main())