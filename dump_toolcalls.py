"""Сырой дамп tool_call-событий: как называется поле с именем и аргументами."""
import asyncio, json, sys, time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parent
ACC = next(json.loads(l) for l in (ROOT/"data/conol_accounts_pool.jsonl").read_text().strip().splitlines()
           if json.loads(l).get("status")=="live")
CK = {"__Secure-better-auth.session_token": ACC["session_token"]}

async def main():
    async with httpx.AsyncClient(cookies=CK, timeout=180) as c:
        r = await c.post("https://conol.ai/api/sessions", json={
            "source":{"type":"home"},
            "messages":[{"type":"text","content":"Создай файл note.md с текстом hello и покажи что получилось."}],
            "timezone":"Europe/Kyiv","agentModel":"claude-haiku-5-5","agentEffort":"low"})
        sid = r.json()["sessionId"]
        t0=time.time(); printed=set()
        async with c.stream("GET", f"https://conol.ai/api/sessions/{sid}/messages?logDeltas=1") as s:
            async for line in s.aiter_lines():
                if time.time()-t0>140: break
                if not line.startswith("data:"): continue
                try: ev=json.loads(line[5:].strip())
                except: continue
                if ev.get("type") in ("done","error"): break
                if ev.get("type")!="history_delta": continue
                for stage in ev.get("stages") or []:
                    for item in (stage.get("logs") or []):
                        if item.get("type")!="tool_call": continue
                        key=(item.get("toolCallId"), item.get("status"))
                        if key in printed: continue
                        printed.add(key)
                        print("\n=== TOOL_CALL EVENT ===")
                        print("keys:", list(item.keys()))
                        print(json.dumps(item, ensure_ascii=False)[:900])
asyncio.run(main())
