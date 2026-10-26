"""Открыть conol, нажать пикер модели в композере, вытащить полный список."""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
TOK = next(json.loads(l)["session_token"]
           for l in ROOT.joinpath("data/conol_accounts_pool.jsonl").read_text().strip().splitlines()
           if json.loads(l).get("status") == "live")

with sync_playwright() as pw:
    browser = pw.chromium.launch(
        headless=False,
        args=["--disable-blink-features=AutomationControlled", "--test-type",
              "--window-size=1400,950", "--lang=en-US"],
        env={**os.environ, "DISPLAY": ":1"},
    )
    ctx = browser.new_context(viewport={"width": 1400, "height": 950})
    ctx.add_cookies([{"name": "__Secure-better-auth.session_token", "value": TOK,
                      "domain": ".conol.ai", "path": "/", "httpOnly": True,
                      "secure": True, "sameSite": "Lax"}])
    page = ctx.new_page()

    # перехват ответов: ловим всё, где в теле есть модели
    hits = []

    def on_resp(r):
        try:
            ct = r.headers.get("content-type", "")
            if "json" not in ct:
                return
            body = r.text()
            low = body.lower()
            if any(k in low for k in ("haiku", "deepseek", "agentmodel", "gpt-", "glm-")):
                hits.append({"url": r.url, "len": len(body), "body": body[:6000]})
        except Exception:
            pass

    page.on("response", on_resp)
    page.goto("https://conol.ai/home", wait_until="domcontentloaded", timeout=90000)
    page.wait_for_timeout(7000)

    # принять куки
    for sel in ["button:has-text('Accept all')", "button:has-text('Accept')"]:
        try:
            page.click(sel, timeout=2500)
            page.wait_for_timeout(600)
            break
        except Exception:
            pass

    # найти композер: textarea/contenteditable внизу
    comp = page.evaluate("""() => {
      const els = [...document.querySelectorAll('textarea,[contenteditable=true],[role=textbox]')];
      const vis = els.filter(e => { const r = e.getBoundingClientRect(); return r.height > 0; });
      return vis.map(e => { const r = e.getBoundingClientRect();
        return {tag: e.tagName, x: r.x + r.width/2, y: r.y + r.height/2,
                w: Math.round(r.width), h: Math.round(r.height),
                ph: e.placeholder || e.getAttribute('aria-placeholder') || ''}; });
    }""")
    print("COMPOSERS:", json.dumps(comp, ensure_ascii=False), flush=True)

    # ищем рядом с композером кнопку модели
    modal_btns = page.evaluate("""() => {
      const all = [...document.querySelectorAll('button,[role=button],[role=combobox]')];
      return all.map(e => { const r = e.getBoundingClientRect();
        const t = (e.innerText||'').trim();
        return {t: t.slice(0,50), x: Math.round(r.x), y: Math.round(r.y),
                w: Math.round(r.width), h: Math.round(r.height),
                vis: r.width>0 && r.height>0};
      }).filter(b => b.vis && b.y > 700);
    }""")
    print("\nBUTTONS near bottom:", json.dumps(modal_btns, ensure_ascii=False, indent=1)[:2000], flush=True)

    # клик по элементу, где может быть модель
    target = next((b for b in modal_btns
                   if any(k in b["t"].lower() for k in ("claude", "haiku", "gpt", "model", "sonnet"))),
                  None)
    print("\nTARGET:", target, flush=True)
    if target:
        page.mouse.click(target["x"] + target["w"] / 2, target["y"] + 16)
        page.wait_for_timeout(2500)
        page.screenshot(path="diag_out/conol_model_picker.png")

        opts = page.evaluate("""() => {
          const out = [];
          document.querySelectorAll('[role=option],[role=menuitem],[role=menuitemradio],li,button')
            .forEach(e => {
              const r = e.getBoundingClientRect();
              const t = (e.innerText || '').trim();
              if (r.width > 0 && r.height > 0 && t && t.length < 80) {
                out.push({t, y: Math.round(r.y), x: Math.round(r.x),
                          role: e.getAttribute('role') || e.tagName});
              }
            });
          return out;
        }""")
        seen = set()
        print("\n=== PICKER OPTIONS ===", flush=True)
        for o in opts:
            if o["t"] in seen:
                continue
            seen.add(o["t"])
            print(f"  [{o['role']:<14}] {o['t']}", flush=True)

    print("\n=== API HITS (модели в JSON) ===", flush=True)
    for h in hits[:8]:
        print(f"\n--- {h['url']} ({h['len']}b)", flush=True)
        # вытащим имена моделей из тела
        try:
            d = json.loads(h["body"])
            print(json.dumps(d, ensure_ascii=False, indent=1)[:1800], flush=True)
        except Exception:
            print(h["body"][:800], flush=True)

    page.screenshot(path="diag_out/conol_ui_final.png")
    time.sleep(2)
    browser.close()