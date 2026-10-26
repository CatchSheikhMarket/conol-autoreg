"""Открыть conol.ai с живой сессией и вытащить список моделей из UI-пикера."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
TOK = None
for line in (ROOT / "data/conol_accounts_pool.jsonl").read_text().strip().splitlines():
    d = json.loads(line)
    if d.get("status") == "live":
        TOK = d["session_token"]
        break
if not TOK:
    sys.exit("нет живого аккаунта")

with sync_playwright() as pw:
    browser = pw.chromium.launch(
        headless=False,
        args=["--disable-blink-features=AutomationControlled", "--test-type",
              "--window-size=1400,950", "--lang=en-US"],
        env={**__import__("os").environ, "DISPLAY": ":1"},
    )
    ctx = browser.new_context(viewport={"width": 1400, "height": 950})
    ctx.add_cookies([{
        "name": "__Secure-better-auth.session_token",
        "value": TOK,
        "domain": ".conol.ai",
        "path": "/",
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }])
    page = ctx.new_page()
    page.goto("https://conol.ai/home", wait_until="domcontentloaded", timeout=90000)
    page.wait_for_timeout(6000)
    print("URL:", page.url, flush=True)
    print("TITLE:", page.title(), flush=True)

    # ищем кнопку/селект с моделью на странице
    info = page.evaluate("""() => {
      const out = {buttons: [], selects: [], modelish: []};
      document.querySelectorAll('button,[role=button],[role=combobox],select')
        .forEach(el => {
          const t = (el.innerText || el.value || '').trim();
          const r = el.getBoundingClientRect();
          if (t && r.width > 0) out.buttons.push({t: t.slice(0, 60), tag: el.tagName,
            role: el.getAttribute('role') || '', id: el.id || '',
            cls: (el.className || '').toString().slice(0, 50)});
        });
      document.querySelectorAll('select').forEach(s => out.selects.push({
        name: s.name, opts: [...s.options].map(o => o.text.trim() + '=' + o.value)
      }));
      const txt = document.body.innerText;
      const re = /(claude|deepseek|gpt|glm|qwen|kimi|gemini|grok|mimo|minimax|hy3)[a-zA-Z0-9 ._\\/-]{0,30}/gi;
      const m = txt.match(re) || [];
      out.modelish = [...new Set(m.map(x => x.trim()))].slice(0, 60);
      return out;
    }""")
    print("\n=== BUTTONS ===", flush=True)
    for b in info["buttons"][:40]:
        if any(k in b["t"].lower() for k in
               ("model", "claude", "gpt", "deepseek", "glm", "qwen", "kimi", "sonnet", "opus", "haiku")):
            print("  ", b, flush=True)
    print("\n=== MODELS IN TEXT ===", flush=True)
    for m in info["modelish"]:
        print("  ", m, flush=True)

    page.screenshot(path="diag_out/conol_ui_home.png")
    print("\nscreenshot: diag_out/conol_ui_home.png", flush=True)
    time.sleep(2)
    browser.close()