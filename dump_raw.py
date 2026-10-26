"""Сырой дамп ответа conol на просьбу создать файл — что реально приходит."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, ".")
sys.path.insert(0, "upstream")
from gateway import _conol_collect_text  # noqa
from agent_tools import builtin_tool_names


async def main():
    root = Path(__file__).resolve().parent
    tok_acc = None
    for line in (root / "data/conol_accounts_pool.jsonl").read_text().strip().splitlines():
        d = json.loads(line)
        if d.get("status") == "live":
            tok_acc = d
            break
    ck_path = tok_acc["cookies_path"]

    sys_prompt = (
        "[CRITICAL: You have real tools and MUST use them]\n"
        f"Available tools: {', '.join(builtin_tool_names())}.\n\n"
        "YOU CANNOT create files by writing text. The ONLY way is a tool call.\n"
        "To call a tool, output EXACTLY this XML and NOTHING else:\n"
        '<function_call>{"name":"write_file","arguments":{"path":"file.md","content":"full text"}}</function_call>\n'
    )
    msgs = [
        {"type": "text", "content": f"[System]\n{sys_prompt}"},
        {"type": "text", "content": "Создай markdown файл test_dump.md с заголовком."},
    ]
    raw = await _conol_collect_text(ck_path, msgs, "claude-haiku-5-5",
                                    timeout=180, effort="low", source_type="home")
    print("=== RAW RESPONSE (%d chars) ===" % len(raw))
    print(raw)
    print("=== REPR ===")
    print(repr(raw[:2000]))


asyncio.run(main())