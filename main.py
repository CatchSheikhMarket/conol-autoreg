#!/usr/bin/env python3
"""main.py — тонкий CLI conol-control-panel (PANEL-SPEC §1).

    python main.py --count 10 --provider catchall --free-captcha   # регистрация (прежний CLI)
    python main.py panel [--port 9903]                                # панель (то же, что start.sh)
    python main.py check                                              # живая перепроверка пула ($0, без капчи)

Всё остальное — в модулях: реггер `conol_register.py`, капча `conol_captcha.py`,
почта `conol_emails.py`, панель `panel/server.py`, воркер `panel/afk_worker.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "panel"))

USAGE = __doc__


def cmd_register(argv: list) -> int:
    import conol_register
    sys.argv = ["conol_register.py"] + argv
    return conol_register.main()


def cmd_panel(argv: list) -> int:
    import server as panel_server  # panel/server.py
    return panel_server.main(argv)


def cmd_check(argv: list) -> int:
    """Перепроверить пул живьём: get-session + balance по каждому аккаунту (бесплатно)."""
    import server as panel_server

    rows = [r for r in panel_server.read_pool() if r.get("email")]
    if not rows:
        print("пул пуст: %s" % panel_server.POOL_FILE)
        return 1
    holder = panel_server.foreign_slot_holder()
    if holder:
        print("пул-слот занят живым процессом pid %s — перепроверка отменена "
              "(два писателя на JSONL недопустимы)" % holder)
        return 3
    results = [panel_server.check_one(r) for r in rows]
    width = max(len(r["email"]) for r in results)
    for r in results:
        print("%-*s  %-11s  credits=%s%s" % (width, r["email"], r["status"],
                                             r.get("credits", "—"),
                                             "  " + r["note"] if r.get("note") else ""))
    updated = panel_server.apply_check(results)
    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print("\nобновлено строк: %d | %s" % (updated, by_status))
    return 0


def main() -> int:
    argv = sys.argv[1:]
    head = argv[0] if argv else ""
    if head in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if head == "panel":
        return cmd_panel(argv[1:])
    if head == "check":
        return cmd_check(argv[1:])
    if head in ("register", "reg"):
        return cmd_register(argv[1:])
    # без подкоманды — прежний запуск реггера: python main.py --count N --provider … --free-captcha
    return cmd_register(argv)


if __name__ == "__main__":
    sys.exit(main())