"""upstream — апстримные модули conol и Windows-хелперы, не участвующие в нашем флоу.

Вынесены из корня 2026-10-08 (манифест переездa: docs/REORG-2026-10-08.md). Наш
флоу — ядро в корне (`conol_register.py`, `conol_captcha.py`, `conol_proxy.py`,
`conol_usage.py`, `conol_emails.py`, `conol_refresh.py`, `conol_secrets.py`,
`conol_server.py`, `main.py`) плюс `panel/`, `tests/`, `start.sh`.

Пакет держит импорты старых имён рабочими: свой каталог кладём в sys.path (чтобы
upstream-модули видели друг друга по короткому имени: `conol_gateway → conol_infer`,
`eni_conol → gateway`), родительский — чтобы они могли ходить в ядро.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _path in (str(_HERE), str(_HERE.parent)):
    if _path not in sys.path:
        sys.path.insert(0, _path)