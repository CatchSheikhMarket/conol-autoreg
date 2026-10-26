"""Серверные тулзы для conol-моста: модели не нужен клиент, мост сам исполняет.

Зачем: conol не умеет native function calling. Мост эмулирует его XML-разметкой,
но исполнять вызовы было некому — клиент (OMP, чат-обёртка) их игнорировал, и
модель выглядела «без тулзов». Здесь мост замыкает цикл на себе.

Схема:
    клиент → /v1/chat/completions (без tools)
    мост   → инжектит BUILTIN_TOOLS в системный промпт
    модель → <function_call>{"name":"write_file",...}</function_call>
    мост   → исполняет локально, кладёт результат как role=tool
    мост   → повторяет, пока модель не вернёт обычный текст
    клиент ← финальный текст + agent_trace

Безопасность: запись разрешена только внутри CONOL_AGENT_ROOTS
(по умолчанию cwd моста + домашний каталог). bash — только при
CONOL_AGENT_ALLOW_BASH=1.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

MAX_READ_BYTES = 200_000
MAX_RESULT_CHARS = 12_000


def _roots() -> list[Path]:
    raw = os.environ.get("CONOL_AGENT_ROOTS", "")
    roots = [Path(p).expanduser().resolve() for p in raw.split(":") if p.strip()]
    if not roots:
        roots = [Path.cwd().resolve(), Path.home().resolve()]
    return roots


def _safe_path(raw: str) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p)
    p = p.resolve()
    for root in _roots():
        try:
            p.relative_to(root)
            return p
        except ValueError:
            continue
    raise PermissionError(
        f"path outside allowed roots: {p} (roots: {[str(r) for r in _roots()]})")


# ─── исполнение ────────────────────────────────────────────────────────────

def tool_write_file(path: str, content: str = "", append: bool = False) -> str:
    p = _safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with p.open(mode, encoding="utf-8") as f:
        f.write(content)
    size = p.stat().st_size
    return f"OK wrote {len(content)} chars to {p} ({size} bytes on disk)"


def tool_read_file(path: str) -> str:
    p = _safe_path(path)
    if not p.exists():
        return f"ERROR file not found: {p}"
    if p.is_dir():
        return f"ERROR is a directory: {p}"
    data = p.read_text(encoding="utf-8", errors="replace")
    if len(data) > MAX_READ_BYTES:
        data = data[:MAX_READ_BYTES] + f"\n... [truncated, {len(data)} bytes total]"
    return data


def tool_list_dir(path: str = ".") -> str:
    p = _safe_path(path)
    if not p.exists():
        return f"ERROR not found: {p}"
    if not p.is_dir():
        return f"ERROR not a directory: {p}"
    rows = []
    for child in sorted(p.iterdir())[:500]:
        try:
            if child.is_dir():
                rows.append(f"{child.name}/")
            else:
                rows.append(f"{child.name}  ({child.stat().st_size}B)")
        except OSError:
            rows.append(child.name)
    return f"{p}:\n" + ("\n".join(rows) if rows else "(empty)")


def tool_delete_file(path: str) -> str:
    p = _safe_path(path)
    if not p.exists():
        return f"ERROR not found: {p}"
    if p.is_dir():
        shutil.rmtree(p)
        return f"OK removed directory {p}"
    p.unlink()
    return f"OK removed file {p}"


def tool_move_file(src: str, dst: str) -> str:
    a, b = _safe_path(src), _safe_path(dst)
    if not a.exists():
        return f"ERROR not found: {a}"
    b.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(a), str(b))
    return f"OK moved {a} -> {b}"


def tool_search_files(pattern: str, path: str = ".", max_hits: int = 100) -> str:
    p = _safe_path(path)
    hits = []
    for f in p.rglob(pattern):
        if len(hits) >= max_hits:
            break
        try:
            hits.append(str(f.relative_to(p)))
        except ValueError:
            hits.append(str(f))
    if not hits:
        return f"no matches for {pattern!r} under {p}"
    return f"{len(hits)} matches for {pattern!r}:\n" + "\n".join(hits)


def tool_run_bash(command: str, timeout: int = 60) -> str:
    if os.environ.get("CONOL_AGENT_ALLOW_BASH") != "1":
        return ("ERROR bash disabled. Set CONOL_AGENT_ALLOW_BASH=1 in the gateway "
                "environment to enable it.")
    timeout = max(1, min(int(timeout or 60), 300))
    try:
        r = subprocess.run(command, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=str(Path.cwd()))
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        out = out or "(no output)"
        if len(out) > MAX_RESULT_CHARS:
            out = out[:MAX_RESULT_CHARS] + "\n... [truncated]"
        return f"exit={r.returncode}\n{out}"
    except subprocess.TimeoutExpired:
        return f"ERROR timeout after {timeout}s"
    except Exception as e:
        return f"ERROR {type(e).__name__}: {e}"


EXECUTORS = {
    "write_file": tool_write_file,
    "read_file": tool_read_file,
    "list_dir": tool_list_dir,
    "delete_file": tool_delete_file,
    "move_file": tool_move_file,
    "search_files": tool_search_files,
    "run_bash": tool_run_bash,
}


def execute_tool(name: str, args: dict) -> str:
    """Выполнить тулзу по имени. Всегда возвращает строку (её увидит модель)."""
    fn = EXECUTORS.get(name)
    if not fn:
        return f"ERROR unknown tool {name!r}. Available: {sorted(EXECUTORS)}"
    if not isinstance(args, dict):
        return f"ERROR arguments must be an object, got {type(args).__name__}"
    try:
        return fn(**args)
    except TypeError as e:
        return f"ERROR bad arguments for {name}: {e}"
    except PermissionError as e:
        return f"ERROR permission: {e}"
    except Exception as e:
        return f"ERROR {type(e).__name__}: {e}"


def is_builtin(name: str) -> bool:
    return name in EXECUTORS


# ─── OpenAI-схемы (мост показывает их модели в системном промпте) ──────────

def _fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props, "required": required},
    }}


BUILTIN_TOOLS = [
    _fn("write_file",
        "Create or overwrite a file on disk with the given text content. "
        "Parent directories are created automatically. Use this to create any file "
        "the user asks for (markdown, code, config, etc.).",
        {"path": {"type": "string", "description": "absolute or relative file path"},
         "content": {"type": "string", "description": "full file content"},
         "append": {"type": "boolean", "description": "append instead of overwrite"}},
        ["path", "content"]),
    _fn("read_file",
        "Read a text file from disk and return its contents.",
        {"path": {"type": "string", "description": "path to the file"}},
        ["path"]),
    _fn("list_dir",
        "List files and directories inside a directory.",
        {"path": {"type": "string", "description": "directory path, default '.'"}},
        []),
    _fn("delete_file",
        "Delete a file or a directory tree.",
        {"path": {"type": "string", "description": "path to delete"}},
        ["path"]),
    _fn("move_file",
        "Move or rename a file/directory.",
        {"src": {"type": "string"}, "dst": {"type": "string"}},
        ["src", "dst"]),
    _fn("search_files",
        "Find files by glob pattern (e.g. '*.md', '**/*.py') under a directory.",
        {"pattern": {"type": "string"},
         "path": {"type": "string", "description": "root directory, default '.'"}},
        ["pattern"]),
    _fn("run_bash",
        "Run a shell command and return its stdout/stderr and exit code. "
        "Disabled unless the gateway operator enabled it.",
        {"command": {"type": "string"}, "timeout": {"type": "integer"}},
        ["command"]),
]


def builtin_tool_names() -> list[str]:
    return list(EXECUTORS)