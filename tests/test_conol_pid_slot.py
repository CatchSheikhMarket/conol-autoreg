"""Self-check for conol_register.py's pid-slot ownership.

Run: python tests/test_conol_pid_slot.py
Exits non-zero if the guard preventing two concurrent registrars breaks.

The guard matters because two registrars would append to one JSONL pool and read one
Gmail mailbox over IMAP; the pool file has no locking, so the pid slot is the only
thing standing between "one writer" and silent interleaved corruption.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # conol_register imports conol_secrets/conol_captcha by name
SRC = ROOT / "conol_register.py"
spec = importlib.util.spec_from_file_location("cr", SRC)
assert spec is not None and spec.loader is not None, f"cannot load {SRC}"
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)

# Drive the guard against a THROWAWAY slot file, never the live one: this test deletes and
# rewrites the slot ~9 times, and a registrar or the panel's AFK worker may legitimately own
# data/conol_register_run.pid while it runs.
TMP_DIR = Path(tempfile.mkdtemp(prefix="conol_pid_slot_test_"))
cr.PID_FILE = TMP_DIR / "conol_register_run.pid"
PID_FILE = cr.PID_FILE
TMP_FILE = PID_FILE.with_suffix(".pid.tmp")

fails = []


def check(name, cond, extra=""):
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else " — " + str(extra)))
    if not cond:
        fails.append(name)


def reset():
    for p in (PID_FILE, TMP_FILE):
        if p.exists():
            p.unlink()


def sleeper():
    """A real live process, so _pid_alive exercises tasklist rather than a mock."""
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    time.sleep(1.5)
    return p


try:
    # 1. empty slot -> claim and publish our own pid
    reset()
    check("acquires an empty slot", cr.acquire_pid_slot() is True)
    check("publishes own pid",
          PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()),
          PID_FILE.read_text(encoding="utf-8"))
    check("atomic write leaves no tmp file", not TMP_FILE.exists())

    # 2. re-acquiring our own slot is idempotent (a supervisor restart mid-round)
    check("re-acquiring own slot is allowed", cr.acquire_pid_slot() is True)

    # 3. stale pid from a taskkill /F'd run -> take over instead of deadlocking
    reset()
    PID_FILE.write_text("999999\n", encoding="utf-8")
    check("takes over a stale pid", cr.acquire_pid_slot() is True)
    check("takeover rewrites the pid",
          PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()))

    # 4. LIVE foreign registrar -> refuse, and do not clobber the holder's pid
    live = sleeper()
    reset()
    PID_FILE.write_text(f"{live.pid}\n", encoding="utf-8")
    check("_pid_alive sees a real process", cr._pid_alive(live.pid) is True)
    check("refuses a live foreign registrar", cr.acquire_pid_slot() is False)
    check("refusal leaves the holder's pid intact",
          PID_FILE.read_text(encoding="utf-8").strip() == str(live.pid),
          PID_FILE.read_text(encoding="utf-8"))
    live.kill()
    live.wait()

    # 5. a reaped pid must read as dead, else every round refuses forever
    check("_pid_alive rejects a dead pid", cr._pid_alive(live.pid) is False)
    check("_pid_alive rejects non-positive pids",
          cr._pid_alive(0) is False and cr._pid_alive(-1) is False)

    # 6. broken probe -> fail-closed. The probe is tasklist on Windows and os.kill on
    #    POSIX, so break BOTH: reading a broken probe as "dead" is what would start a
    #    second registrar next to a live one.
    reset()
    PID_FILE.write_text("424242\n", encoding="utf-8")
    real_run = cr.subprocess.run
    real_kill = cr.os.kill

    def broken(*a, **k):
        raise OSError("probe broke")

    cr.subprocess.run = broken
    cr.os.kill = broken
    try:
        check("broken probe is fail-closed (refuses to start)", cr.acquire_pid_slot() is False)
    finally:
        cr.subprocess.run = real_run
        cr.os.kill = real_kill

    # 7. release clears only OUR pid
    reset()
    PID_FILE.write_text("424242\n", encoding="utf-8")
    cr.release_pid_slot()
    check("release never clears a foreign pid", PID_FILE.exists())
    PID_FILE.write_text(f"{os.getpid()}\n", encoding="utf-8")
    cr.release_pid_slot()
    check("release clears our own pid", not PID_FILE.exists())

    # 8. a two-line file (pid + heartbeat epoch) must still parse the pid
    live2 = sleeper()
    reset()
    PID_FILE.write_text(f"{live2.pid}\n{int(time.time())}\n", encoding="utf-8")
    check("two-line pid file still guards", cr.acquire_pid_slot() is False)
    live2.kill()
    live2.wait()

    # 9. garbage in the file must not crash the start path
    reset()
    PID_FILE.write_text("not-a-pid\n", encoding="utf-8")
    check("unparsable pid file is taken over, not fatal", cr.acquire_pid_slot() is True)
finally:
    reset()
    shutil.rmtree(TMP_DIR, ignore_errors=True)

print()
print(f"{9 - len(fails)}/9 blocks passed" if not fails else f"FAILURES: {fails}")
sys.exit(1 if fails else 0)
