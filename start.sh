#!/bin/bash
# start.sh — поднять панель conol-control-panel на 127.0.0.1:9903.
#
# Обязательная часть (PANEL-SPEC §3а): cd в свою папку, снять PYTHONHOME/PYTHONPATH/
# LD_LIBRARY_PATH (иначе ломаются urllib/SSL на этой машине), запустить панель общим
# venv'ом, вывод — в data/panel.log через tee. Ctrl+C гасит панель.
#
# Аргументы:
#   (без аргументов) — как раньше + автооткрытие браузера на панели (как во freebuff);
#   --no-browser     — не открывать браузер (тестовые/headless-запуски).
#
# Дополнительно (специфика conol): бесплатная капча требует НЕ-headless Chrome.
# Замер 07.10: enterprise-токены из --headless=new сервер режет 403 (2/2), те же
# токены из headful-Chrome — 200 (2/2). Поэтому скрипт поднимает невидимый дисплей
# (gamescope --backend headless: окна на рабочем столе нет) и отдаёт его Chrome.
set -u

NO_BROWSER=0
for arg in "$@"; do
  case "$arg" in
    --no-browser) NO_BROWSER=1 ;;
    *) echo "[start.sh] неизвестный аргумент: $arg (доступно: --no-browser)" >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")" || exit 1
unset PYTHONHOME PYTHONPATH LD_LIBRARY_PATH 2>/dev/null

PORT="${CONOL_PANEL_PORT:-9903}"
PY=".venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
LOG_DIR="data"
mkdir -p "$LOG_DIR"

# ── невидимый X-дисплей для headful Chrome ───────────────────────────────────
DISPLAY_FILE="/tmp/conol_gamescope.display"
PID_FILE="/tmp/conol_gamescope.pid"          # информационно: pid для ручного kill

# «Дисплей жив» проверяем настоящим X-клиентом, а не сокетом: после убитого gamescope
# сокет /tmp/.X11-unix/X1 остаётся, и проверка по файлу молча отдала бы Chrome мёртвый дисплей.
probe_display() {
  local d="$1"
  [ -n "$d" ] || return 1
  if command -v xdpyinfo >/dev/null 2>&1; then
    xdpyinfo -display "$d" >/dev/null 2>&1
  else
    [ -S "/tmp/.X11-unix/X${d#:}" ]
  fi
}

HAS_DISPLAY=0
if probe_display "${CONOL_CHROME_DISPLAY:-}"; then
  HAS_DISPLAY=1
elif [ -s "$DISPLAY_FILE" ] && probe_display "$(cat "$DISPLAY_FILE")"; then
  CONOL_CHROME_DISPLAY="$(cat "$DISPLAY_FILE")"
  HAS_DISPLAY=1
elif command -v gamescope >/dev/null 2>&1; then
  echo "[start.sh] поднимаю невидимый дисплей: gamescope --backend headless (для headful Chrome)"
  rm -f "$DISPLAY_FILE"
  setsid nohup gamescope --backend headless -W 1280 -H 900 -r 60 --xwayland-count 1 -- \
      sh -c "echo \"\$DISPLAY\" > $DISPLAY_FILE; exec sleep 100000" \
      >> "$LOG_DIR/gamescope.log" 2>&1 &
  echo $! > "$PID_FILE"
  for _ in $(seq 1 20); do
    [ -s "$DISPLAY_FILE" ] && break
    sleep 1
  done
  if [ -s "$DISPLAY_FILE" ] && probe_display "$(cat "$DISPLAY_FILE")"; then
    CONOL_CHROME_DISPLAY="$(cat "$DISPLAY_FILE")"
    HAS_DISPLAY=1
  else
    echo "[start.sh] ВНИМАНИЕ: gamescope не поднялся, chrome_cdp может не работать" >&2
  fi
fi
if [ "$HAS_DISPLAY" = "1" ]; then
  export CONOL_CHROME_DISPLAY
  export CONOL_CHROME_HEADLESS=0        # headful в невидимом дисплее
  echo "[start.sh] Chrome будет запущен на дисплее $CONOL_CHROME_DISPLAY (окон на десктопе нет)"
else
  echo "[start.sh] невидимого дисплея нет — Chrome пойдёт headless (капча может отбиваться 403)" >&2
fi

PANEL_URL="http://127.0.0.1:$PORT"

echo "[start.sh] панель: $PANEL_URL  (лог: $LOG_DIR/panel.log)"
if [ "$NO_BROWSER" != "1" ]; then
  # Автооткрытие браузера (как во freebuff): но не раньше, чем панель реально
  # отвечает — иначе xdg-open покажет «не удалось подключиться» вместо панели.
  # Фоновый сабшелл: сервер ниже стартует на переднем плане (exec), ждать в нём нельзя.
  (
    for _ in $(seq 1 40); do
      env -u PYTHONHOME -u PYTHONPATH -u LD_LIBRARY_PATH \
        curl -s -o /dev/null -m 1 "$PANEL_URL/api/summary" && break
      sleep 0.3
    done
    xdg-open "$PANEL_URL" >/dev/null 2>&1 || true
    echo "[start.sh] браузер открыт: $PANEL_URL"
  ) &
else
  echo "[start.sh] --no-browser: браузер не открываю"
fi
exec > >(tee -a "$LOG_DIR/panel.log") 2>&1
exec "$PY" -X utf8 -u panel/server.py --port "$PORT"