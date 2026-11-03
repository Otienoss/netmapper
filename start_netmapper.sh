#!/usr/bin/env bash
# NetMapper'ı gerekli ham-soket yetkileriyle başlatır.
# Varsayılan: yalnızca localhost (127.0.0.1:8000).
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if (( EUID != 0 )); then
  exec sudo --preserve-env=PATH,PYTHON_BIN,HOST,PORT,RELOAD,API_TOKEN,EXPLOIT_ENABLED,EXPLOIT_ALLOWLIST,EXPLOIT_REQUIRE_CONFIRM,EXPLOIT_CLEANUP,TICKETS_RETENTION_DAYS,DATABASE_URL \
    bash "$0" "$@"
fi

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
RELOAD="${RELOAD:-0}"

if [[ "$HOST" != "127.0.0.1" && "$HOST" != "localhost" && -z "${API_TOKEN:-}" ]]; then
  printf 'UYARI: Uzak arayüz (%s) API_TOKEN olmadan açılıyor!\n' "$HOST" >&2
fi
if [[ "${EXPLOIT_ENABLED:-false}" == "true" ]]; then
  printf 'UYARI: SÖMÜR modülü açık — yalnızca izinli laboratuvar hedeflerini kullanın.\n' >&2
fi

args=(--host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" ]]; then
  args+=(--reload)
fi

printf 'NetMapper başlatılıyor: http://%s:%s (root)\n' "$HOST" "$PORT"
exec "$PYTHON_BIN" -m uvicorn app.main:app "${args[@]}"
