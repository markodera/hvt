"""Retry database connectivity before migrations or app startup."""

from __future__ import annotations

import os
import sys
import time

import psycopg2


def _connection_kwargs() -> dict[str, object]:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url:
        return {"dsn": database_url}

    return {
        "dbname": os.getenv("DB_NAME", "").strip(),
        "user": os.getenv("DB_USER", "").strip(),
        "password": os.getenv("DB_PASSWORD", "").strip(),
        "host": os.getenv("DB_HOST", "localhost").strip(),
        "port": os.getenv("DB_PORT", "5432").strip(),
    }


def main() -> int:
    attempts = int(os.getenv("DB_CONNECT_MAX_ATTEMPTS", "45"))
    delay_seconds = float(os.getenv("DB_CONNECT_RETRY_DELAY", "2"))
    connection_kwargs = _connection_kwargs()

    if not any(connection_kwargs.values()):
        print("No database settings found; skipping database wait.")
        return 0

    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            connection = psycopg2.connect(connect_timeout=5, **connection_kwargs)
        except psycopg2.OperationalError as exc:
            last_error = exc
            print(
                f"Database not ready yet (attempt {attempt}/{attempts}): {exc}",
                flush=True,
            )
            if attempt == attempts:
                break
            time.sleep(delay_seconds)
        else:
            connection.close()
            print(f"Database connection succeeded on attempt {attempt}.", flush=True)
            return 0

    print(f"Database never became ready: {last_error}", file=sys.stderr, flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
