#!/bin/sh
set -eu

python /opt/akfes-local/prepare_local.py

# The application startup runs the same SQLAlchemy schema initializer and
# compatibility migrations used by the production source tree.  This source
# snapshot intentionally has no alembic.ini, so invoking Alembic here would
# prevent the container from ever starting.
exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-server-header
