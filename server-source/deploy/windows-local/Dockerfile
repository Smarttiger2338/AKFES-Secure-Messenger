FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY server/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY server /app
COPY deploy/windows-local/prepare_local.py /opt/akfes-local/prepare_local.py
COPY deploy/windows-local/entrypoint.sh /opt/akfes-local/entrypoint.sh
RUN chmod 0755 /opt/akfes-local/entrypoint.sh \
    && mkdir -p /run/akfes-local /app/encrypted-files

EXPOSE 8000
ENTRYPOINT ["/opt/akfes-local/entrypoint.sh"]
