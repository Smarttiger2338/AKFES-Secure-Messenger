ARG PYTHON_BASE_IMAGE=python:3.13-slim
FROM ${PYTHON_BASE_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends gosu ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system akfes && adduser --system --ingroup akfes --home /app akfes
WORKDIR /app
COPY requirements.txt requirements.lock* ./
RUN if [ -f requirements.lock ]; then \
      python -m pip install --only-binary=:all: --require-hashes -r requirements.lock; \
    else \
      python -m pip install --only-binary=:all: -r requirements.txt; \
    fi
COPY app ./app
COPY docker-entrypoint.sh /usr/local/bin/akfes-entrypoint
RUN chmod 0755 /usr/local/bin/akfes-entrypoint \
    && mkdir -p /app/encrypted-files /run/zt \
    && chown -R akfes:akfes /app /run/zt
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/akfes-entrypoint"]
CMD ["sh","-c","exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\" --ws-max-size \"${WS_MAX_FRAME_BYTES:-16384}\""]
