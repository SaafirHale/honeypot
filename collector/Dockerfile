# Collector image: reads Cowrie logs read-only, writes stats.json, has no network.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml ./
COPY honeypot_collector ./honeypot_collector
# /stats is pre-created with the right owner so a fresh named volume inherits it.
RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin collector \
 && mkdir /stats && chown 10001:10001 /stats

USER 10001:10001
ENTRYPOINT ["python", "-m", "honeypot_collector"]
