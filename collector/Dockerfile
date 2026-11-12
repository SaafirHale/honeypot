# syntax=docker/dockerfile:1
# Collector image: reads Cowrie logs read-only, writes stats.json, has no network.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml ./
COPY honeypot_collector ./honeypot_collector

# Optional build secret "extra_ca": a PEM root certificate appended to the
# system bundle for this one pip install, for building behind a TLS-inspecting
# proxy. Verification stays on, and the certificate is never written to a layer.
# Without the secret (any normal build) the default trust store is used.
# /stats is pre-created with the right owner so a fresh named volume inherits it.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca-bundle.pem; \
      export PIP_CERT=/tmp/ca-bundle.pem; \
    fi; \
    pip install --no-cache-dir . \
 && rm -f /tmp/ca-bundle.pem \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin collector \
 && mkdir /stats && chown 10001:10001 /stats

USER 10001:10001
ENTRYPOINT ["python", "-m", "honeypot_collector"]
