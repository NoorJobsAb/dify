# Secret broker: holds the Board's secrets so agent shells never do; stdlib Python plus the Doppler CLI.
FROM python:3.12-slim
# Keep in step with DOPPLER_VERSION in make_coolify.py (a test compares them).
ARG DOPPLER_VERSION=3.75.1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/DopplerHQ/cli/releases/download/${DOPPLER_VERSION}/doppler_${DOPPLER_VERSION}_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin doppler \
 && apt-get purge -y curl && apt-get autoremove -y
RUN useradd --create-home --shell /usr/sbin/nologin broker
COPY broker.py /app/broker.py
USER broker
EXPOSE 8080
CMD ["python3", "-I", "/app/broker.py"]
