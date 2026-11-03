# BrowserMesh: one long-lived browser with separate sessions per agent run, served as MCP over HTTP by mcp-proxy.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm install -g multi-agent-browser-mcp@0.1.5 \
 && cd /usr/local/lib/node_modules/multi-agent-browser-mcp && npx -y playwright@1.62.1 install --with-deps chromium
RUN python3 -m venv /opt/proxy && /opt/proxy/bin/pip install --no-cache-dir mcp-proxy==0.14.0
ENV BROWSERMESH_HEADLESS=true BROWSERMESH_DATA_DIR=/data BROWSERMESH_LOG_LEVEL=warn
EXPOSE 8932
# The agent sandbox writes login states into /data/states as another user, so the folder is world-writable (sticky).
CMD ["sh", "-c", "mkdir -p /data/states && chmod 1777 /data/states && exec /opt/proxy/bin/mcp-proxy --host 0.0.0.0 --port 8932 --pass-environment -- browsermesh"]
