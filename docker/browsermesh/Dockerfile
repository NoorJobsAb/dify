# BrowserMesh: one long-lived browser with separate sessions per agent run, served as MCP over HTTP by mcp-proxy.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm install -g multi-agent-browser-mcp@0.1.5 \
 && cd /usr/local/lib/node_modules/multi-agent-browser-mcp && npx -y playwright@1.62.1 install --with-deps chromium
# Dify turns each top-level key of an MCP tool's structured output into a variable and rejects `text`, `json` and
# `files`, so browser_visible_text failed on every call: rename its `text` to `content`. The greps stop the build
# when a version bump moves these lines.
RUN cd /usr/local/lib/node_modules/multi-agent-browser-mcp/dist/adapters/mcp \
 && sed -i 's/^        text: z.string(),$/        content: z.string(),/' contracts.js \
 && sed -i 's/^            text: completed.value,$/            content: completed.value,/' server.js \
 && grep -q '^        content: z.string(),$' contracts.js && grep -q '^            content: completed.value,$' server.js
RUN python3 -m venv /opt/proxy && /opt/proxy/bin/pip install --no-cache-dir mcp-proxy==0.14.0
ENV BROWSERMESH_HEADLESS=true BROWSERMESH_DATA_DIR=/data BROWSERMESH_LOG_LEVEL=warn
EXPOSE 8932
# mcp-proxy answers 421 to any Host but loopback, so allow the service name Dify calls.
# The agent sandbox writes login states into /data/states as another user, so the folder is world-writable (sticky).
CMD ["sh", "-c", "mkdir -p /data/states && chmod 1777 /data/states && exec /opt/proxy/bin/mcp-proxy --host 0.0.0.0 --port 8932 --allowed-host browsermesh --allowed-host browsermesh:8932 --pass-environment -- browsermesh"]
