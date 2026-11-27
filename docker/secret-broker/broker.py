"""secret-broker: holds the secrets the agent sandbox must not. Standard library only."""
import base64
import hmac
import http.client
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

SANDBOX_REPO = "noorjobsab/dify-sandbox"
MAX_TTL = 7200
PORT = 8080
SANDBOX_PATHS = ("/git/", "/config", "/alpha")
ZERO = "0" * 40
# Only the smart-HTTP endpoints; the strict owner and name characters keep "..", "%" and the like out of the upstream path.
GIT_PATH = re.compile(r"/git/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/(info/refs|git-upload-pack|git-receive-pack)")
REF_UPDATE = re.compile(r"([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)")
REQUEST_DROP = {"host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer",
                "upgrade", "expect", "proxy-authorization", "authorization", "x-board-ticket"}
RESPONSE_DROP = {"connection", "keep-alive", "transfer-encoding", "trailer", "upgrade", "date", "server"}


def log(endpoint, repo, ref, verdict, status):
    print(f"{endpoint} repo={repo} ref={ref} {verdict} {status}", file=sys.stderr, flush=True)


def _repo(name):
    if not isinstance(name, str) or name.count("/") != 1 or "" in name.split("/"):
        raise ValueError("malformed repo")
    return name.lower()


def _branch(name):
    if not isinstance(name, str) or not name:
        raise ValueError("malformed branch")
    return name


def normalize_scope(request, preview):
    try:
        if isinstance(request.get("read"), str):
            raise ValueError("read must be a list")
        read = {_repo(r) for r in request.get("read") or []}
        push = {(_repo(p["repo"]), _branch(p["branch"])) for p in request.get("push") or []}
        d = request.get("doppler")
        doppler = (d["project"], d["config"]) if d else None
        ttl = MAX_TTL if request.get("ttl_seconds") is None else min(max(int(request["ttl_seconds"]), 1), MAX_TTL)
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        raise ValueError("malformed request") from e
    if preview:
        read = {r for r in read if r == SANDBOX_REPO}
        push = {p for p in push if p[0] == SANDBOX_REPO}
    return {"read": read, "push": push, "doppler": doppler,
            "alpha_login": bool(request.get("alpha_login")), "ttl": ttl}


def parse_ref_updates(body):
    """(old, new, ref) for each command pkt-line before the first flush; ValueError on anything else."""
    updates, i = [], 0
    while True:
        head = body[i:i + 4]
        if not re.fullmatch(rb"[0-9a-fA-F]{4}", head):
            raise ValueError("bad pkt-line")
        size = int(head, 16)
        if size == 0:
            return updates
        if size < 5 or i + size > len(body):
            raise ValueError("bad pkt-line")
        line = body[i + 4:i + size].split(b"\0", 1)[0].decode().removesuffix("\n")
        update = REF_UPDATE.fullmatch(line)
        if not update:
            raise ValueError("not a ref update")
        updates.append(update.groups())
        i += size


def ref_refusal(scope, repo, update):
    _, new, ref = update
    if not any(r == repo for r, _ in scope["push"]):
        return f"{repo} is not open for push"
    if new == ZERO:
        return f"deleting {ref} is not allowed"
    if not ref.startswith("refs/heads/") or (repo, ref[len("refs/heads/"):]) not in scope["push"]:
        return f"pushing {ref} to {repo} is not allowed"
    return None


def push_refusal(scope, repo, updates):
    return next((r for u in updates if (r := ref_refusal(scope, repo, u))), None)


def push_capabilities(body):
    """The capabilities after the NUL of the first command pkt-line (the body is already parsed)."""
    line = body[4:int(body[:4], 16)]
    return set(line.split(b"\0", 1)[1].decode().split()) if b"\0" in line else set()


def pkt(data):
    return b"%04x" % (len(data) + 4) + data


def push_report(updates, reasons, sideband):
    """A receive-pack status report that refuses every ref; git prints each as "! [remote rejected] <ref> (<reason>)"."""
    report = pkt(b"unpack ok\n") + b"".join(
        pkt(f"ng {ref} {reason or 'refused with the rest of this push'}\n".encode())
        for (_, _, ref), reason in zip(updates, reasons)) + b"0000"
    return pkt(b"\x01" + report) + b"0000" if sideband else report


class Tickets:
    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}

    def issue(self, scope, now):
        ticket = secrets.token_urlsafe(32)
        expires = now + scope["ttl"]
        with self._lock:
            self._items[ticket] = (scope, expires)
        return ticket, expires

    def get(self, ticket, now):
        with self._lock:
            item = self._items.get(ticket)
            if item and now > item[1]:
                del self._items[ticket]
                item = None
        return item[0] if item else None

    def revoke(self, ticket):
        with self._lock:
            self._items.pop(ticket, None)


def ticket_of(handler, tickets, now):
    return tickets.get(handler.headers.get("X-Board-Ticket", ""), now)


def _key_ok(given, expected):
    return bool(expected) and hmac.compare_digest(given.encode(), expected.encode())


def make_server(env, port=PORT):
    tickets = Tickets()

    class Handler(BaseHTTPRequestHandler):
        timeout = 60  # socket reads and writes; a silent client cannot hold a thread forever

        def log_message(self, *args):
            pass  # the default line carries the request path, which can hold a ticket

        def _send(self, status, body="", ctype="text/plain"):
            body = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _api_key(self):
            """False for the deploy key, True for the preview key, None for neither."""
            auth = self.headers.get("Authorization", "")
            given = auth[7:] if auth.startswith("Bearer ") else ""
            if _key_ok(given, env.get("BROKER_API_KEY", "")):
                return False
            if _key_ok(given, env.get("BROKER_PREVIEW_KEY", "")):
                return True
            return None

        def _route(self):
            path = self.path.split("?", 1)[0]
            if path == "/tickets" and self.command == "POST":
                return self._issue()
            if path.startswith("/tickets/") and self.command == "DELETE":
                return self._revoke(path[len("/tickets/"):])
            if path.startswith(SANDBOX_PATHS):
                scope = ticket_of(self, tickets, time.time())
                if scope is None:
                    log(path.split("/")[1], "-", "-", "denied", 403 if path.startswith("/git/") else 401)
                    # git shows a 403 text body as "remote: <reason>"; a 401 would make it ask for a username
                    return self._send(403 if path.startswith("/git/") else 401, "unknown or expired ticket")
                if path.startswith("/git/"):
                    return self._git(scope, path)
                if path == "/config" and self.command == "POST":
                    return self._config(scope)
                if path == "/alpha" and self.command == "GET":
                    return self._alpha(scope)
            log("other", "-", "-", "denied", 404)
            self._send(404, "not found")

        def _issue(self):
            preview = self._api_key()
            if preview is None:
                log("tickets", "-", "-", "denied", 401)
                return self._send(401, "unauthorized")
            try:
                n = int(self.headers.get("Content-Length") or 0)
                scope = normalize_scope(json.loads(self.rfile.read(n) or b"{}"), preview)
            except (ValueError, AttributeError):
                log("tickets", "-", "-", "denied", 400)
                return self._send(400, "bad request")
            ticket, expires = tickets.issue(scope, time.time())
            stamp = datetime.fromtimestamp(expires, timezone.utc).isoformat()
            log("tickets", "-", "-", "allowed", 201)
            self._send(201, json.dumps({"ticket": ticket, "expires_at": stamp}), "application/json")

        def _revoke(self, ticket):
            if self._api_key() is None:
                log("tickets", "-", "-", "denied", 401)
                return self._send(401, "unauthorized")
            tickets.revoke(ticket)
            log("tickets", "-", "-", "allowed", 204)
            self._send(204)

        def _git(self, scope, path):
            match = GIT_PATH.fullmatch(path)
            service = parse_qs(self.path.partition("?")[2]).get("service", [""])
            if not match or len(service) != 1:
                log("git", "-", "-", "denied", 404)
                return self._send(404, "not found")
            owner, name, rest = match.groups()
            repo, service = f"{owner}/{name}".lower(), service[0]
            if rest == "info/refs":
                ok = self.command == "GET" and service in ("git-upload-pack", "git-receive-pack")
                rest += "?service=" + service
            else:
                ok, service = self.command == "POST", rest
            if not ok:
                log("git", repo, "-", "denied", 404)
                return self._send(404, "not found")
            try:
                body = self._body() if self.command == "POST" else None
            except ValueError:
                log("git", repo, "-", "denied", 400)
                return self._send(400, "unreadable request body")
            push, ref = service == "git-receive-pack", "-"
            if push:
                refusal, caps = None, set()
                if body is None:
                    if not any(r == repo for r, _ in scope["push"]):
                        refusal = f"{repo} is not open for push"
                else:
                    try:
                        decoded = self._decoded(body)
                        updates = parse_ref_updates(decoded)
                        caps = push_capabilities(decoded) if updates else set()
                    except ValueError:
                        refusal = "unreadable push request"
                    else:
                        ref = ",".join(u[2] for u in updates) or "-"
                        reasons = [ref_refusal(scope, repo, u) for u in updates]
                        refusal = next((r for r in reasons if r), None)
                if refusal:
                    log("git", repo, ref, "denied", 403)
                    if caps & {"report-status", "report-status-v2"}:
                        # a 403 here reaches the agent only as "RPC failed"; a status report shows the reason
                        report = push_report(updates, reasons, bool(caps & {"side-band", "side-band-64k"}))
                        return self._send(200, report, "application/x-git-receive-pack-result")
                    return self._send(403, refusal + "\n")
            self._forward(f"/{owner}/{name}.git/{rest}", body, push or repo in scope["read"], repo, ref)

        def _config(self, scope):
            if not scope["doppler"]:
                log("config", "-", "-", "denied", 403)
                return self._send(403, "no doppler config in scope")
            try:
                template = self._body()
            except ValueError:
                log("config", "-", "-", "denied", 400)
                return self._send(400, "unreadable request body")
            project, config = scope["doppler"]
            # DOPPLER_BIN may hold a command with arguments (tests run a Python stub); production is "doppler".
            cmd = shlex.split(env.get("DOPPLER_BIN", "doppler"))
            # an allowlist, not the broker's environment: the CLI is a third party and its output goes to the caller
            run_env = {k: env[k] for k in ("PATH", "HOME", "SYSTEMROOT") if k in env}
            run_env |= {"DOPPLER_TOKEN": env.get("DOPPLER_TOKEN", ""), "DOPPLER_ENABLE_VERSION_CHECK": "false"}
            with tempfile.TemporaryDirectory() as tmp:
                src = os.path.join(tmp, "template")
                with open(src, "wb") as f:
                    f.write(template)
                try:
                    done = subprocess.run(cmd + ["secrets", "substitute", src, "--project", project, "--config", config],
                                          env=run_env, capture_output=True, timeout=60)
                except (OSError, subprocess.TimeoutExpired):
                    done = None
            if done is None or done.returncode != 0:
                log("config", "-", "-", "failed", 502)
                return self._send(502, "rendering the config failed")  # the CLI output can hold secrets: never relayed
            log("config", "-", "-", "allowed", 200)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(done.stdout)))
            self.end_headers()
            self.wfile.write(done.stdout)

        def _alpha(self, scope):
            if not scope["alpha_login"]:
                log("alpha", "-", "-", "denied", 403)
                return self._send(403, "no alpha login in scope")
            log("alpha", "-", "-", "allowed", 200)
            self._send(200, f"ALPHA_TEST_EMAIL={env.get('ALPHA_TEST_EMAIL', '')}\nALPHA_TEST_PASSWORD={env.get('ALPHA_TEST_PASSWORD', '')}\n")

        def _body(self):
            """The request body as sent, with chunked transfer encoding undone."""
            if "Transfer-Encoding" not in self.headers:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n >= 0 else b""
                if len(body) != n:
                    raise ValueError("short body")
                return body
            if self.headers["Transfer-Encoding"].strip().lower() != "chunked":
                raise ValueError("unsupported transfer encoding")
            chunks = []
            while (size := int(self.rfile.readline(1024).split(b";")[0], 16)) > 0:
                chunks.append(self.rfile.read(size))
                if len(chunks[-1]) != size or self.rfile.readline(1024).strip():
                    raise ValueError("bad chunk")
            if size < 0:
                raise ValueError("bad chunk")
            while self.rfile.readline(1024).strip():
                pass  # trailer fields
            return b"".join(chunks)

        def _decoded(self, body):
            encoding = self.headers.get("Content-Encoding", "").strip().lower()
            if encoding == "gzip":
                # shortcut: only the first 1 MiB is inflated; the ref updates lead the body, and a longer list is refused.
                return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, 1 << 20)
            if encoding in ("", "identity"):
                return body
            raise ValueError("unsupported content encoding")

        def _forward(self, path, body, token, repo, ref):
            up = urlsplit(env.get("BROKER_GITHUB_URL", "https://github.com"))
            conn_class = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(up.netloc, timeout=300)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in REQUEST_DROP}
            if token:
                pat = base64.b64encode(("x-access-token:" + env.get("BOARD_BOT_PAT", "")).encode()).decode()
                headers["Authorization"] = "Basic " + pat
            if body is not None:
                headers["Content-Length"] = str(len(body))
            try:
                conn.request(self.command, up.path.rstrip("/") + path, body, headers)
                resp = conn.getresponse()
            except OSError:
                conn.close()
                log("git", repo, ref, "failed", 502)
                return self._send(502, "github unreachable")
            log("git", repo, ref, "allowed", resp.status)
            try:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in RESPONSE_DROP:
                        self.send_header(k, v)
                self.end_headers()
                while chunk := resp.read1(65536):
                    self.wfile.write(chunk)
            finally:
                conn.close()

        do_GET = do_POST = do_DELETE = _route

    server = ThreadingHTTPServer((env.get("BROKER_BIND", "0.0.0.0"), port), Handler)
    server.tickets = tickets  # exposed so tests can check the stored scope
    return server


def main():
    make_server(dict(os.environ)).serve_forever()


if __name__ == "__main__":
    main()
