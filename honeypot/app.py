"""Low-interaction HTTP honeypot for BrovanaRange.

It records requests but never executes supplied input, proxies traffic, or
connects to any BrovanaRange service.
"""
import json
import logging
import os
from datetime import datetime, timezone

from flask import Flask, Response, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
logging.basicConfig(level=logging.INFO, format="%(message)s")


def client_ip() -> str:
    # The service is intentionally not placed behind the application proxy.
    # Do not trust forwarded headers from arbitrary Internet clients.
    return request.remote_addr or "unknown"


def record_request() -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "honeypot_request",
        "source_ip": client_ip(),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("utf-8", "replace")[:1024],
        "user_agent": request.headers.get("User-Agent", "")[:512],
        "content_type": request.content_type or "",
        "content_length": request.content_length or 0,
    }
    app.logger.info(json.dumps(event, separators=(",", ":")))


@app.before_request
def capture_request():
    record_request()


@app.errorhandler(413)
def request_too_large(_error):
    return Response("Request Entity Too Large\n", status=413, mimetype="text/plain")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def decoy(path: str):
    if request.method == "OPTIONS":
        return Response(status=204, headers={"Allow": "GET, POST, OPTIONS"})
    if path in {"admin", "admin/", "login", "login/", "phpmyadmin", "phpmyadmin/"}:
        return Response("<html><title>Administration</title><body>Authentication required.</body></html>", status=401, headers={"WWW-Authenticate": 'Basic realm="Administration"'}, mimetype="text/html")
    if path in {".env", ".git/config", "wp-login.php", "server-status"}:
        return Response("Not Found\n", status=404, mimetype="text/plain")
    return Response("Not Found\n", status=404, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
