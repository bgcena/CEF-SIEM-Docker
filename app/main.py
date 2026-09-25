import hmac
import os

from flask import Flask, Response, jsonify, request, send_from_directory

from connector import ConnectorManager

app = Flask(__name__, static_folder="static")
manager = ConnectorManager()

UI_USERNAME = os.environ.get("UI_USERNAME", "admin")
UI_PASSWORD = os.environ.get("UI_PASSWORD", "")

if manager.state.get("running"):
    manager.start()  # resume after container restart


@app.before_request
def basic_auth():
    if not UI_PASSWORD or request.path == "/healthz":
        return None
    auth = request.authorization
    if (auth and hmac.compare_digest(auth.username or "", UI_USERNAME)
            and hmac.compare_digest(auth.password or "", UI_PASSWORD)):
        return None
    return Response("Authentication required", 401,
                    {"WWW-Authenticate": 'Basic realm="Akamai SIEM Collector"'})


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


@app.get("/api/settings")
def get_settings():
    return jsonify(manager.public_settings())


@app.post("/api/settings")
def save_settings():
    try:
        manager.update_settings(request.get_json(force=True))
    except (ValueError, TypeError) as e:
        return jsonify(ok=False, message=str(e)), 400
    msg = "Saved"
    if manager.is_running():
        msg += " (restart the connector to apply)"
    return jsonify(ok=True, message=msg, settings=manager.public_settings())


@app.post("/api/test")
def test():
    ok, msg = manager.test_connection()
    return jsonify(ok=ok, message=msg)


@app.post("/api/start")
def start():
    ok, msg = manager.start()
    return jsonify(ok=ok, message=msg)


@app.post("/api/stop")
def stop():
    ok, msg = manager.stop()
    return jsonify(ok=ok, message=msg)


@app.post("/api/restart")
def restart():
    manager.stop()
    ok, msg = manager.start()
    return jsonify(ok=ok, message=msg)


@app.post("/api/reset-db")
def reset_db():
    ok, msg = manager.reset_db()
    return jsonify(ok=ok, message=msg)


@app.get("/api/download/<name>")
def download(name):
    """Config files for running the connector directly on a host (see README)."""
    if manager.missing():
        return jsonify(ok=False, message="Missing: " + ", ".join(manager.missing())), 400
    if name == "CEFConnector.properties":
        body, mime = manager.build_properties(), "text/plain; charset=iso-8859-1"
    elif name == "log4j2.xml":
        body, mime = manager.build_standalone_log4j(), "application/xml; charset=utf-8"
    else:
        return jsonify(ok=False, message="Unknown file"), 404
    return Response(body, content_type=mime, headers={
        "Content-Disposition": 'attachment; filename="{}"'.format(name),
        "Cache-Control": "no-store",
    })


@app.get("/api/status")
def status():
    return jsonify(manager.status())


@app.get("/api/events")
def events():
    limit = min(int(request.args.get("limit", 500)), 2000)
    return jsonify(manager.recent_events(request.args.get("q", ""), limit))


@app.get("/api/cef-events")
def cef_events():
    """Raw CEF lines, newest first — what the connector sends to the SIEM."""
    events = manager.recent_events(request.args.get("q", ""), 2000)
    body = "\n".join(e["raw"] for e in events) + "\n"
    if request.args.get("download"):
        return Response(body, content_type="text/plain; charset=utf-8", headers={
            "Content-Disposition": 'attachment; filename="cef-events.log"',
            "Cache-Control": "no-store",
        })
    return Response(body, content_type="text/plain; charset=utf-8")


@app.get("/api/connector-log")
def connector_log():
    return jsonify(manager.connector_log())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
