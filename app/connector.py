"""Runs the official Akamai CEF Connector and captures the CEF events it emits.

The UI settings are rendered into CEFConnector.properties and log4j2.xml (based on
the templates shipped in the connector package). log4j2 is configured with an
extra Socket appender pointing at a local TCP receiver so every event the
connector sends can be shown in the UI, while optionally still being forwarded
to an external SIEM / syslog listener.
"""
import json
import logging
import os
import re
import signal
import socketserver
import subprocess
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from logging.handlers import RotatingFileHandler

import requests
from akamai.edgegrid import EdgeGridAuth

CEF_HOME = os.environ.get("CEF_HOME", "/opt/cefconnector")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
CONFIG_DIR = os.path.join(DATA_DIR, "connector", "config")
WORK_DIR = os.path.join(DATA_DIR, "connector", "work")  # cefconnector.db lives here
LOG_DIR = os.path.join(DATA_DIR, "logs")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
CAPTURE_PORT = int(os.environ.get("CAPTURE_PORT", "5140"))
JAVA_OPTS = os.environ.get("JAVA_OPTS", "-Xms256m -Xmx1024m").split()

SECRET_FIELDS = ("client_token", "client_secret", "access_token")

DEFAULTS = {
    "base_url": "",
    "client_token": "",
    "client_secret": "",
    "access_token": "",
    "config_ids": "",
    "request_url_host": "https://cloudsecurity.akamaiapis.net",
    "refresh_period": 60,
    "limit": 200000,
    "timebased": False,
    "timebased_from": "",
    "timebased_to": "",
    "proxy_host": "",
    "proxy_port": "",
    "consumer_count": 3,
    "retry": 5,
    "forward_enabled": False,
    "forward_host": "listener",
    "forward_port": 8080,
    "forward_protocol": "TCP",
}

# UI setting -> CEFConnector.properties key
PROPERTY_MAP = {
    "request_url_host": "akamai.data.requesturlhost",
    "config_ids": "akamai.data.configs",
    "base_url": "akamai.data.baseurl",
    "access_token": "akamai.data.accesstoken",
    "client_token": "akamai.data.clienttoken",
    "client_secret": "akamai.data.clientsecret",
    "refresh_period": "connector.refresh.period",
    "limit": "akamai.data.limit",
    "timebased": "akamai.data.timebased",
    "timebased_from": "akamai.data.timebased.from",
    "timebased_to": "akamai.data.timebased.to",
    "proxy_host": "connector.proxy.host",
    "proxy_port": "connector.proxy.port",
    "consumer_count": "connector.consumer.count",
    "retry": "connector.retry",
}


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_private(path, text, encoding="utf-8"):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding=encoding) as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------- CEF parsing
_EXT_RE = re.compile(r"(\w+)=((?:\\.|[^\\])*?)(?=\s+\w+=|\s*$)", re.S)


def _unescape(value):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r"}.get(m.group(1), m.group(1)), value)


def parse_cef(line):
    line = line.strip()
    idx = line.find("CEF:")
    if idx < 0:
        return {"raw": line}
    body = line[idx:]
    parts, buf, i = [], "", 0
    while i < len(body) and len(parts) < 7:
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            buf += body[i:i + 2]
            i += 2
            continue
        if ch == "|":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if len(parts) < 7:
        return {"raw": line}
    ext = {k: _unescape(v) for k, v in _EXT_RE.findall(body[i:])}
    header = [_unescape(p) for p in parts]
    return {
        "received": time.time(),
        "vendor": header[1], "product": header[2], "version": header[3],
        "eventClassId": header[4], "name": header[5], "severity": header[6],
        "ext": ext,
        "raw": line,
    }


# ---------------------------------------------------------------- receiver
class _CaptureHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                self.server.manager.record_event(line)


class _CaptureServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ConnectorManager:
    def __init__(self):
        for d in (CONFIG_DIR, WORK_DIR, LOG_DIR):
            os.makedirs(d, exist_ok=True)
        self.lock = threading.Lock()
        self.events = deque(maxlen=int(os.environ.get("EVENT_BUFFER", "2000")))
        self.proc = None
        self.stdout_file = None
        self.settings = {**DEFAULTS, **_read_json(SETTINGS_PATH, {})}
        self.state = {"running": False, "total_events": 0, "started_at": None,
                      "last_event_at": None, "last_exit": None,
                      **_read_json(STATE_PATH, {})}
        self.version = self._detect_version()

        self.event_log = logging.getLogger("cef-events")
        self.event_log.propagate = False
        self.event_log.setLevel(logging.INFO)
        handler = RotatingFileHandler(os.path.join(LOG_DIR, "cef-events.log"),
                                      maxBytes=50 * 1024 * 1024, backupCount=5)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.event_log.addHandler(handler)

        self._preload_events()
        self.capture = _CaptureServer(("127.0.0.1", CAPTURE_PORT), _CaptureHandler)
        self.capture.manager = self
        threading.Thread(target=self.capture.serve_forever, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def _preload_events(self):
        """Refill the in-memory buffer from cef-events.log so a restart keeps history."""
        path = os.path.join(LOG_DIR, "cef-events.log")
        if not os.path.exists(path):
            return
        try:
            with open(path, "rb") as f:
                f.seek(max(0, os.path.getsize(path) - 4_000_000))
                lines = f.read().decode("utf-8", "replace").splitlines()
            for line in lines[-self.events.maxlen:]:
                if line.strip():
                    self.events.append(parse_cef(line))
        except OSError:
            pass

    def _detect_version(self):
        for name in os.listdir(os.path.join(CEF_HOME, "bin")):
            m = re.match(r"CEFConnector-(.+)\.jar$", name)
            if m:
                return m.group(1)
        return "unknown"

    # ------------------------------------------------------------ settings
    def public_settings(self):
        s = dict(self.settings)
        for f in SECRET_FIELDS:
            v = s.get(f) or ""
            s[f] = ("••••" + v[-4:]) if v else ""
        return s

    def update_settings(self, data):
        with self.lock:
            s = dict(self.settings)
            for key, default in DEFAULTS.items():
                if key not in data:
                    continue
                value = data[key]
                if key in SECRET_FIELDS and (not value or str(value).startswith("••••")):
                    continue  # keep stored secret
                if isinstance(default, bool):
                    value = value in (True, "true", "on", "1", 1)
                elif isinstance(default, int):
                    value = int(value)
                else:
                    value = str(value).strip()
                s[key] = value
            s["base_url"] = re.sub(r"^https?://", "", s["base_url"]).rstrip("/")
            if s["base_url"] and not re.search(r"\.(luna|cloudsecurity)\.akamaiapis\.net$", s["base_url"]):
                raise ValueError("Host must end with .luna.akamaiapis.net or .cloudsecurity.akamaiapis.net")
            s["config_ids"] = ";".join(c.strip() for c in re.split(r"[;,\s]+", s["config_ids"]) if c.strip())
            s["forward_protocol"] = "UDP" if s["forward_protocol"].upper() == "UDP" else "TCP"
            for key in ("timebased_from", "timebased_to", "proxy_port"):
                if s[key] and not s[key].isdigit():
                    raise ValueError("{} must be a number".format(key))
            if s["timebased"] and not s["timebased_from"]:
                raise ValueError("timebased_from (epoch seconds) is required when time based is enabled")
            self.settings = s
            _write_private(SETTINGS_PATH, json.dumps(s, indent=2))

    def missing(self):
        return [f for f in ("base_url", "client_token", "client_secret", "access_token", "config_ids")
                if not self.settings.get(f)]

    # ------------------------------------------------------------ rendering
    def build_properties(self):
        with open(os.path.join(CEF_HOME, "config", "CEFConnector.properties"), encoding="latin-1") as f:
            text = f.read()
        for key, prop in PROPERTY_MAP.items():
            value = self.settings[key]
            if isinstance(value, bool):
                value = str(value).lower()
            value = str(value).replace("\\", "\\\\")
            pattern = re.compile(r"^{}=.*$".format(re.escape(prop)), re.M)
            line = "{}={}".format(prop, value)
            if pattern.search(text):
                text = pattern.sub(lambda _: line, text, count=1)
            else:
                text += "\n" + line + "\n"
        return text

    def render_properties(self):
        _write_private(os.path.join(CONFIG_DIR, "CEFConnector.properties"),
                       self.build_properties(), "latin-1")

    def build_standalone_log4j(self):
        """log4j2.xml for running the connector directly on a host: CEF events go
        to the configured SIEM/listener instead of this container's UI receiver."""
        with open(os.path.join(CEF_HOME, "config", "log4j2.xml"), encoding="utf-8") as f:
            text = f.read()
        s = self.settings
        for name, value in (("log-path", "logs"),
                            ("CEFHost", s["forward_host"] if s["forward_enabled"] else "127.0.0.1"),
                            ("CEFPort", str(s["forward_port"]) if s["forward_enabled"] else "514"),
                            ("CEFProtocol", s["forward_protocol"])):
            text = re.sub(r'(<Property name="{}">)[^<]*(</Property>)'.format(name),
                          lambda m, v=value: m.group(1) + v + m.group(2), text)
        return text

    def render_log4j(self):
        tree = ET.parse(os.path.join(CEF_HOME, "config", "log4j2.xml"))
        root = tree.getroot()
        props = {p.get("name"): p for p in root.find("Properties")}
        props["log-path"].text = LOG_DIR
        props["CEFHost"].text = "127.0.0.1"
        props["CEFPort"].text = str(CAPTURE_PORT)
        props["CEFProtocol"].text = "TCP"

        appenders = root.find("Appenders")
        logger = next(l for l in root.find("Loggers") if l.get("name") == "cefsyslog")
        if self.settings["forward_enabled"]:
            ET.SubElement(appenders, "Socket", {
                "name": "cefforward",
                "host": self.settings["forward_host"],
                "port": str(self.settings["forward_port"]),
                "protocol": self.settings["forward_protocol"],
                "ignoreExceptions": "true",
            }).append(ET.Element("PatternLayout", {"pattern": "${logPattern-CEF}"}))
            ET.SubElement(logger, "AppenderRef", {"ref": "cefforward", "level": "SYSLOG"})
        tree.write(os.path.join(CONFIG_DIR, "log4j2.xml"), encoding="UTF-8", xml_declaration=True)

    # ------------------------------------------------------------ process
    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        missing = self.missing()
        if missing:
            return False, "Missing: " + ", ".join(missing)
        with self.lock:
            if self.is_running():
                return True, "Already running"
            self.render_properties()
            self.render_log4j()
            jar = os.path.join(CEF_HOME, "bin", "CEFConnector-{}.jar".format(self.version))
            classpath = ":".join([CONFIG_DIR, jar, os.path.join(CEF_HOME, "lib", "*")])
            cmd = ["java", "-Dfile.encoding=UTF-8", *JAVA_OPTS,
                   "-Dlog4j.configurationFile=" + os.path.join(CONFIG_DIR, "log4j2.xml"),
                   "-cp", classpath, "net.meta.cefconnector.CEFConnectorApp"]
            if self.stdout_file:
                self.stdout_file.close()
            self.stdout_file = open(os.path.join(LOG_DIR, "connector-stdout.log"), "ab")
            self.stdout_file.write("\n==== {} starting CEF Connector {} ====\n".format(
                time.strftime("%Y-%m-%d %H:%M:%S"), self.version).encode())
            self.stdout_file.flush()
            self.proc = subprocess.Popen(cmd, cwd=WORK_DIR, stdout=self.stdout_file,
                                         stderr=subprocess.STDOUT)
            self.state.update(running=True, started_at=time.time(), last_exit=None)
            self._save_state()
        return True, "Started (pid {})".format(self.proc.pid)

    def stop(self):
        with self.lock:
            self.state["running"] = False
            self._save_state()
            if not self.is_running():
                return True, "Not running"
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        return True, "Stopped"

    def reset_db(self):
        if self.is_running():
            return False, "Stop the connector before resetting the offset DB"
        db = os.path.join(WORK_DIR, "cefconnector.db")
        if os.path.exists(db):
            os.remove(db)
            return True, "cefconnector.db removed — next start pulls without a saved offset"
        return True, "No offset DB present"

    def _watch(self):
        saved_total = self.state["total_events"]
        while True:
            time.sleep(5)
            proc = self.proc
            changed = self.state["total_events"] != saved_total
            if proc is not None and proc.poll() is not None and self.state.get("last_exit") is None \
                    and self.state.get("started_at"):
                self.state["last_exit"] = proc.returncode
                changed = True
            if changed:
                saved_total = self.state["total_events"]
                with self.lock:
                    self._save_state()

    def _save_state(self):
        _write_private(STATE_PATH, json.dumps(self.state))

    # ------------------------------------------------------------ events
    def record_event(self, line):
        event = parse_cef(line)
        self.event_log.info(line)
        with self.lock:
            self.events.append(event)
            self.state["total_events"] += 1
            self.state["last_event_at"] = time.time()

    def recent_events(self, query="", limit=500):
        with self.lock:
            events = list(self.events)
        events.reverse()
        if query:
            q = query.lower()
            events = [e for e in events if q in e["raw"].lower()]
        return events[:limit]

    def status(self):
        s = dict(self.state)
        s["running"] = self.is_running()
        s["pid"] = self.proc.pid if self.is_running() else None
        s["buffered"] = len(self.events)
        s["version"] = self.version
        s["offset_db"] = os.path.exists(os.path.join(WORK_DIR, "cefconnector.db"))
        s["forwarding"] = ("{}:{}/{}".format(self.settings["forward_host"], self.settings["forward_port"],
                                             self.settings["forward_protocol"])
                           if self.settings["forward_enabled"] else None)
        return s

    def connector_log(self, lines=200):
        out = []
        for name in ("connector-stdout.log", "cefconnector.log"):
            path = os.path.join(LOG_DIR, name)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    f.seek(max(0, os.path.getsize(path) - 200_000))
                    tail = f.read().decode("utf-8", "replace").splitlines()[-lines:]
                out.append({"file": name, "lines": tail})
        return out

    # ------------------------------------------------------------ test
    def test_connection(self):
        missing = self.missing()
        if missing:
            return False, "Missing: " + ", ".join(missing)
        s = self.settings
        session = requests.Session()
        session.auth = EdgeGridAuth(client_token=s["client_token"], client_secret=s["client_secret"],
                                    access_token=s["access_token"])
        if s["proxy_host"]:
            proxy = "http://{}:{}".format(s["proxy_host"], s["proxy_port"] or 3128)
            session.proxies = {"http": proxy, "https": proxy}
        url = "https://{}/siem/v1/configs/{}".format(s["base_url"], urllib.parse.quote(s["config_ids"], safe=""))
        try:
            r = session.get(url, params={"from": int(time.time()) - 300, "limit": 1}, timeout=(15, 120))
        except requests.RequestException as e:
            return False, "Connection failed: {}".format(e)
        if r.status_code == 200:
            return True, "OK: credentials accepted, SIEM API reachable for config(s) {}".format(s["config_ids"])
        return False, "HTTP {}: {}".format(r.status_code, r.text[:500])
