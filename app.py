"""Lantern Discovery Assistant: local, dependency-free prototype server."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from io import BytesIO
import json
import os
import re
import urllib.error
import urllib.request
import uuid
import webbrowser
import base64
from datetime import datetime
import hashlib
import hmac
import secrets
import sqlite3
import math
from http.cookies import SimpleCookie
from urllib.parse import unquote, urlsplit
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "dist" if (ROOT / "dist").is_dir() else ROOT
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

def load_dotenv():
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))

load_dotenv()
DATA = Path(os.getenv("DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
DATA.mkdir(parents=True, exist_ok=True)
TEAM_MODE = os.getenv("TEAM_MODE", "0").strip().lower() in ("1", "true", "yes")
AUTH_DB = DATA / "accounts.sqlite3"
SETTINGS_FILE = DATA / "lantern-settings.json"

def read_settings():
    try:
        value = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            value = {}
    except (OSError, ValueError, TypeError, AttributeError):
        value = {}
    try:
        days = int(value.get("retentionDays", 0))
    except (ValueError, TypeError):
        days = 0
    model = str(value.get("aiModel") or os.getenv("AI_MODEL", "gpt-4o-mini")).strip()[:100] or "gpt-4o-mini"
    rates = {}
    for setting, env_name in (("inputRate", "AI_INPUT_USD_PER_MILLION"), ("outputRate", "AI_OUTPUT_USD_PER_MILLION")):
        raw = value.get(setting, os.getenv(env_name))
        try:
            rate = float(raw)
            rates[setting] = rate if math.isfinite(rate) and 0 <= rate <= 10000 else None
        except (ValueError, TypeError):
            rates[setting] = None
    return {"retentionDays": days if days in (0, 30, 90, 365) else 0, "aiModel": model, **rates}

def apply_retention():
    days = read_settings()["retentionDays"]
    if not days:
        return
    cutoff = datetime.now().astimezone().timestamp() - days * 24 * 60 * 60
    for path in DATA.glob("*.json"):
        try:
            project = json.loads(path.read_text(encoding="utf-8"))
            updated = datetime.fromisoformat(project.get("updatedAt", "")).timestamp()
            if updated < cutoff and project.get("id") and path.stem == str(project["id"]):
                path.unlink()
        except (OSError, ValueError, TypeError, AttributeError):
            continue

def auth_connection():
    con = sqlite3.connect(AUTH_DB)
    con.row_factory = sqlite3.Row
    return con

def initialize_team_auth():
    with auth_connection() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, created_at TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL)")
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            username = os.getenv("ADMIN_USERNAME", "lantern-admin").strip()
            password = os.getenv("ADMIN_PASSWORD", "").strip()
            if len(password) < 14 or password.lower() in ("password", "changeme", "choose_a_long_random_password"):
                raise RuntimeError("TEAM_MODE requires a unique ADMIN_PASSWORD of at least 14 characters in .env before the server can start.")
            salt = secrets.token_bytes(16)
            digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
            con.execute("INSERT INTO users VALUES (?, ?, 'admin', ?, ?, ?)", (username, "Lantern Administrator", salt, digest, datetime.now().astimezone().isoformat(timespec="seconds")))

if TEAM_MODE:
    initialize_team_auth()

def password_matches(password, salt, digest):
    candidate = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate, digest)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def send_json(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def current_account(self):
        if not TEAM_MODE:
            return None
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookies.get("lantern_session")
        if not morsel:
            return None
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        with auth_connection() as con:
            row = con.execute("SELECT s.csrf, s.expires_at, u.username, u.display_name, u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=?", (token_hash,)).fetchone()
            if not row or row["expires_at"] < int(__import__("time").time()):
                con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
        return dict(row)

    def require_csrf(self, account):
        if TEAM_MODE and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), account.get("csrf", "")):
            self.send_json(403, {"error": "Security token expired. Refresh the page and sign in again."})
            return False
        return True

    @staticmethod
    def public_account(row):
        return {"username": row["username"], "displayName": row["display_name"], "role": row["role"], "createdAt": row["created_at"]}

    def create_login(self, payload):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        with auth_connection() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row or not password_matches(password, row["salt"], row["password_hash"]):
                return self.send_json(401, {"error": "Username or password was not recognized."})
            token = secrets.token_urlsafe(36)
            csrf = secrets.token_urlsafe(24)
            con.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)", (hashlib.sha256(token.encode()).hexdigest(), username, csrf, int(__import__("time").time()) + 7 * 24 * 60 * 60))
        body = json.dumps({"authenticated": True, "teamMode": True, "csrf": csrf, "user": {"username": row["username"], "displayName": row["display_name"], "role": row["role"]}}).encode()
        self.send_response(200)
        cookie = f"lantern_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800"
        if os.getenv("COOKIE_SECURE", "0").strip().lower() in ("1", "true", "yes"):
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def manage_users(self, payload):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        display_name = str(payload.get("displayName", "")).strip() or username
        role = str(payload.get("role", "analyst"))
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
            return self.send_json(400, {"error": "Username must be 3–64 characters (letters, numbers, dot, underscore, @ or hyphen)."})
        if len(password) < 14:
            return self.send_json(400, {"error": "Use a unique password with at least 14 characters."})
        if role not in ("admin", "analyst", "reviewer"):
            return self.send_json(400, {"error": "Choose the admin, analyst or reviewer role."})
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        with auth_connection() as con:
            try:
                con.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (username, display_name, role, salt, digest, datetime.now().astimezone().isoformat(timespec="seconds")))
            except sqlite3.IntegrityError:
                return self.send_json(409, {"error": "That username already exists."})
        return self.send_json(201, {"username": username, "displayName": display_name, "role": role})

    def do_GET(self):
        decoded_path = unquote(urlsplit(self.path).path)
        safe_static = {"/", "/index.html"}
        if decoded_path in ("/.env", "/.env.example", "/app.py", "/README.md", "/START-HERE.txt") or decoded_path.startswith(("/data/", "/__pycache__/")):
            return self.send_error(404)
        asset_match = re.fullmatch(r"/assets/([A-Za-z0-9_-]+\.(?:js|css)|lantern-logo\.jpeg)", decoded_path)
        safe_asset = bool(asset_match and (WEB_ROOT / "assets" / asset_match.group(1)).is_file())
        if TEAM_MODE and not decoded_path.startswith("/api/") and decoded_path not in safe_static and not safe_asset:
            return self.send_error(404)
        if self.path == "/api/settings":
            if TEAM_MODE and not self.current_account():
                return self.send_json(401, {"error": "Sign in to continue."})
            return self.send_json(200, read_settings())
        if self.path == "/api/reviewers":
            account = self.current_account()
            if not account:
                return self.send_json(401, {"error": "Sign in to continue."})
            with auth_connection() as con:
                rows = con.execute("SELECT username, display_name FROM users WHERE role='reviewer' ORDER BY display_name")
                return self.send_json(200, [{"username": row["username"], "displayName": row["display_name"]} for row in rows])
        if self.path == "/api/session" and not TEAM_MODE:
            return self.send_json(200, {"teamMode": False, "authenticated": True, "user": {"username": "local", "displayName": "Local user", "role": "admin"}, "csrf": ""})
        if TEAM_MODE and self.path == "/api/session":
            account = self.current_account()
            return self.send_json(200, {"teamMode": True, "authenticated": bool(account), "user": {"username": account["username"], "displayName": account["display_name"], "role": account["role"]} if account else None, "csrf": account["csrf"] if account else ""})
        if TEAM_MODE and self.path == "/api/users":
            account = self.current_account()
            if not account:
                return self.send_json(401, {"error": "Sign in to continue."})
            if account["role"] != "admin":
                return self.send_json(403, {"error": "Only administrators can manage accounts."})
            with auth_connection() as con:
                return self.send_json(200, [self.public_account(row) for row in con.execute("SELECT username, display_name, role, created_at FROM users ORDER BY username")])
        if TEAM_MODE and self.path.startswith("/api/") and self.path != "/api/login":
            account = self.current_account()
            if not account:
                return self.send_json(401, {"error": "Sign in to continue."})
            if self.path == "/api/backup" and account["role"] != "admin":
                return self.send_json(403, {"error": "Only administrators can export all project records."})
        if TEAM_MODE and self.path == "/api/login":
            return self.send_json(405, {"error": "Use POST to sign in."})
        if self.path == "/api/backup":
            return self.export_backup()
        if self.path == "/api/projects":
            apply_retention()
            items = []
            for p in sorted(DATA.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    project = json.loads(p.read_text(encoding="utf-8"))
                    items.append({"id": project["id"], "name": project["name"], "updatedAt": project.get("updatedAt"), "status": project.get("status", "Draft"), "version": project.get("version", 1), "archived": project.get("archived", False)})
                except (ValueError, KeyError):
                    continue
            return self.send_json(200, items)
        if self.path.startswith("/api/projects/") and self.path.endswith("/history"):
            project_id = self.path.split("/")[3]
            path = DATA / f"{project_id}.json"
            if not path.exists():
                return self.send_json(404, {"error": "Project not found"})
            project = json.loads(path.read_text(encoding="utf-8"))
            versions = list(project.get("history", []))
            versions.append({key: project.get(key) for key in ("version", "updatedAt", "status", "reviewer", "approvedAt", "name", "context", "answers", "docs", "mode", "templateId", "reviewComments", "assignedReviewer", "usageEntries")})
            versions.sort(key=lambda item: int(item.get("version") or 0), reverse=True)
            return self.send_json(200, versions)
        if self.path.startswith("/api/projects/"):
            pid = self.path.rsplit("/", 1)[-1]
            path = DATA / f"{pid}.json"
            if path.exists():
                return self.send_json(200, json.loads(path.read_text(encoding="utf-8")))
            return self.send_json(404, {"error": "Project not found"})
        return super().do_GET()

    def do_POST(self):
        if self.path not in ("/api/analyze", "/api/demo", "/api/save", "/api/export/word", "/api/export/pdf", "/api/import-backup", "/api/archive", "/api/revise", "/api/handoff", "/api/login", "/api/logout", "/api/users", "/api/settings"):
            return self.send_json(404, {"error": "Not found"})
        if not TEAM_MODE and self.path in ("/api/login", "/api/logout", "/api/users"):
            return self.send_json(404, {"error": "Team accounts are disabled in this local-only configuration."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 30 * 1024 * 1024:
                return self.send_json(413, {"error": "The uploaded backup is too large (30 MB limit)."})
            payload = json.loads(self.rfile.read(length))
            if TEAM_MODE and self.path == "/api/login":
                return self.create_login(payload)
            account = self.current_account() if TEAM_MODE else None
            if TEAM_MODE:
                if not account:
                    return self.send_json(401, {"error": "Sign in to continue."})
                if not self.require_csrf(account):
                    return
                if self.path == "/api/logout":
                    token = SimpleCookie(self.headers.get("Cookie", "")).get("lantern_session")
                    if token:
                        with auth_connection() as con:
                            con.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.value.encode()).hexdigest(),))
                    self.send_response(200)
                    self.send_header("Set-Cookie", "lantern_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/api/users":
                    if account["role"] != "admin":
                        return self.send_json(403, {"error": "Only administrators can manage accounts."})
                    return self.manage_users(payload)
                if self.path == "/api/archive" and account["role"] != "admin":
                    return self.send_json(403, {"error": "Only administrators can archive or restore projects."})
                if self.path == "/api/settings" and account["role"] != "admin":
                    return self.send_json(403, {"error": "Only administrators can change data-retention settings."})
                if self.path in ("/api/backup", "/api/import-backup") and account["role"] != "admin":
                    return self.send_json(403, {"error": "Only administrators can manage full project backups."})
                if self.path in ("/api/analyze", "/api/revise", "/api/handoff") and account["role"] == "reviewer":
                    return self.send_json(403, {"error": "Reviewer accounts cannot generate AI documents."})
                if self.path == "/api/save" and payload.get("status") == "Approved":
                    if account["role"] not in ("admin", "reviewer"):
                        return self.send_json(403, {"error": "Only reviewers and administrators can approve a project."})
                if self.path == "/api/save" and account["role"] == "reviewer":
                    project_id = str(payload.get("id", ""))
                    existing_path = DATA / f"{project_id}.json" if project_id.isalnum() else None
                    try:
                        existing_assignment = json.loads(existing_path.read_text(encoding="utf-8")).get("assignedReviewer", "") if existing_path and existing_path.exists() else ""
                    except (OSError, ValueError, TypeError):
                        existing_assignment = ""
                    if payload.get("status") == "Approved" and existing_assignment != account["username"]:
                        return self.send_json(403, {"error": "This project must be assigned to your reviewer account before you approve it."})
                    # A reviewer cannot assign a project to themselves through a crafted request.
                    payload["assignedReviewer"] = existing_assignment
            if self.path == "/api/analyze":
                return self.analyze(payload)
            if self.path == "/api/demo":
                return self.demo(payload)
            if self.path == "/api/export/word":
                return self.export_word(payload)
            if self.path == "/api/export/pdf":
                return self.export_pdf(payload)
            if self.path == "/api/import-backup":
                return self.import_backup(payload)
            if self.path == "/api/archive":
                return self.archive_project(payload)
            if self.path == "/api/settings":
                try:
                    days = int(payload.get("retentionDays", 0))
                except (ValueError, TypeError):
                    days = -1
                if days not in (0, 30, 90, 365):
                    return self.send_json(400, {"error": "Choose never, 30, 90 or 365 days."})
                current = read_settings()
                model = str(payload.get("aiModel", current["aiModel"])).strip()
                if not model or len(model) > 100 or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", model):
                    return self.send_json(400, {"error": "Enter a valid AI model name."})
                rates = {}
                for key in ("inputRate", "outputRate"):
                    raw = payload.get(key, current[key])
                    if raw in (None, ""):
                        rates[key] = None
                        continue
                    try:
                        rate = float(raw)
                    except (ValueError, TypeError):
                        return self.send_json(400, {"error": "AI token prices must be valid non-negative numbers."})
                    if not math.isfinite(rate) or not 0 <= rate <= 10000:
                        return self.send_json(400, {"error": "AI token prices must be between 0 and 10000 USD per million."})
                    rates[key] = rate
                temporary = SETTINGS_FILE.with_suffix(".tmp")
                temporary.write_text(json.dumps({"retentionDays": days, "aiModel": model, **rates}, indent=2), encoding="utf-8")
                temporary.replace(SETTINGS_FILE)
                apply_retention()
                return self.send_json(200, read_settings())
            if self.path == "/api/revise":
                return self.revise(payload)
            if self.path == "/api/handoff":
                return self.handoff(payload)
            return self.save(payload)
        except (ValueError, KeyError, TypeError) as exc:
            return self.send_json(400, {"error": str(exc)})

    def do_DELETE(self):
        if TEAM_MODE:
            account = self.current_account()
            if not account:
                return self.send_json(401, {"error": "Sign in to continue."})
            if not self.require_csrf(account):
                return
            user_match = re.fullmatch(r"/api/users/([A-Za-z0-9_.@-]+)", self.path)
            if user_match:
                if account["role"] != "admin":
                    return self.send_json(403, {"error": "Only administrators can manage accounts."})
                username = user_match.group(1)
                if username == account["username"]:
                    return self.send_json(400, {"error": "You cannot delete the account currently signed in."})
                with auth_connection() as con:
                    con.execute("DELETE FROM sessions WHERE username=?", (username,))
                    result = con.execute("DELETE FROM users WHERE username=?", (username,))
                return self.send_json(200 if result.rowcount else 404, {"deleted": username})
            if account["role"] != "admin":
                return self.send_json(403, {"error": "Only administrators can permanently delete projects."})
        match = re.fullmatch(r"/api/projects/([A-Za-z0-9]+)", self.path)
        if not match:
            return self.send_json(404, {"error": "Not found"})
        project_id = match.group(1)
        path = DATA / f"{project_id}.json"
        if not path.exists():
            return self.send_json(404, {"error": "Project not found"})
        path.unlink()
        return self.send_json(200, {"deleted": project_id})

    def archive_project(self, payload):
        project_id = str(payload.get("id", ""))
        if not project_id.isalnum():
            return self.send_json(400, {"error": "Invalid project ID"})
        path = DATA / f"{project_id}.json"
        if not path.exists():
            return self.send_json(404, {"error": "Project not found"})
        project = json.loads(path.read_text(encoding="utf-8"))
        project["archived"] = bool(payload.get("archived", True))
        audit = list(project.get("audit") or [])
        audit.append({"action": "Archived" if project["archived"] else "Restored from archive", "actor": payload.get("actor") or "Lantern team", "at": datetime.now().astimezone().isoformat(timespec="seconds")})
        project["audit"] = audit[-200:]
        path.write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
        return self.send_json(200, project)

    def call_ai_json(self, prompt, expected):
        key = os.getenv("AI_API_KEY", "").strip()
        if not key or key == "replace_with_your_api_key":
            raise RuntimeError("AI_API_KEY is not set. Add the OpenAI API key to .env and restart the server.")
        base = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        model = read_settings()["aiModel"]
        request_body = json.dumps({"model": model, "messages": [{"role": "system", "content": "Return valid JSON only."}, {"role": "user", "content": prompt}], "response_format": {"type": "json_object"}, "temperature": 0.2}).encode()
        request = urllib.request.Request(base + "/chat/completions", data=request_body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read())
            result = json.loads(data["choices"][0]["message"]["content"])
            if any(not result.get(key) for key in expected):
                raise ValueError("The AI response omitted a required document.")
            return result, model, data.get("usage", {})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise RuntimeError(f"AI provider returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Could not reach the AI provider: {exc}") from exc
        except (KeyError, IndexError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"Could not read the AI response: {exc}") from exc

    def revise(self, payload):
        if payload.get("consent") is not True:
            return self.send_json(400, {"error": "Confirm that the notes are approved for this AI service before generating a revision."})
        docs = payload.get("docs", {})
        feedback = str(payload.get("feedback", "")).strip()
        if not feedback:
            return self.send_json(400, {"error": "Add reviewer or client feedback before requesting a revision."})
        prompt = f'''Revise the two Lantern discovery drafts using the client interview notes and the feedback. Preserve supported facts and citations; do not invent facts. Mark unresolved uncertainty as an assumption or open question. Return JSON with exactly two Markdown string properties: requirements_summary and prototype_plan. In the requirements summary include sections named exactly ## Assumptions to validate and ## Open questions / missing details.\n\nProject: {payload.get('name','Untitled project')}\nInterview answers: {json.dumps(payload.get('answers', []), ensure_ascii=False)}\nCurrent requirements summary:\n{docs.get('requirementsSummary','')}\nCurrent prototype plan:\n{docs.get('prototypePlan','')}\nReviewer/client feedback:\n{feedback}'''
        try:
            result, model, usage = self.call_ai_json(prompt, ("requirements_summary", "prototype_plan"))
            return self.send_json(200, {"requirementsSummary": result["requirements_summary"], "prototypePlan": result["prototype_plan"], "model": model, "usage": usage, "mode": "openai"})
        except RuntimeError as exc:
            return self.send_json(502, {"error": str(exc)})

    def handoff(self, payload):
        if payload.get("consent") is not True:
            return self.send_json(400, {"error": "Confirm that the notes are approved for this AI service before generating a handoff."})
        docs = payload.get("docs", {})
        prompt = f'''Prepare a developer handoff draft based only on these reviewed Lantern documents. Do not invent existing infrastructure or integrations. Label recommendations and assumptions clearly; cite interview question sources when present. Return JSON with one string property technical_handoff containing Markdown sections: Scope and goals, User roles, Suggested data model, API and integrations, Security and privacy considerations, Development tasks, Acceptance checks, Assumptions and decisions needed.\n\nProject: {payload.get('name','Untitled project')}\nRequirements summary:\n{docs.get('requirementsSummary','')}\nPrototype plan:\n{docs.get('prototypePlan','')}'''
        try:
            result, model, usage = self.call_ai_json(prompt, ("technical_handoff",))
            return self.send_json(200, {"technicalHandoff": result["technical_handoff"], "model": model, "usage": usage})
        except RuntimeError as exc:
            return self.send_json(502, {"error": str(exc)})

    @staticmethod
    def pdf_string(value):
        data = str(value).encode("cp1252", errors="replace")
        parts = []
        for byte in data:
            if byte in (40, 41, 92):
                parts.append("\\" + chr(byte))
            elif byte < 32 or byte > 126:
                parts.append(f"\\{byte:03o}")
            else:
                parts.append(chr(byte))
        return "(" + "".join(parts) + ")"

    def export_pdf(self, payload):
        docs = payload.get("docs", {})
        selected = payload.get("documentKey")
        keys = [selected] if selected else [key for key in ("requirementsSummary", "prototypePlan", "technicalHandoff") if docs.get(key)]
        if not keys or any(key not in ("requirementsSummary", "prototypePlan", "technicalHandoff") or not docs.get(key) for key in keys):
            return self.send_json(400, {"error": "Generate the selected document before downloading the PDF."})
        pages = []
        page = []
        y = 790

        def add_line(text, size=10, bold=False, gap=14):
            nonlocal page, y
            if y < 54:
                pages.append(page)
                page, y = [], 790
            font = "F1" if bold else "F0"
            page.append(f"BT /{font} {size} Tf 48 {y} Td {self.pdf_string(text)} Tj ET")
            y -= gap

        add_line("Lantern Discovery Documents", 20, True, 30)
        add_line(payload.get("name") or "Untitled project", 13, True, 22)
        mode = payload.get("mode")
        caption = "LOCAL DEMO TEMPLATE - NOT AI-GENERATED" if mode == "demo" else "OPENAI FIRST DRAFT - REVIEW REQUIRED"
        add_line("INTERNAL  |  " + caption, 8, True, 14)
        status = payload.get("status") or "Draft"
        reviewer = payload.get("reviewer") or "not assigned"
        add_line(f"Status: {status}  |  Reviewer: {reviewer}", 8, False, 25)
        if payload.get("coverPage"):
            pages.append(page)
            page, y = [], 790

        for index, key in enumerate(keys):
            if index:
                pages.append(page)
                page, y = [], 790
            raw_lines = str(docs[key]).splitlines()
            for raw in raw_lines:
                line = raw.strip()
                if not line or line == "---":
                    y -= 4
                    continue
                if line.startswith("# "):
                    add_line(line[2:], 17, True, 24)
                elif line.startswith("## "):
                    add_line(line[3:], 12, True, 18)
                elif line.startswith("### "):
                    add_line(line[4:], 11, True, 16)
                else:
                    if line.startswith(("- ", "* ")):
                        line = "•  " + line[2:]
                    line = re.sub(r"\*\*|`", "", line)
                    width = 88
                    while len(line) > width:
                        split_at = line.rfind(" ", 0, width + 1)
                        split_at = split_at if split_at > 0 else width
                        add_line(line[:split_at], 9, False, 13)
                        line = "    " + line[split_at:].lstrip()
                    add_line(line, 9, False, 13)
        if page:
            pages.append(page)

        objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            None,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        ]
        page_refs = []
        for commands in pages:
            stream = "\n".join(commands).encode("ascii")
            page_id = len(objects) + 1
            stream_id = page_id + 1
            page_refs.append(f"{page_id} 0 R")
            objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F0 3 0 R /F1 4 0 R >> >> /Contents {stream_id} 0 R >>")
            objects.append((f"<< /Length {len(stream)} >>\nstream\n").encode("ascii") + stream + b"\nendstream")
        objects[1] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>"
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, obj in enumerate(objects, 1):
            offsets.append(len(out))
            body = obj if isinstance(obj, bytes) else obj.encode("ascii")
            out.extend(f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n")
        xref = len(out)
        out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
        for offset in offsets[1:]:
            out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        out.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii"))
        data = bytes(out)
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", 'attachment; filename="Lantern-Discovery-Documents.pdf"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def export_backup(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            manifest = {"format": "lantern-discovery-backup", "version": 1, "createdAt": datetime.now().astimezone().isoformat(timespec="seconds")}
            archive.writestr("lantern-backup/manifest.json", json.dumps(manifest, indent=2))
            for path in DATA.glob("*.json"):
                if path.stem.isalnum():
                    archive.write(path, f"lantern-backup/projects/{path.name}")
        data = output.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", 'attachment; filename="Lantern-Projects-Backup.zip"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def import_backup(self, payload):
        encoded = payload.get("file", "")
        if not encoded:
            return self.send_json(400, {"error": "Choose a Lantern backup ZIP first."})
        try:
            archive_bytes = base64.b64decode(encoded, validate=True)
            if len(archive_bytes) > 20 * 1024 * 1024:
                return self.send_json(413, {"error": "The backup ZIP is too large (20 MB limit)."})
            imported = skipped = 0
            with ZipFile(BytesIO(archive_bytes)) as archive:
                try:
                    manifest = json.loads(archive.read("lantern-backup/manifest.json"))
                    if not isinstance(manifest, dict) or manifest.get("format") != "lantern-discovery-backup":
                        raise ValueError("Backup type not recognized")
                except (KeyError, ValueError) as exc:
                    return self.send_json(400, {"error": f"This ZIP is not a Lantern projects backup: {exc}"})
                expanded_total = 0
                for item in archive.infolist():
                    match = re.fullmatch(r"lantern-backup/projects/([A-Za-z0-9]+)\.json", item.filename)
                    if not match or item.file_size > 10 * 1024 * 1024:
                        continue
                    expanded_total += item.file_size
                    if expanded_total > 20 * 1024 * 1024:
                        return self.send_json(413, {"error": "The expanded backup exceeds the 20 MB restore limit."})
                    project_id = match.group(1)
                    try:
                        project = json.loads(archive.read(item))
                    except (ValueError, KeyError, RuntimeError):
                        skipped += 1
                        continue
                    if not isinstance(project, dict) or project.get("id") != project_id:
                        skipped += 1
                        continue
                    destination = DATA / f"{project_id}.json"
                    if destination.exists():
                        skipped += 1
                        continue
                    destination.write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
                    imported += 1
            return self.send_json(200, {"imported": imported, "skipped": skipped})
        except (BadZipFile, ValueError, OSError) as exc:
            return self.send_json(400, {"error": f"That file is not a valid Lantern backup ZIP: {exc}"})

    def analyze(self, payload):
        if payload.get("consent") is not True:
            return self.send_json(400, {"error": "Confirm that these notes are approved for the configured AI service."})
        key = os.getenv("AI_API_KEY", "").strip()
        if not key or key == "replace_with_your_api_key":
            return self.send_json(503, {"error": "AI_API_KEY is not set. Add your OpenAI API key to the .env file and restart the server."})
        answers = payload.get("answers", [])
        if not any(str(a.get("answer", "")).strip() for a in answers):
            return self.send_json(400, {"error": "Add interview answers before generating documents."})
        questions = "\n".join(f"{i+1}. {a.get('question','')}\n   Interview notes: {a.get('answer','(not answered)')}" for i, a in enumerate(answers))
        prompt = f'''You are Lantern Intelligence Solutions' internal discovery assistant. Turn interview notes into a careful, useful first draft. Do not invent facts. Distinguish confirmed information from assumptions and open questions. Recommend a focused prototype that addresses the underlying business problems, not just a list of requested features. Use clear, practical language. Return ONLY valid JSON with exactly two string properties: requirements_summary and prototype_plan. Use Markdown inside each string.\n\nClient / project: {payload.get('name','Untitled project')}\nBusiness context: {payload.get('context','')}\nInterview questions and notes (keep these Q numbers as source references):\n{questions}\n\nThe requirements summary should cover: business overview, current process, pain points, desired outcomes, proposed solution, user roles, functional requirements, constraints and an evidence/source map. Include separate Markdown sections titled exactly ## Assumptions to validate and ## Open questions / missing details. List unanswered interview questions in the latter and do not treat missing information as fact. The prototype plan should cover: prototype objective, suggested screens and user journey, core features, sample data, assumptions, and acceptance checks. Mark uncertain points clearly. For each key requirement, feature, or recommendation, cite its supporting source as [Source: Q#]. If it is inferred rather than explicitly stated, label it [Assumption] and say which answers informed it. Do not create a source citation if the notes do not support it. Include a short evidence/source map so a reviewer can trace recommendations back to the interview.'''
        base = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        model = read_settings()["aiModel"]
        request_body = json.dumps({"model": model, "messages": [{"role": "system", "content": "Return valid JSON only."}, {"role": "user", "content": prompt}], "response_format": {"type": "json_object"}, "temperature": 0.2}).encode()
        request = urllib.request.Request(base + "/chat/completions", data=request_body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = json.loads(response.read())
            content = data["choices"][0]["message"]["content"]
            result = json.loads(content)
            if not result.get("requirements_summary") or not result.get("prototype_plan"):
                raise ValueError("The AI response did not contain both documents.")
            return self.send_json(200, {"requirementsSummary": result["requirements_summary"], "prototypePlan": result["prototype_plan"], "model": model, "usage": data.get("usage", {})})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            return self.send_json(502, {"error": f"AI provider returned HTTP {exc.code}: {detail}"})
        except (urllib.error.URLError, TimeoutError) as exc:
            return self.send_json(502, {"error": f"Could not reach the AI provider: {exc}"})
        except (KeyError, IndexError, json.JSONDecodeError, ValueError) as exc:
            return self.send_json(502, {"error": f"Could not read the AI response: {exc}"})

    def demo(self, payload):
        """Create transparent, local template drafts so the review workflow can be tried without API credits."""
        answers = payload.get("answers", [])
        if not any(str(a.get("answer", "")).strip() for a in answers):
            return self.send_json(400, {"error": "Add at least one interview answer before creating a demo draft."})

        def note(index):
            if index < len(answers):
                answer = str(answers[index].get("answer", "")).strip()
                if answer:
                    return answer
            return "Not captured in the interview notes."

        unanswered = [f"- Q{i+1}: {a.get('question', f'Question {i+1}')}" for i, a in enumerate(answers) if not str(a.get("answer", "")).strip()]
        open_questions = "\n".join(unanswered) if unanswered else "- No interview answers were left blank. Ask follow-up questions for any inferred or uncertain details."

        project = str(payload.get("name", "Untitled project")).strip() or "Untitled project"
        summary = f'''# Requirements Summary

**Client / project:** {project}  
**Draft type:** Local demonstration template — not AI-generated

## Business overview · Source Q1
{note(0)}

## Current process · Source Q2
{note(1)}

## People and user roles · Source Q3
{note(2)}

## Pain points · Source Q4
{note(3)}

## Current tools and systems · Source Q5
{note(4)}

## Information to manage · Source Q6
{note(5)}

## Desired outcomes · Source Q7
{note(6)}

## Rules and constraints · Source Q8
{note(7)}

## First-version priorities · Source Q9
{note(8)}

## Additional discovery notes · Source Q10
{note(9)}

## Evidence map
- Business overview: Q1
- Current process: Q2
- User roles: Q3
- Pain points: Q4
- Existing tools: Q5
- Information needs: Q6
- Desired outcomes: Q7
- Rules and constraints: Q8
- First-version priorities: Q9
- Additional discovery: Q10

## Review checklist
- Confirm this summary accurately reflects what the client said.
- Resolve any items marked “Not captured” with the client.
- Validate the proposed scope, roles, privacy needs, and integrations before development.

## Assumptions to validate
- Confirm that any proposed workflow or feature reflects the client's actual process.
- Confirm user permissions, privacy needs, integrations, and exception paths before building.

## Open questions / missing details
{open_questions}

---
*This local demonstration document places interview notes into a template. It does not interpret them or call an AI model.*'''
        plan = f'''# Prototype Plan

**Client / project:** {project}  
**Draft type:** Local demonstration template — not AI-generated

## Prototype objective · Source Q7
Demonstrate a small first version that could support this desired outcome, once Lantern has validated it: {note(6)}

## Current workflow to reflect · Source Q2
{note(1)}

## Users to consider · Source Q3
{note(2)}

## Candidate first-version priorities · Source Q9
{note(8)}

## Candidate screens for discussion
These are generic placeholders for review, not AI recommendations. Adjust them to match the validated workflow.
1. **Home / work list:** show current items and their status.
2. **Create or update item:** capture the information identified in the interview.
3. **Item details:** show the recorded information and relevant history.
4. **Review / approval:** include only if the client's process requires it.

## Constraints and existing tools · Sources Q5 and Q8
{note(7)}

Current tools mentioned: {note(4)}

## Sample data
Use fictional sample records only. Do not use real client or personal information in the prototype until an approved privacy approach is in place.

## Assumptions to validate before building
- Confirm the user roles and permissions.
- Confirm which information is essential and who may access it.
- Confirm integrations, approvals, and exception paths.
- Confirm that the proposed screens support the actual process and desired outcome.

## Acceptance checks for a clickable prototype
- A user can follow the agreed main workflow from start to finish.
- The prototype captures the agreed minimum information.
- Users can understand the current status and next action.
- All sample records are fictional and assumptions are visible.

---
*This local demonstration document is a starting template. It does not interpret interview notes or call an AI model.*'''
        return self.send_json(200, {"requirementsSummary": summary, "prototypePlan": plan, "model": "Local demo template (no AI call)", "mode": "demo"})

    def export_word(self, payload):
        docs = payload.get("docs", {})
        selected = payload.get("documentKey")
        keys = [selected] if selected else [key for key in ("requirementsSummary", "prototypePlan", "technicalHandoff") if docs.get(key)]
        if not keys or any(key not in ("requirementsSummary", "prototypePlan", "technicalHandoff") or not docs.get(key) for key in keys):
            return self.send_json(400, {"error": "Generate the selected document before downloading the Word file."})

        def xml_text(value):
            value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(value))
            return escape(value)

        def paragraph(text, style="Normal", page_break=False):
            props = f'<w:pStyle w:val="{style}"/>' if style else ""
            if page_break:
                props += "<w:pageBreakBefore/>"
            ppr = f"<w:pPr>{props}</w:pPr>" if props else ""
            pieces = re.split(r"(\*\*.*?\*\*|`[^`]+`)", text)
            runs = []
            for piece in pieces:
                if not piece:
                    continue
                bold = piece.startswith("**") and piece.endswith("**") and len(piece) > 4
                code = piece.startswith("`") and piece.endswith("`") and len(piece) > 2
                content = piece[2:-2] if bold else piece[1:-1] if code else piece
                run_props = ""
                if bold or code:
                    run_props = "<w:rPr>" + ("<w:b/>" if bold else "<w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\"/>") + "</w:rPr>"
                runs.append(f'<w:r>{run_props}<w:t xml:space="preserve">{xml_text(content)}</w:t></w:r>')
            return f"<w:p>{ppr}{''.join(runs)}</w:p>"

        mode = str(payload.get("mode", "openai"))
        draft_caption = "LOCAL DEMO TEMPLATE · NOT AI-GENERATED" if mode == "demo" else "OPENAI FIRST DRAFT · REVIEW REQUIRED"
        if payload.get("status") == "Approved":
            review_line = f"Approved by {payload.get('reviewer') or 'reviewer'} · {payload.get('approvedAt') or 'date not recorded'}"
        else:
            review_line = f"Status: {payload.get('status') or 'Draft'} · Reviewer: {payload.get('reviewer') or 'not assigned'}"
        blocks = [
            paragraph("Lantern Discovery Documents", "Title"),
            paragraph(str(payload.get("name") or "Untitled project"), "Subtitle"),
            paragraph("INTERNAL · " + draft_caption, "Caption"),
            paragraph(review_line, "Caption"),
            paragraph("", "Normal"),
        ]
        for section_index, key in enumerate(keys):
            source = str(docs[key]).splitlines()
            page_break_pending = section_index > 0 or bool(payload.get("coverPage"))
            for raw in source:
                line = raw.strip()
                if not line or line == "---":
                    continue
                page_break = page_break_pending and line.startswith("# ")
                if page_break:
                    page_break_pending = False
                if line.startswith("### "):
                    blocks.append(paragraph(line[4:], "Heading3", page_break))
                elif line.startswith("## "):
                    blocks.append(paragraph(line[3:], "Heading2", page_break))
                elif line.startswith("# "):
                    blocks.append(paragraph(line[2:], "Heading1", page_break))
                elif line.startswith("- ") or line.startswith("* "):
                    blocks.append(paragraph("•  " + line[2:], "Normal", page_break))
                else:
                    blocks.append(paragraph(line, "Normal", page_break))

        document_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>''' + "".join(blocks) + '''<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1200" w:right="1200" w:bottom="1200" w:left="1200" w:header="600" w:footer="600" w:gutter="0"/></w:sectPr></w:body></w:document>'''
        styles_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="22"/><w:color w:val="263449"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="130" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="19345A"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:sz w:val="25"/><w:color w:val="3B8F99"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="16"/><w:color w:val="64748B"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/><w:color w:val="19345A"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="180" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="25"/><w:color w:val="278F98"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60"/></w:pPr><w:rPr><w:b/><w:sz w:val="23"/><w:color w:val="34445C"/></w:rPr></w:style>
</w:styles>'''
        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'''
        root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
        doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
        output = BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as package:
            package.writestr("[Content_Types].xml", content_types)
            package.writestr("_rels/.rels", root_rels)
            package.writestr("word/document.xml", document_xml)
            package.writestr("word/styles.xml", styles_xml)
            package.writestr("word/_rels/document.xml.rels", doc_rels)
        data = output.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.send_header("Content-Disposition", 'attachment; filename="Lantern-Discovery-Documents.docx"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def save(self, project):
        project_id = project.get("id") or uuid.uuid4().hex
        if not project_id.isalnum():
            return self.send_json(400, {"error": "Invalid project ID"})
        project["id"] = project_id
        path = DATA / f"{project_id}.json"
        now = __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds")
        if path.exists():
            previous = json.loads(path.read_text(encoding="utf-8"))
            history = list(previous.get("history", []))
            history.append({key: previous.get(key) for key in ("version", "updatedAt", "status", "reviewer", "approvedAt", "name", "context", "answers", "docs", "mode", "templateId", "reviewComments", "assignedReviewer", "usageEntries")})
            project["history"] = history[-50:]
            project["version"] = int(previous.get("version") or 1) + 1
            audit = list(previous.get("audit", []))
            project["archived"] = previous.get("archived", False)
        else:
            project["history"] = []
            project["version"] = 1
            audit = []
        project["updatedAt"] = now
        project["approvedAt"] = now if project.get("status") == "Approved" else None
        action = {"Approved": "Approved", "Needs changes": "Requested changes"}.get(project.get("status"), "Saved")
        account = self.current_account() if TEAM_MODE else None
        actor = account.get("display_name") if account else project.get("reviewer") or "Lantern team"
        audit.append({"action": action, "actor": actor, "at": now, "comment": project.get("reviewComments", "")})
        project["audit"] = audit[-200:]
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(path)
        return self.send_json(200, project)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "127.0.0.1")
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"Could not start the local web server on port {port}: {exc}")
        print("Close the other Lantern app window or set a different PORT in .env, then try again.")
        raise SystemExit(1)
    address = f"http://127.0.0.1:{server.server_port}" if host in ("0.0.0.0", "::") else f"http://{host}:{server.server_port}"
    print(f"Lantern Discovery Assistant is running at {address}")
    print("Keep this terminal open while using the app. Press Ctrl+C to stop.")
    if not TEAM_MODE and os.getenv("OPEN_BROWSER", "1") != "0":
        import threading
        threading.Timer(1.0, lambda: webbrowser.open(address)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
