# app.py — Aegean Tech Portal (Supabase + Folders + Assets + Email Reminders)
import os, secrets, smtplib, datetime, json, traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from functools import wraps
from threading import Thread, Event

from flask import Flask, request, jsonify, redirect
from werkzeug.utils import secure_filename

from supabase import create_client, Client

# ────────────────────────────────────────────────────────────────────────────────
# Environment Config
# ────────────────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE = os.environ.get("SUPABASE_SERVICE_ROLE", "")
AEG_USERS = os.environ.get("AEG_USERS", "admin@aegeantech.com:ChangeMe, partner@aegeantech.com:ChangeMeToo")

# SMTP (Mailgun/SendGrid/Gmail app password etc.)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@aegeantech.com")

APP_VERSION = os.environ.get("APP_VERSION", "1.4.0")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE)

# Parse users from env (simple admin role for MVP)
USERS = {}
for pair in [p.strip() for p in AEG_USERS.split(",") if p.strip()]:
    if ":" in pair:
        email, pw = pair.split(":", 1)
        USERS[email.strip()] = pw.strip()

# ────────────────────────────────────────────────────────────────────────────────
# Flask App
# ────────────────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 200  # 200 MB

# ────────────────────────────────────────────────────────────────────────────────
# Helpers / Middleware
# ────────────────────────────────────────────────────────────────────────────────
TOKENS = {}  # token -> email
stop_event = Event()
_worker_started = False

def json_error(message, code=400, **extra):
    payload = {"error": message}
    if extra:
        payload.update(extra)
    return jsonify(payload), code

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return json_error("Unauthorized", 401)
        token = auth.split(" ", 1)[1]
        if token not in TOKENS:
            return json_error("Unauthorized", 401)
        request.user_email = TOKENS[token]
        return f(*args, **kwargs)
    return wrapper

def log_activity(actor, action, entity, entity_id=None, details=None):
    try:
        supabase.table("activities").insert({
            "actor": actor,
            "action": action,
            "entity": entity,
            "entity_id": entity_id,
            "details": details or {},
        }).execute()
    except Exception:
        # Avoid crashing the request if logging fails
        pass

def send_email(to_emails, subject, html_body, ics_text=None):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM):
        return False, "SMTP not configured"
    if isinstance(to_emails, str):
        to_emails = [e.strip() for e in to_emails.split(",") if e.strip()]

    msg = MIMEMultipart("mixed")
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_emails)
    msg["Subject"] = subject

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html"))
    msg.attach(alt)

    if ics_text:
        ics_part = MIMEText(ics_text, "calendar; method=REQUEST; charset=UTF-8")
        ics_part.add_header("Content-Disposition", 'attachment; filename="invite.ics"')
        msg.attach(ics_part)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_FROM, to_emails, msg.as_string())
    return True, "sent"

def to_ics(meeting):
    """
    meeting: dict with title, start_at (UTC iso), duration_min, location, id
    """
    start = datetime.datetime.fromisoformat(meeting["start_at"].replace("Z","")).replace(tzinfo=datetime.timezone.utc)
    end = start + datetime.timedelta(minutes=int(meeting.get("duration_min",60)))
    def fmt(dt): return dt.strftime("%Y%m%dT%H%M%SZ")
    uid = f"{meeting.get('id', secrets.token_hex(6))}@aegeantech"
    ics = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//AegeanTech//Portal//EN
METHOD:REQUEST
BEGIN:VEVENT
UID:{uid}
DTSTAMP:{fmt(datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc))}
DTSTART:{fmt(start)}
DTEND:{fmt(end)}
SUMMARY:{meeting.get('title','Meeting')}
LOCATION:{meeting.get('location','')}
DESCRIPTION:Aegean Tech meeting
END:VEVENT
END:VCALENDAR
"""
    return ics

# ────────────────────────────────────────────────────────────────────────────────
# Auth
# ────────────────────────────────────────────────────────────────────────────────
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    if email in USERS and USERS[email] == password:
        token = secrets.token_urlsafe(32)
        TOKENS[token] = email
        return jsonify({"token": token, "role": "admin", "email": email})
    return json_error("Invalid credentials", 401)

# ────────────────────────────────────────────────────────────────────────────────
# Activities (Dashboard feed)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/activities")
@require_auth
def activities_feed():
    limit = int(request.args.get("limit", 15))
    res = supabase.table("activities").select("*").order("created_at", desc=True).limit(limit).execute()
    return jsonify(res.data or [])

# ────────────────────────────────────────────────────────────────────────────────
# Clients CRUD
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/clients")
@require_auth
def clients_list():
    res = supabase.table("clients").select("*").order("id", desc=True).execute()
    return jsonify(res.data or [])

@app.get("/api/clients/<int:client_id>")
@require_auth
def clients_get(client_id):
    res = supabase.table("clients").select("*").eq("id", client_id).single().execute()
    if not res.data:
        return json_error("not found", 404)
    return jsonify(res.data)

@app.post("/api/clients")
@require_auth
def clients_add():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return json_error("Name required", 400)
    row = {
        "name": name,
        "industry": (data.get("industry") or "").strip(),
        "contact": (data.get("contact") or "").strip(),
    }
    ins = supabase.table("clients").insert(row).execute()
    cid = ins.data[0]["id"] if ins.data else None
    log_activity(request.user_email, "created_client", "clients", cid, {"name": name})
    return jsonify({"ok": True, "id": cid})

@app.put("/api/clients/<int:client_id>")
@require_auth
def clients_update(client_id):
    data = request.get_json() or {}
    row = {
        "name": (data.get("name") or "").strip(),
        "industry": (data.get("industry") or "").strip(),
        "contact": (data.get("contact") or "").strip(),
    }
    supabase.table("clients").update(row).eq("id", client_id).execute()
    log_activity(request.user_email, "updated_client", "clients", client_id, row)
    return jsonify({"ok": True})

@app.delete("/api/clients/<int:client_id>")
@require_auth
def clients_delete(client_id):
    supabase.table("clients").delete().eq("id", client_id).execute()
    log_activity(request.user_email, "deleted_client", "clients", client_id)
    return jsonify({"ok": True})

# ────────────────────────────────────────────────────────────────────────────────
# Client Folders & Files
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/clients/<int:client_id>/folders")
@require_auth
def client_folders(client_id):
    res = supabase.table("files").select("folder").eq("client_id", client_id).execute()
    folders = sorted({(r.get("folder") or "general") for r in (res.data or [])})
    if not folders:
        folders = ["general"]
    return jsonify(folders)

@app.get("/api/clients/<int:client_id>/files")
@require_auth
def client_files_list(client_id):
    folder = request.args.get("folder")
    q = supabase.table("files").select("*").eq("client_id", client_id).order("id", desc=True)
    if folder:
        q = q.eq("folder", folder)
    res = q.execute()
    return jsonify(res.data or [])

@app.post("/api/clients/<int:client_id>/files")
@require_auth
def client_files_upload(client_id):
    if "file" not in request.files:
        return json_error("file missing", 400)
    folder = (request.form.get("folder") or "general").strip()
    f = request.files["file"]
    filename = secure_filename(f.filename or "file.bin")
    mime = f.mimetype or "application/octet-stream"
    content = f.read()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    storage_path = f"clients/{client_id}/{folder}/{ts}_{secrets.token_hex(6)}_{filename}"
    supabase.storage.from_("portal").upload(storage_path, content, file_options={"contentType": mime, "upsert": True})
    ins = supabase.table("files").insert({
        "client_id": client_id,
        "project_id": None,
        "kind": "client_file",
        "folder": folder,
        "filename": filename,
        "storage_path": storage_path,
        "size_bytes": len(content),
        "mime": mime,
        "uploaded_by": request.user_email,
    }).execute()
    fid = ins.data[0]["id"] if ins.data else None
    log_activity(request.user_email, "uploaded_client_file", "files", fid, {"client_id": client_id, "folder": folder, "filename": filename})
    return jsonify({"ok": True, "id": fid})

@app.delete("/api/files/<int:file_id>")
@require_auth
def files_delete(file_id):
    # Delete DB record only (keep storage for safety)
    supabase.table("files").delete().eq("id", file_id).execute()
    log_activity(request.user_email, "deleted_file", "files", file_id)
    return jsonify({"ok": True})

@app.get("/api/files/download/<int:file_id>")
@require_auth
def files_download(file_id):
    f = supabase.table("files").select("storage_path, filename").eq("id", file_id).single().execute()
    if not f.data:
        return json_error("not found", 404)
    path = f.data["storage_path"]
    bucket = "templates" if path.startswith("templates/") else "portal"
    signed = supabase.storage.from_(bucket).create_signed_url(path, 600)
    return redirect(signed.get("signedURL"))

# ────────────────────────────────────────────────────────────────────────────────
# Proposals CRUD + File + Global Proposal Assets (folders)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/proposals")
@require_auth
def proposals_list():
    q = supabase.table("proposals").select("*").order("id", desc=True)
    client_id = request.args.get("client_id")
    category = request.args.get("category")
    status = request.args.get("status")
    if client_id: q = q.eq("client_id", int(client_id))
    if category:  q = q.eq("category", category)
    if status:    q = q.eq("status", status)
    res = q.execute()
    return jsonify(res.data or [])

@app.post("/api/proposals")
@require_auth
def proposals_add():
    data = request.form.to_dict() if request.form else (request.get_json() or {})
    client_id = data.get("client_id")
    title = (data.get("title") or "").strip()
    category = (data.get("category") or "Maritime").strip()
    status = (data.get("status") or "draft").strip()
    value_amount = float(data.get("value_amount") or 0)
    currency = (data.get("currency") or "EUR").strip()
    due_date = data.get("due_date")  # YYYY-MM-DD

    if not client_id or not title:
        return json_error("client_id and title required", 400)

    file_id = None
    if "file" in request.files:
        f = request.files["file"]
        filename = secure_filename(f.filename or "file.bin")
        mime = f.mimetype or "application/octet-stream"
        content = f.read()
        storage_path = f"proposals/{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}_{filename}"
        supabase.storage.from_("portal").upload(storage_path, content, file_options={"contentType": mime, "upsert": True})
        r = supabase.table("files").insert({
            "client_id": int(client_id),
            "project_id": None,
            "kind": "proposal",
            "folder": "proposals",
            "filename": filename,
            "storage_path": storage_path,
            "size_bytes": len(content),
            "mime": mime,
            "uploaded_by": request.user_email,
        }).execute()
        file_id = r.data[0]["id"] if r.data else None

    row = {
        "client_id": int(client_id),
        "title": title,
        "category": category,
        "status": status,
        "value_amount": value_amount,
        "currency": currency,
        "due_date": due_date,
        "file_id": file_id,
    }
    res = supabase.table("proposals").insert(row).execute()
    pid = res.data[0]["id"] if res.data else None
    log_activity(request.user_email, "created_proposal", "proposals", pid, {"title": title, "category": category})
    return jsonify({"ok": True, "id": pid})

@app.delete("/api/proposals/<int:proposal_id>")
@require_auth
def proposals_delete(proposal_id):
    supabase.table("proposals").delete().eq("id", proposal_id).execute()
    log_activity(request.user_email, "deleted_proposal", "proposals", proposal_id)
    return jsonify({"ok": True})

@app.get("/api/proposals/download/<int:proposal_id>")
@require_auth
def proposals_download(proposal_id):
    res = supabase.table("proposals").select("file_id").eq("id", proposal_id).single().execute()
    if not res.data or not res.data.get("file_id"):
        return json_error("no file", 404)
    f = supabase.table("files").select("storage_path, filename").eq("id", res.data["file_id"]).single().execute()
    storage_path = f.data["storage_path"]
    signed = supabase.storage.from_("portal").create_signed_url(storage_path, 600)
    return redirect(signed.get("signedURL"))

# Global proposal assets library (folders)
@app.get("/api/proposals/folders")
@require_auth
def proposals_folders():
    res = supabase.table("files").select("folder").eq("kind","proposal_asset").execute()
    folders = sorted({(r.get("folder") or "general") for r in (res.data or [])})
    return jsonify(folders or ["general"])

@app.post("/api/proposals/assets")
@require_auth
def proposals_assets_upload():
    if "file" not in request.files:
        return json_error("file missing", 400)
    folder = (request.form.get("folder") or "general").strip()
    f = request.files["file"]
    filename = secure_filename(f.filename or "file.bin")
    mime = f.mimetype or "application/octet-stream"
    content = f.read()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    storage_path = f"proposal_assets/{folder}/{ts}_{secrets.token_hex(6)}_{filename}"
    supabase.storage.from_("portal").upload(storage_path, content, file_options={"contentType": mime, "upsert": True})
    ins = supabase.table("files").insert({
        "client_id": None,
        "project_id": None,
        "kind": "proposal_asset",
        "folder": folder,
        "filename": filename,
        "storage_path": storage_path,
        "size_bytes": len(content),
        "mime": mime,
        "uploaded_by": request.user_email,
    }).execute()
    fid = ins.data[0]["id"] if ins.data else None
    log_activity(request.user_email, "uploaded_proposal_asset", "files", fid, {"folder": folder, "filename": filename})
    return jsonify({"ok": True, "id": fid})

@app.get("/api/proposals/assets")
@require_auth
def proposals_assets_list():
    res = supabase.table("files").select("*").eq("kind","proposal_asset").order("id", desc=True).execute()
    return jsonify(res.data or [])

# ────────────────────────────────────────────────────────────────────────────────
# Templates Library (folders supported)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/templates")
@require_auth
def templates_list():
    res = supabase.table("files").select("*").eq("kind","template").order("id", desc=True).execute()
    return jsonify(res.data or [])

@app.get("/api/templates/folders")
@require_auth
def templates_folders():
    res = supabase.table("files").select("folder").eq("kind","template").execute()
    folders = sorted({(r.get("folder") or "general") for r in (res.data or [])})
    return jsonify(folders or ["general"])

# Original flat upload (kept for backward compatibility)
@app.post("/api/templates/upload")
@require_auth
def templates_upload():
    if "file" not in request.files:
        return json_error("file missing", 400)
    f = request.files["file"]
    filename = secure_filename(f.filename or "file.bin")
    mime = f.mimetype or "application/octet-stream"
    content = f.read()
    storage_path = f"templates/{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}_{filename}"
    supabase.storage.from_("templates").upload(storage_path, content, file_options={"contentType": mime, "upsert": True})
    supabase.table("files").insert({
        "client_id": None,
        "project_id": None,
        "kind": "template",
        "folder": "general",
        "filename": filename,
        "storage_path": storage_path,
        "size_bytes": len(content),
        "mime": mime,
        "uploaded_by": request.user_email,
    }).execute()
    log_activity(request.user_email, "uploaded_template", "files", None, {"filename": filename})
    return jsonify({"ok": True})

# Folder-aware upload
@app.post("/api/templates/upload2")
@require_auth
def templates_upload2():
    if "file" not in request.files:
        return json_error("file missing", 400)
    folder = (request.form.get("folder") or "general").strip()
    f = request.files["file"]
    filename = secure_filename(f.filename or "file.bin")
    mime = f.mimetype or "application/octet-stream"
    content = f.read()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    storage_path = f"templates/{folder}/{ts}_{secrets.token_hex(6)}_{filename}"
    supabase.storage.from_("templates").upload(storage_path, content, file_options={"contentType": mime, "upsert": True})
    supabase.table("files").insert({
        "client_id": None,
        "project_id": None,
        "kind": "template",
        "folder": folder,
        "filename": filename,
        "storage_path": storage_path,
        "size_bytes": len(content),
        "mime": mime,
        "uploaded_by": request.user_email,
    }).execute()
    log_activity(request.user_email, "uploaded_template", "files", None, {"filename": filename, "folder": folder})
    return jsonify({"ok": True})

# Folder-aware list (UI tries this first)
@app.get("/api/templates/list2")
@require_auth
def templates_list2():
    res = supabase.table("files").select("*").eq("kind","template").order("id", desc=True).execute()
    return jsonify(res.data or [])

@app.get("/api/templates/download/<int:file_id>")
@require_auth
def templates_download(file_id):
    f = supabase.table("files").select("storage_path, filename").eq("id", file_id).single().execute()
    if not f.data:
        return json_error("not found", 404)
    storage_path = f.data["storage_path"]
    signed = supabase.storage.from_("templates").create_signed_url(storage_path, 600)
    return redirect(signed.get("signedURL"))

# ────────────────────────────────────────────────────────────────────────────────
# Meetings (email reminders)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/meetings")
@require_auth
def meetings_list():
    res = supabase.table("meetings").select("*").order("start_at", desc=False).execute()
    return jsonify(res.data or [])

@app.post("/api/meetings")
@require_auth
def meetings_add():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    start_at = (data.get("start_at") or "").strip()  # UTC ISO string
    duration_min = int(data.get("duration_min") or 60)
    location = (data.get("location") or "").strip()
    participants = (data.get("participants") or "").strip()
    remind_before_min = int(data.get("remind_before_min") or 30)
    if not title or not start_at or not participants:
        return json_error("title, start_at, participants required", 400)
    res = supabase.table("meetings").insert({
        "title": title, "start_at": start_at, "duration_min": duration_min,
        "location": location, "participants": participants,
        "remind_before_min": remind_before_min, "created_by": request.user_email
    }).execute()
    mid = res.data[0]["id"] if res.data else None
    log_activity(request.user_email, "scheduled_meeting", "meetings", mid, {"title": title, "start_at": start_at})
    return jsonify({"ok": True, "id": mid})

@app.delete("/api/meetings/<int:meeting_id>")
@require_auth
def meetings_delete(meeting_id):
    supabase.table("meetings").delete().eq("id", meeting_id).execute()
    log_activity(request.user_email, "deleted_meeting", "meetings", meeting_id)
    return jsonify({"ok": True})

@app.post("/api/email/test")
@require_auth
def email_test():
    data = request.get_json(silent=True) or {}
    to = data.get("to") or request.user_email
    ok, msg = send_email(to, "Aegean Tech • Test Email", "<p>This is a test email from the portal.</p>")
    return jsonify({"ok": ok, "msg": msg})

# ────────────────────────────────────────────────────────────────────────────────
# UI Tabs Config (optional)
# ────────────────────────────────────────────────────────────────────────────────
DEFAULT_TABS = ["Dashboard","Proposals","Templates","Reporting","Clients","Meetings","Settings"]

@app.get("/api/ui/tabs")
@require_auth
def tabs_get():
    res = supabase.table("tabs_config").select("*").eq("user_email", request.user_email).single().execute()
    if res.data and res.data.get("tabs"):
        return jsonify(res.data["tabs"])
    return jsonify(DEFAULT_TABS)

@app.post("/api/ui/tabs")
@require_auth
def tabs_set():
    data = request.get_json(silent=True) or {}
    tabs = data.get("tabs")
    if not isinstance(tabs, list) or not tabs:
        return json_error("tabs array required", 400)
    supabase.table("tabs_config").upsert({"user_email": request.user_email, "tabs": tabs}).execute()
    return jsonify({"ok": True})

# ────────────────────────────────────────────────────────────────────────────────
# Reporting (KPIs)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/reporting/kpis")
@require_auth
def reporting_kpis():
    # Clients
    clients = supabase.table("clients").select("id", count="exact").execute()
    client_count = clients.count or (len(clients.data) if clients.data else 0)
    # Proposals by status
    props = supabase.table("proposals").select("*").execute()
    st = {"draft":0,"sent":0,"won":0,"lost":0}
    total_value = 0.0
    for p in (props.data or []):
        st[p.get("status","draft")] = st.get(p.get("status","draft"),0)+1
        try:
            total_value += float(p.get("value_amount") or 0)
        except Exception:
            pass
    # Next meetings
    now = datetime.datetime.utcnow().isoformat() + "Z"
    upcoming = supabase.table("meetings").select("*").gt("start_at", now).order("start_at", desc=False).limit(5).execute()
    return jsonify({
        "clients": client_count,
        "proposals": st,
        "pipeline_value": round(total_value,2),
        "upcoming_meetings": upcoming.data or []
    })

# ────────────────────────────────────────────────────────────────────────────────
# Files generic list (by kind)
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/files")
@require_auth
def files_list():
    kind = request.args.get("kind")
    q = supabase.table("files").select("*").order("id", desc=True)
    if kind:
        q = q.eq("kind", kind)
    res = q.execute()
    return jsonify(res.data or [])

# ────────────────────────────────────────────────────────────────────────────────
# Background Reminder Worker (Flask 3 compatible)
# ────────────────────────────────────────────────────────────────────────────────
def reminder_worker():
    # Runs every 60s: send reminders when now >= (start_at - remind_before_min)
    while not stop_event.is_set():
        try:
            now_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            res = supabase.table("meetings").select("*").eq("reminder_sent", False).execute()
            for m in (res.data or []):
                # tolerate missing Z
                start = datetime.datetime.fromisoformat(m["start_at"].replace("Z","")).replace(tzinfo=datetime.timezone.utc)
                remind_before = int(m.get("remind_before_min") or 30)
                remind_at = start - datetime.timedelta(minutes=remind_before)
                if now_utc >= remind_at:
                    html = f"<p>Reminder: <strong>{m['title']}</strong></p><p>When: {start.strftime('%Y-%m-%d %H:%M UTC')}</p><p>Location: {m.get('location','')}</p>"
                    ics_text = to_ics(m)
                    ok, _ = send_email(m["participants"], f"Reminder: {m['title']}", html, ics_text=ics_text)
                    if ok:
                        supabase.table("meetings").update({"reminder_sent": True}).eq("id", m["id"]).execute()
                        log_activity("system","sent_meeting_reminder","meetings", m["id"])
        except Exception:
            # don't crash the loop
            pass
        stop_event.wait(60)

@app.before_request
def _start_worker_once():
    global _worker_started
    if not _worker_started:
        t = Thread(target=reminder_worker, daemon=True)
        t.start()
        _worker_started = True

# ────────────────────────────────────────────────────────────────────────────────
# Health / Version / Error handling
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return jsonify({"ok": True, "version": APP_VERSION})

@app.errorhandler(413)
def too_large(e):
    return json_error("file too large", 413)

@app.errorhandler(Exception)
def on_error(e):
    # Return compact error in JSON for easy debugging in UI
    return json_error("server_error", 500, detail=str(e), trace=getattr(e, "__traceback__", None) and "".join(traceback.format_tb(e.__traceback__)))

# ────────────────────────────────────────────────────────────────────────────────
# SPA (serve static index.html)
# ────────────────────────────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def spa(path):
    # Single Page App: always return static/index.html
    return app.send_static_file("index.html")

# ────────────────────────────────────────────────────────────────────────────────
# Run
# ────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))  # Render sets PORT at runtime
    app.run(host="0.0.0.0", port=port, debug=False)
