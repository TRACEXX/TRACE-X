"""
TRACE X configuration.

All settings are read from environment variables (or from a local .env file)
so that secrets such as API keys and demo passwords are never written into
source code or frontend files.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def load_env_file(path):
    """Read simple KEY=VALUE lines from a .env file into os.environ.

    Values that are already set in the real environment are NOT overwritten.
    We parse the file ourselves so the project does not need python-dotenv.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_env_file(os.path.join(BASE_DIR, ".env"))


def env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# File extensions accepted by the evidence vault, grouped by evidence type.
# The group decides which viewer opens the file.
EVIDENCE_TYPES = {
    "image": {"jpg", "jpeg", "png", "gif", "webp", "bmp"},
    "video": {"mp4", "webm", "ogv", "mov", "m4v"},
    "audio": {"mp3", "wav", "ogg", "m4a", "aac"},
    "pdf": {"pdf"},
    "text": {"txt", "md", "log", "json"},
    "csv": {"csv"},
    "other": {"docx", "xlsx", "zip"},
}


class Config:
    # Flask signs the session cookie with this key. If it is not provided,
    # app.py creates a random key and stores it in instance/secret_key.txt.
    SECRET_KEY = os.environ.get("TRACEX_SECRET_KEY")

    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    DATABASE = os.environ.get("TRACEX_DATABASE") or os.path.join(INSTANCE_DIR, "tracex.db")

    # Private evidence storage. This folder is outside /static, so files can
    # only be reached through the authorised Flask routes in routes/evidence.py.
    EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence_storage")
    REPORTS_DIR = os.path.join(INSTANCE_DIR, "reports")
    TEMP_DIR = os.path.join(INSTANCE_DIR, "tmp")
    SUSPECT_PHOTO_DIR = os.path.join(BASE_DIR, "static", "assets", "suspects")
    DEMO_VIDEO_DIR = os.path.join(BASE_DIR, "static", "assets", "demo-videos")

    MAX_CONTENT_LENGTH = int(os.environ.get("TRACEX_MAX_UPLOAD_MB", "200")) * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    CSRF_ENABLED = True

    # Demo account passwords used ONLY by database/seed.py on first setup.
    ADMIN_USERNAME = os.environ.get("TRACEX_ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("TRACEX_ADMIN_PASSWORD", "TraceX-Admin-2026")
    DETECTIVE_PASSWORD = os.environ.get("TRACEX_DETECTIVE_PASSWORD", "TraceX-Detective-2026")

    # The integrity demo only touches a temporary copy, never the original.
    # The spec calls it admin-only, but demo step 16 happens while a detective
    # is logged in, so detectives may run it on cases they can access.
    INTEGRITY_DEMO_FOR_DETECTIVES = env_bool("TRACEX_DEMO_FOR_DETECTIVES", True)

    # TRACE AI provider: none | groq | openrouter | openai | gemini | ollama
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "none").strip().lower()
    AI_API_KEY = os.environ.get("AI_API_KEY", "")
    AI_MODEL = os.environ.get("AI_MODEL", "")
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "")
    OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT", "45"))
