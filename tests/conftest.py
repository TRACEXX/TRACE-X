"""Shared test fixtures. Every test gets a fresh database and evidence folder in a temp directory."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402

ADMIN_PASSWORD = "test-admin-password"
DETECTIVE_PASSWORD = "test-detective-password"


def make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.db"),
        "EVIDENCE_DIR": str(tmp_path / "evidence"),
        "REPORTS_DIR": str(tmp_path / "reports"),
        "TEMP_DIR": str(tmp_path / "tmp"),
        "SUSPECT_PHOTO_DIR": str(tmp_path / "suspect_photos"),
        "DEMO_VIDEO_DIR": str(tmp_path / "no_videos"),
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": ADMIN_PASSWORD,
        "DETECTIVE_PASSWORD": DETECTIVE_PASSWORD,
        "CSRF_ENABLED": False,
        "AI_PROVIDER": "none",
    }
    config.update(overrides)
    return create_app(config)


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(client):
    """login("amna") logs a detective in; login("admin") logs the administrator in."""
    def _login(username):
        password = ADMIN_PASSWORD if username == "admin" else DETECTIVE_PASSWORD
        return client.post("/login", data={"username": username, "password": password})
    return _login
