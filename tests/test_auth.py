"""Login, logout, session protection, password storage and CSRF."""

from conftest import ADMIN_PASSWORD, DETECTIVE_PASSWORD, make_app
from database.db import query_all, query_one


def test_exactly_five_accounts_with_hashed_passwords(app):
    with app.app_context():
        users = query_all("SELECT * FROM users")
        assert len(users) == 5
        assert sum(1 for u in users if u["role"] == "admin") == 1
        assert sum(1 for u in users if u["role"] == "detective") == 4
        for user in users:
            assert user["password_hash"] not in (ADMIN_PASSWORD, DETECTIVE_PASSWORD)
            assert ADMIN_PASSWORD not in user["password_hash"]


def test_landing_page_lists_four_detectives(client):
    page = client.get("/").get_data(as_text=True)
    for name in ("Amna Fareed", "Warisha Ahmed", "Hiba Khan", "Maryam Farhan"):
        assert name in page
    assert page.count("Access Portal") == 4
    assert "password_hash" not in page


def test_detective_login_page_does_not_expose_secrets(client):
    page = client.get("/login?portal=amna").get_data(as_text=True)
    assert "Amna Fareed" in page
    assert DETECTIVE_PASSWORD not in page
    assert "scrypt" not in page and "pbkdf2" not in page


def test_admin_login_goes_to_dashboard(client, login):
    response = login("admin")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/")


def test_detective_login_goes_to_portal(client, login):
    response = login("amna")
    assert response.headers["Location"].endswith("/portal")
    assert "Riverside Library" in client.get("/portal").get_data(as_text=True)


def test_wrong_password_is_rejected_and_logged(app, client):
    response = client.post("/login", data={"username": "amna", "password": "wrong"})
    assert response.status_code == 200
    assert "Invalid username or password" in response.get_data(as_text=True)
    with app.app_context():
        assert query_one("SELECT * FROM activity_logs WHERE action = 'Failed login attempt'") is not None
    assert client.get("/portal").status_code == 302      # still not logged in


def test_protected_routes_redirect_to_login(client):
    for url in ("/portal", "/admin/", "/cases/CASE-001", "/evidence/1", "/evidence/1/file", "/ai/", "/dsa/"):
        response = client.get(url)
        assert response.status_code == 302, url
        assert "/login" in response.headers["Location"]


def test_logout_clears_session(client, login):
    login("hiba")
    assert client.get("/portal").status_code == 200
    client.post("/logout")
    assert client.get("/portal").status_code == 302


def test_disabled_account_cannot_log_in(app, client, login):
    with app.app_context():
        from database.db import execute
        execute("UPDATE users SET is_active = 0 WHERE username = 'warisha'")
    response = login("warisha")
    assert response.status_code == 200          # login page re-rendered, no redirect


def test_csrf_token_required_for_posts(tmp_path):
    app = make_app(tmp_path, CSRF_ENABLED=True)
    client = app.test_client()
    response = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD})
    assert response.status_code == 400
    client.get("/login")                          # creates the session token
    with client.session_transaction() as session:
        token = session["csrf_token"]
    response = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD, "csrf_token": token})
    assert response.status_code == 302


def test_open_redirect_is_blocked(client):
    response = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                           "next": "//evil.example/steal"})
    assert response.headers["Location"].endswith("/admin/")
