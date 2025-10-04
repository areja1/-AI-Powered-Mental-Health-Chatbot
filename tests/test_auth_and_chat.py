import types
import re
from unittest.mock import patch
import os
import unittest

# Ensure imports don't fail if CI forgot envs
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("OPENAI_API_KEY", "dummy")

from app import app, db, User, bcrypt

from app import app, db, User, bcrypt


class AuthChatTests(unittest.TestCase):
    """
    Functional tests using Flask's test client.
    - Uses in-memory SQLite per test.
    - Extracts CSRF tokens from pages.
    - Mocks OpenAI so no network calls happen.
    """

    def setUp(self):
        self.app = app
        self.app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            WTF_CSRF_CHECK_DEFAULT=True,  # ensure CSRF is enforced
        )
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    # ---------- helpers ----------
    def _create_user(self, username="abhi", email="abhi@example.com", password="password123"):
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        u = User(username=username, email=email, password=hashed)
        db.session.add(u)
        db.session.commit()
        return u

    def _csrf_from(self, html_bytes, where="input"):
        """
        Extract CSRF token:
        - where="input": from hidden form input
        - where="meta":  from <meta name="csrf-token" ...>
        """
        if where == "input":
            m = re.search(rb'name="csrf_token" value="([^"]+)"', html_bytes)
        else:
            m = re.search(rb'<meta name="csrf-token" content="([^"]+)"', html_bytes)
        assert m, "CSRF token not found in page"
        return m.group(1).decode()

    def _signup(self, username, email, password, confirm, follow=True):
        r_get = self.client.get("/signup")
        token = self._csrf_from(r_get.data, where="input")
        form = {
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": confirm,
            "csrf_token": token,
        }
        return self.client.post("/signup", data=form, follow_redirects=follow)

    def _login(self, email, password, follow=True):
        r_get = self.client.get("/login")
        token = self._csrf_from(r_get.data, where="input")
        form = {"email": email, "password": password, "csrf_token": token}
        return self.client.post("/login", data=form, follow_redirects=follow)

    # ---------- signup tests ----------
    def test_signup_missing_fields(self):
        r = self._signup("", "user@example.com", "password123", "password123")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"All fields are required.", r.data)

    def test_signup_short_username(self):
        r = self._signup("ab", "user@example.com", "password123", "password123")
        self.assertIn(b"Username must be between 3 and 150 characters.", r.data)

    def test_signup_invalid_email(self):
        r = self._signup("user", "bad@", "password123", "password123")
        self.assertIn(b"Please enter a valid email address.", r.data)

    def test_signup_short_password(self):
        r = self._signup("user", "user@example.com", "short", "short")
        self.assertIn(b"Password must be at least 8 characters.", r.data)

    def test_signup_mismatched_passwords(self):
        r = self._signup("user", "user@example.com", "password123", "password124")
        self.assertIn(b"Passwords do not match.", r.data)

    def test_signup_duplicate_email_and_username(self):
        self._create_user(username="user", email="user@example.com", password="password123")
        r1 = self._signup("newname", "user@example.com", "password123", "password123")
        self.assertIn(b"An account with this email already exists.", r1.data)
        r2 = self._signup("user", "another@example.com", "password123", "password123")
        self.assertIn(b"That username is already taken.", r2.data)

    def test_signup_success_redirects_with_modal_flag(self):
        r = self._signup("user", "user@example.com", "password123", "password123", follow=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login?registered=1", r.headers.get("Location", ""))
        r2 = self.client.get(r.headers["Location"], follow_redirects=True)
        self.assertEqual(r2.status_code, 200)
        self.assertIn(b"Account created successfully!", r2.data)

    # ---------- login tests ----------
    def test_login_invalid_email_or_password(self):
        self._create_user(email="user@example.com", password="password123")
        r1 = self._login("nope@example.com", "password123")
        self.assertIn(b"Invalid email or password.", r1.data)
        r2 = self._login("user@example.com", "wrongpass")
        self.assertIn(b"Invalid email or password.", r2.data)

    def test_login_success_redirects_to_chat(self):
        self._create_user(email="user@example.com", password="password123")
        r = self._login("user@example.com", "password123", follow=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/chat", r.headers.get("Location", ""))

    # ---------- chat route protection ----------
    def test_chat_requires_login(self):
        r = self.client.get("/chat", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("Location", ""))

    # ---------- /chatbot behavior ----------
    def test_chatbot_crisis_path_does_not_call_openai(self):
        self._create_user(email="user@example.com", password="password123")
        self._login("user@example.com", "password123")
        # Fetch CSRF token for AJAX
        r_chat = self.client.get("/chat")
        meta = self._csrf_from(r_chat.data, where="meta")
        with patch("app.client.chat.completions.create") as mocked:
            resp = self.client.post(
                "/chatbot",
                json={"message": "I feel like suicide today"},
                headers={"X-CSRFToken": meta},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["crisis"])
            self.assertIn("988", data["reply"])
            mocked.assert_not_called()

    def test_chatbot_normal_flow_calls_openai_and_returns_text(self):
        self._create_user(email="user@example.com", password="password123")
        self._login("user@example.com", "password123")
        r_chat = self.client.get("/chat")
        meta = self._csrf_from(r_chat.data, where="meta")
        fake = types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="Hello, I'm here for you."))]
        )
        with patch("app.client.chat.completions.create", return_value=fake) as mocked:
            resp = self.client.post(
                "/chatbot",
                json={"message": "hello"},
                headers={"X-CSRFToken": meta},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertFalse(data["crisis"])
            self.assertEqual(data["reply"], "Hello, I'm here for you.")
            mocked.assert_called_once()

    def test_chatbot_missing_message(self):
        self._create_user(email="user@example.com", password="password123")
        self._login("user@example.com", "password123")
        r_chat = self.client.get("/chat")
        meta = self._csrf_from(r_chat.data, where="meta")
        r = self.client.post("/chatbot", json={}, headers={"X-CSRFToken": meta})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"I didn't receive any input.", r.data)

    # ---------- security tests ----------
    def test_authenticated_user_sees_gate_on_login_and_signup(self):
        self._create_user(email="user@example.com", password="password123")
        self._login("user@example.com", "password123", follow=False)
        r1 = self.client.get("/login", follow_redirects=False)
        self.assertEqual(r1.status_code, 200)
        text1 = r1.get_data(as_text=True)
        # Accept either curly or straight apostrophe
        self.assertRegex(text1, r"You(?:’|')re already signed in")

        r2 = self.client.get("/signup", follow_redirects=False)
        self.assertEqual(r2.status_code, 200)
        text2 = r2.get_data(as_text=True)
        self.assertRegex(text2, r"You(?:’|')re already signed in")

    def test_csrf_required_for_signup_and_login(self):
        # Missing token -> 400
        r1 = self.client.post(
            "/signup",
            data={"username": "u", "email": "e@x.com", "password": "password123", "confirm_password": "password123"},
            follow_redirects=False,
        )
        self.assertEqual(r1.status_code, 400)
        r2 = self.client.post(
            "/login",
            data={"email": "e@x.com", "password": "password123"},
            follow_redirects=False,
        )
        self.assertEqual(r2.status_code, 400)

    def test_csrf_required_for_chatbot(self):
        self._create_user(email="user@example.com", password="password123")
        self._login("user@example.com", "password123")
        # No CSRF header on POST -> 400
        r = self.client.post("/chatbot", json={"message": "hello"})
        self.assertEqual(r.status_code, 400)

    def test_security_headers_present(self):
        r = self.client.get("/login")
        # Minimal sanity checks for our after_request headers
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'self'", r.headers.get("Content-Security-Policy", ""))
        self.assertEqual(r.headers.get("Referrer-Policy"), "no-referrer")

    def test_auth_pages_are_not_cached(self):
        r1 = self.client.get("/login")
        r2 = self.client.get("/signup")
        for r in (r1, r2):
            cc = r.headers.get("Cache-Control", "")
            self.assertIn("no-store", cc)
            self.assertIn("no-cache", cc)
            self.assertIn("must-revalidate", cc)
            self.assertIn("max-age=0", cc)
            self.assertEqual(r.headers.get("Pragma"), "no-cache")
            self.assertEqual(r.headers.get("Expires"), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
