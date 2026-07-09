"""Fixtures for the end-to-end suite.

Unlike tests/conftest.py (which drives Flask's in-process test_client), these
tests need real HTTP servers: Playwright drives a real browser through real
redirects, and the RP makes real back-channel calls to the provider. Both apps
therefore run as subprocesses on ephemeral ports.

OIDC_ISSUER is pinned to the provider's own base URL so the issuer in the
discovery document, the `iss` claim, and the URL the browser visits all agree —
which is exactly the reverse-proxy behaviour H6 added.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[2]

CLIENT_ID = "client_id_12decaf34bad56"
CLIENT_SECRET = "Super-+Secret_=Key0123456789"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn(argv, env, log_name):
    """Start a server subprocess, sending its output to a log file.

    The output must go to a file rather than subprocess.PIPE: the provider logs
    every request, and nothing in the test process drains the pipe, so a PIPE
    fills its ~64KB kernel buffer after a handful of requests and the server
    blocks forever on write.
    """
    log_path = Path(tempfile.gettempdir()) / f"tiny-oidc-e2e-{log_name}-{os.getpid()}.log"
    log_file = log_path.open("w")
    proc = subprocess.Popen(
        argv, cwd=REPO_ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT, text=True
    )
    proc._log_path = log_path  # type: ignore[attr-defined]
    proc._log_file = log_file  # type: ignore[attr-defined]
    return proc


def _server_log(proc):
    try:
        return proc._log_path.read_text()[-4000:]
    except OSError:
        return "<no log captured>"


def _wait_for_health(base_url, proc, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"{base_url} exited early with code {proc.returncode}\n"
                f"{_server_log(proc)}"
            )
        try:
            if requests.get(f"{base_url}/health", timeout=1).status_code == 200:
                return
        except requests.RequestException:
            time.sleep(0.1)
    raise RuntimeError(
        f"{base_url} did not become healthy within {timeout}s\n{_server_log(proc)}"
    )


def _terminate(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    proc._log_file.close()
    proc._log_path.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def idp_server():
    """The tiny-oidc provider, on a throwaway database with a pinned issuer."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    env = {
        **os.environ,
        "FLASK_HOST": "127.0.0.1",
        "FLASK_PORT": str(port),
        "FLASK_DEBUG": "",
        "DATABASE_URI": f"sqlite:///{db_path}",
        "SECRET_KEY": "idp-e2e-secret",
        "OIDC_ISSUER": base_url,
    }
    proc = _spawn([sys.executable, str(REPO_ROOT / "app.py")], env, "idp")
    try:
        _wait_for_health(base_url, proc)
        yield base_url
    finally:
        _terminate(proc)
        os.unlink(db_path)


@pytest.fixture(scope="session")
def rp_server(idp_server):
    """The relying party from tests/e2e/rp_app.py, pointed at the provider."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = {
        **os.environ,
        "RP_PORT": str(port),
        "IDP_ISSUER": idp_server,
        "RP_CLIENT_ID": CLIENT_ID,
        "RP_CLIENT_SECRET": CLIENT_SECRET,
        "RP_REDIRECT_URI": f"{base_url}/callback",
    }
    proc = _spawn([sys.executable, str(REPO_ROOT / "tests" / "e2e" / "rp_app.py")], env, "rp")
    try:
        _wait_for_health(base_url, proc)
        yield base_url
    finally:
        _terminate(proc)


@pytest.fixture
def rp(page, rp_server, idp_server):
    """A browser-driven handle on the RP, one fresh browser context per test."""
    return RelyingParty(page, rp_server, idp_server)


class RelyingParty:
    """Drives the five-step workflow through a real browser."""

    def __init__(self, page, rp_url, idp_url):
        self.page = page
        self.rp_url = rp_url
        self.idp_url = idp_url

    def login(self, persona="admin", auth="post", pkce="S256", scope=None):
        """Steps 1-4: start at the RP, authenticate at the IdP, land back at the RP."""
        self.start_login(auth=auth, pkce=pkce, scope=scope)
        self.select_persona(persona)
        return self.state()

    def start_login(self, auth="post", pkce="S256", scope=None, prompt=None,
                    max_age=None):
        """Step 1-2: the RP redirects the browser to the provider."""
        params = f"auth={auth}&pkce={pkce}"
        if scope is not None:
            params += f"&scope={scope.replace(' ', '%20')}"
        if prompt is not None:
            params += f"&prompt={prompt}"
        if max_age is not None:
            params += f"&max_age={max_age}"
        self.page.goto(f"{self.rp_url}/login?{params}")

    def select_persona(self, persona):
        """Step 3: the provider prompts; the "user" picks an authentication profile."""
        self.page.wait_for_url(f"{self.idp_url}/user/login")
        self.page.click(f'button:has-text("Login as {persona}")')
        # Step 4: /user/login -> /c2s/authorize -> RP /callback -> RP /session.
        self.page.wait_for_url(f"{self.rp_url}/session")

    def state(self):
        """Step 5: whatever the RP made of the tokens it was issued."""
        return self.get("/api/session")

    def get(self, path):
        resp = self.page.request.get(f"{self.rp_url}{path}")
        return resp.json()

    def visit(self, path):
        self.page.goto(f"{self.rp_url}{path}")
