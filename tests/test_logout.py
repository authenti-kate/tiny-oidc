"""RP-Initiated Logout: session teardown without an open redirect."""
from urllib.parse import parse_qs, urlsplit

from helpers import CLIENT_ID, REDIRECT_URI, obtain_code


def test_logout_clears_the_session(client):
    obtain_code(client)  # signs the user in

    assert client.get("/user/logout").status_code == 200

    # With no session left, prompt=none can no longer be satisfied.
    resp = client.get(
        f"/c2s/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        f"&response_type=code&scope=openid&state=st&prompt=none"
    )
    query = parse_qs(urlsplit(resp.headers["Location"]).query)
    assert query["error"] == ["login_required"]


def test_post_logout_redirect_uri_is_shown_not_followed(client):
    """RP-Initiated Logout §2: an unvalidated target must not be redirected to."""
    resp = client.get(
        "/user/logout?post_logout_redirect_uri=https://rp.example/done&state=xyz"
    )
    assert resp.status_code == 200
    assert "Location" not in resp.headers

    body = resp.get_data(as_text=True)
    assert "you would be redirected to" in body
    assert "this will not happen here" in body
    # The target is displayed, with state echoed as an RP would have received it.
    assert "https://rp.example/done?state=xyz" in body


def test_post_logout_redirect_uri_is_html_escaped(client):
    """The target is caller-controlled, so it must not be reflected verbatim."""
    resp = client.get(
        "/user/logout?post_logout_redirect_uri="
        "https://rp.example/%22%3E%3Cscript%3Ealert(1)%3C/script%3E"
    )
    body = resp.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_logout_without_a_target_still_renders(client):
    resp = client.get("/user/logout")
    assert resp.status_code == 200
    assert "You have logged out." in resp.get_data(as_text=True)
