"""Test harness for the multi-tenant API.

Every test runs against a real SQLite database through a real ASGI app. There
are no mocks: the point of most of these tests is that a query is scoped, and a
mocked session would not exercise the SQL where scoping actually happens.

The :class:`Stack` helper exists so a test can sign up real accounts with real
password hashing and real cookies. Tests that need two tenants - the isolation
tests especially - get two independent clients.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from hunter import db as hunter_db

# A password that satisfies the policy. Shared so tests do not each invent one.
GOOD_PASSWORD = "correct-horse-battery-9"

SECOND_PASSWORD = "another-strong-pass-4"


@dataclass
class Account:
    """A signed-in user, their tenant, and the cookies that carry the session."""

    client: TestClient
    email: str
    user_id: int
    nonprofit_id: int
    nonprofit_name: str
    password: str
    csrf: str = ""

    @property
    def auth(self) -> dict[str, str]:
        """Headers needed for a state-changing request from this browser."""
        return {"X-CSRF-Token": self.csrf}

    def get(self, url: str, **kwargs):
        return self.client.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        kwargs.setdefault("headers", {}).update(self.auth)
        return self.client.post(url, **kwargs)

    def patch(self, url: str, **kwargs):
        kwargs.setdefault("headers", {}).update(self.auth)
        return self.client.patch(url, **kwargs)

    def put(self, url: str, **kwargs):
        kwargs.setdefault("headers", {}).update(self.auth)
        return self.client.put(url, **kwargs)

    def delete(self, url: str, **kwargs):
        kwargs.setdefault("headers", {}).update(self.auth)
        return self.client.delete(url, **kwargs)


def _unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.org"


def signup(
    client: TestClient,
    *,
    email: str | None = None,
    password: str = GOOD_PASSWORD,
    nonprofit_name: str = "Test Nonprofit",
    state: str = "WI",
    full_name: str = "Test Person",
) -> Account:
    """Register an account and return it with its session established."""
    email = email or _unique_email("user")
    response = client.post(
        "/api/auth/signup",
        json={
            "email": email,
            "password": password,
            "full_name": full_name,
            "nonprofit_name": nonprofit_name,
            "state": state,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["nonprofits"], "signup must create the first nonprofit"

    return Account(
        client=client,
        email=email,
        user_id=body["user"]["id"],
        nonprofit_id=body["nonprofits"][0]["id"],
        nonprofit_name=nonprofit_name,
        password=password,
        csrf=body.get("csrf_token") or "",
    )


def login(
    client: TestClient, *, email: str, password: str = GOOD_PASSWORD
) -> Account:
    """Sign in on an existing client, reusing its cookie jar."""
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    body = response.json()
    return Account(
        client=client,
        email=email,
        user_id=body["user"]["id"],
        nonprofit_id=body["nonprofits"][0]["id"] if body["nonprofits"] else 0,
        nonprofit_name=body["nonprofits"][0]["name"] if body["nonprofits"] else "",
        password=password,
        csrf=body.get("csrf_token") or "",
    )


def add_member(
    owner: Account, email: str, role: str = "member", password: str = SECOND_PASSWORD
) -> Account:
    """Invite a new person to the owner's tenant and return their client.

    The invite creates the account; the returned :class:`Account` has that
    person signed in on a second client, so the two sessions do not clobber each
    other's cookies.
    """
    response = owner.post(
        f"/api/nonprofits/{owner.nonprofit_id}/members",
        json={"email": email, "role": role},
    )
    assert response.status_code == 201, response.text

    # The invitee has no usable password (the invite path generates a random
    # one), so the test sets one directly through the reset flow.
    from accounts import service
    from accounts.models import EmailToken

    with hunter_db.session_scope() as db:
        user = service.get_user_by_email(db, email)
        assert user is not None
        token = service.issue_email_token(db, user, purpose=EmailToken.PURPOSE_RESET)

    other = TestClient(owner.client.app)
    reset = other.post(
        "/api/auth/reset-password", json={"token": token, "password": password}
    )
    assert reset.status_code == 200, reset.text
    account = login(other, email=email, password=password)
    account.nonprofit_id = owner.nonprofit_id
    return account


def make_grant(
    *,
    title: str,
    source: str = "state_WI",
    state_code: str | None = "WI",
    agency: str = "Test Agency",
    external_id: str | None = None,
    dedupe_hash: str | None = None,
):
    """Insert a grant directly, bypassing the network sources."""
    from datetime import date, timedelta

    from hunter.models import Grant

    eid = external_id or uuid.uuid4().hex[:12]
    with hunter_db.session_scope() as db:
        grant = Grant(
            external_id=eid,
            title=title,
            agency=agency,
            deadline=date.today() + timedelta(days=30),
            amount_min=5000,
            amount_max=50000,
            description=title,
            url=f"https://example.org/{eid}",
            source=source,
            state_code=state_code,
            dedupe_hash=dedupe_hash or f"hash-{eid}",
        )
        db.add(grant)
        db.flush()
        return {"id": grant.id, "title": grant.title}


def make_match(
    *, nonprofit_id: int, grant_id: int, score: float = 80.0, status: str = "NEEDS_REVIEW"
) -> int:
    """Create a match for a tenant directly."""
    from hunter.models import Match

    with hunter_db.session_scope() as db:
        match = Match(
            nonprofit_id=nonprofit_id,
            grant_id=grant_id,
            score=score,
            status=status,
        )
        db.add(match)
        db.flush()
        return match.id


@pytest.fixture()
def two_accounts(client):
    """Two users in **separate** tenants, for isolation tests."""
    first = signup(client, nonprofit_name="Alpha Org", state="WI")
    second_client = TestClient(client.app)
    second = signup(second_client, nonprofit_name="Beta Org", state="CA")
    return first, second


__all__ = [
    "GOOD_PASSWORD",
    "SECOND_PASSWORD",
    "Account",
    "add_member",
    "login",
    "make_grant",
    "make_match",
    "signup",
]