"""Settings profiles: save/load/match user scan settings."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from vantacrawl_api.database import get_session  # noqa: E402
from vantacrawl_api.deps import get_current_user  # noqa: E402
from vantacrawl_api.main import app  # noqa: E402
from vantacrawl_api.models import SettingsProfile, User  # noqa: E402
from vantacrawl_api.routes import settings_profiles as sp  # noqa: E402


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _session():
        with Session(engine) as session:
            yield session

    class _AuthUser:
        id = "u-profile-1"
        email = "profiles@example.com"
        is_admin = False
        is_verified = True

    def _user():
        return _AuthUser()

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_current_user] = _user
    with TestClient(app) as c:
        with Session(engine) as session:
            session.add(
                User(
                    id="u-profile-1",
                    email="profiles@example.com",
                    password_hash="x",
                    is_verified=True,
                )
            )
            session.commit()
        yield c
    app.dependency_overrides.clear()


def test_host_pattern_matching():
    assert sp._host_matches("example.com", "example.com")
    assert sp._host_matches("example.com", "www.example.com")
    assert sp._host_matches("*.example.com", "a.example.com")
    assert not sp._host_matches("other.com", "example.com")
    assert sp._specificity("www.example.com") > sp._specificity("*.example.com")


def test_create_list_load_update_delete(client: TestClient):
    created = client.post(
        "/api/settings-profiles",
        json={
            "name": "WU stealth",
            "mode": "full_audit",
            "speed": "gentle",
            "settings": {"directory_enum": False, "max_depth": 4},
            "host_pattern": "westernunion.com",
            "is_default": False,
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["name"] == "WU stealth"
    assert body["settings"]["max_depth"] == 4
    assert body["host_pattern"] == "westernunion.com"
    pid = body["id"]

    listed = client.get("/api/settings-profiles")
    assert listed.status_code == 200
    assert len(listed.json()["profiles"]) == 1

    matched = client.get(
        "/api/settings-profiles/match",
        params={"url": "https://www.westernunion.com/us/en/home.html"},
    )
    assert matched.status_code == 200
    assert matched.json()["profile"]["id"] == pid
    assert matched.json()["reason"] == "host_pattern"

    updated = client.patch(
        f"/api/settings-profiles/{pid}",
        json={"settings": {"directory_enum": True, "max_depth": 6}, "speed": "balanced"},
    )
    assert updated.status_code == 200
    assert updated.json()["settings"]["max_depth"] == 6
    assert updated.json()["speed"] == "balanced"

    deleted = client.delete(f"/api/settings-profiles/{pid}")
    assert deleted.status_code == 200
    listed2 = client.get("/api/settings-profiles")
    assert listed2.json()["profiles"] == []


def test_default_profile_match_when_no_host(client: TestClient):
    client.post(
        "/api/settings-profiles",
        json={
            "name": "Default soft",
            "mode": "full_audit",
            "speed": "gentle",
            "settings": {"stealth_mode": True},
            "is_default": True,
        },
    )
    client.post(
        "/api/settings-profiles",
        json={
            "name": "Other host",
            "mode": "deep_audit",
            "speed": "fast",
            "settings": {},
            "host_pattern": "acme.test",
        },
    )
    matched = client.get(
        "/api/settings-profiles/match",
        params={"url": "https://unknown.example"},
    )
    assert matched.json()["reason"] == "default"
    assert matched.json()["profile"]["name"] == "Default soft"


def test_duplicate_name_rejected(client: TestClient):
    payload = {
        "name": "Lab",
        "mode": "full_audit",
        "speed": "balanced",
        "settings": {},
    }
    assert client.post("/api/settings-profiles", json=payload).status_code == 201
    again = client.post("/api/settings-profiles", json=payload)
    assert again.status_code == 409
