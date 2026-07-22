"""User-saved scan settings profiles (mode/speed/expert overlay)."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, SessionDep
from ..models import SettingsProfile
from ..schemas import (
    MessageOut,
    SettingsProfileCreate,
    SettingsProfileListOut,
    SettingsProfileMatchOut,
    SettingsProfileOut,
    SettingsProfileUpdate,
)

router = APIRouter(prefix="/settings-profiles", tags=["settings-profiles"])


def _normalize_host(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        try:
            raw = urlparse(raw).hostname or raw
        except Exception:
            pass
    raw = raw.split("/")[0].split("?")[0].split(":")[0]
    if raw.startswith("*."):
        return raw
    if raw.startswith("."):
        return "*" + raw
    return raw


def _host_matches(pattern: str, host: str) -> bool:
    pat = _normalize_host(pattern)
    h = _normalize_host(host)
    if not pat or not h:
        return False
    if pat.startswith("*."):
        suffix = pat[1:]  # .example.com
        return h == pat[2:] or h.endswith(suffix)
    return h == pat or h.endswith("." + pat)


def _specificity(pattern: str) -> int:
    pat = _normalize_host(pattern)
    if not pat:
        return 0
    if pat.startswith("*."):
        return 50 + len(pat)
    return 100 + len(pat)


def _to_out(row: SettingsProfile) -> SettingsProfileOut:
    return SettingsProfileOut(
        id=row.id,
        name=row.name,
        mode=row.mode or "full_audit",
        speed=row.speed or "balanced",
        settings=dict(row.settings_json or {}),
        host_pattern=row.host_pattern or "",
        wordlist_id=row.wordlist_id or "",
        notes=row.notes or "",
        is_default=bool(row.is_default),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _clear_other_defaults(session: SessionDep, user_id: str, keep_id: Optional[str] = None) -> None:
    rows = session.exec(
        select(SettingsProfile).where(SettingsProfile.user_id == user_id, SettingsProfile.is_default == True)  # noqa: E712
    ).all()
    for row in rows:
        if keep_id and row.id == keep_id:
            continue
        row.is_default = False
        session.add(row)


def _get_owned(session: SessionDep, user: CurrentUser, profile_id: str) -> SettingsProfile:
    row = session.get(SettingsProfile, profile_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    return row


@router.get("", response_model=SettingsProfileListOut)
def list_profiles(session: SessionDep, user: CurrentUser):
    rows = session.exec(
        select(SettingsProfile)
        .where(SettingsProfile.user_id == user.id)
        .order_by(SettingsProfile.name)
    ).all()
    return SettingsProfileListOut(profiles=[_to_out(r) for r in rows])


@router.get("/match", response_model=SettingsProfileMatchOut)
def match_profile(
    session: SessionDep,
    user: CurrentUser,
    url: str = Query("", description="Target URL or hostname to match"),
):
    host = _normalize_host(url)
    rows: List[SettingsProfile] = session.exec(
        select(SettingsProfile).where(SettingsProfile.user_id == user.id)
    ).all()
    if not rows:
        return SettingsProfileMatchOut(profile=None, reason="no_profiles")

    matches = [r for r in rows if _host_matches(r.host_pattern or "", host)]
    if matches:
        matches.sort(key=lambda r: _specificity(r.host_pattern or ""), reverse=True)
        return SettingsProfileMatchOut(profile=_to_out(matches[0]), reason="host_pattern")

    defaults = [r for r in rows if r.is_default]
    if defaults:
        return SettingsProfileMatchOut(profile=_to_out(defaults[0]), reason="default")
    return SettingsProfileMatchOut(profile=None, reason="no_match")


@router.post("", response_model=SettingsProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(body: SettingsProfileCreate, session: SessionDep, user: CurrentUser):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    existing = session.exec(
        select(SettingsProfile).where(
            SettingsProfile.user_id == user.id,
            SettingsProfile.name == name,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="A profile with that name already exists")

    row = SettingsProfile(
        user_id=user.id,
        name=name,
        mode=(body.mode or "full_audit").strip() or "full_audit",
        speed=(body.speed or "balanced").strip() or "balanced",
        settings_json=dict(body.settings or {}),
        host_pattern=_normalize_host(body.host_pattern),
        wordlist_id=(body.wordlist_id or "").strip(),
        notes=(body.notes or "").strip(),
        is_default=bool(body.is_default),
    )
    if row.is_default:
        _clear_other_defaults(session, user.id)
    session.add(row)
    session.commit()
    session.refresh(row)
    return _to_out(row)


@router.get("/{profile_id}", response_model=SettingsProfileOut)
def get_profile(profile_id: str, session: SessionDep, user: CurrentUser):
    return _to_out(_get_owned(session, user, profile_id))


@router.patch("/{profile_id}", response_model=SettingsProfileOut)
def update_profile(
    profile_id: str,
    body: SettingsProfileUpdate,
    session: SessionDep,
    user: CurrentUser,
):
    row = _get_owned(session, user, profile_id)
    data = body.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        new_name = str(data["name"]).strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="Name is required")
        clash = session.exec(
            select(SettingsProfile).where(
                SettingsProfile.user_id == user.id,
                SettingsProfile.name == new_name,
                SettingsProfile.id != row.id,
            )
        ).first()
        if clash:
            raise HTTPException(status_code=409, detail="A profile with that name already exists")
        row.name = new_name
    if "mode" in data and data["mode"] is not None:
        row.mode = str(data["mode"]).strip() or row.mode
    if "speed" in data and data["speed"] is not None:
        row.speed = str(data["speed"]).strip() or row.speed
    if "settings" in data and data["settings"] is not None:
        row.settings_json = dict(data["settings"] or {})
    if "host_pattern" in data and data["host_pattern"] is not None:
        row.host_pattern = _normalize_host(str(data["host_pattern"]))
    if "wordlist_id" in data and data["wordlist_id"] is not None:
        row.wordlist_id = str(data["wordlist_id"] or "").strip()
    if "notes" in data and data["notes"] is not None:
        row.notes = str(data["notes"] or "").strip()
    if "is_default" in data and data["is_default"] is not None:
        row.is_default = bool(data["is_default"])
        if row.is_default:
            _clear_other_defaults(session, user.id, keep_id=row.id)
    row.updated_at = datetime.utcnow()
    session.add(row)
    session.commit()
    session.refresh(row)
    return _to_out(row)


@router.delete("/{profile_id}", response_model=MessageOut)
def delete_profile(profile_id: str, session: SessionDep, user: CurrentUser):
    row = _get_owned(session, user, profile_id)
    session.delete(row)
    session.commit()
    return MessageOut(message="Profile deleted")
