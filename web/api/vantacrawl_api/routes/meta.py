from __future__ import annotations

from fastapi import APIRouter

from ..deps import CurrentUser
from ..scan_settings import meta_payload
from ..schemas import MetaOut

router = APIRouter(prefix="/meta", tags=["meta"])


@router.get("/scan", response_model=MetaOut)
def scan_meta(_user: CurrentUser):
    return MetaOut(**meta_payload())
