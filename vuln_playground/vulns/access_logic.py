"""Access control, IDOR, mass assignment, business-logic flaws."""

from __future__ import annotations

import html
import json
from typing import Dict

from http_util import json_bytes, page, send
from registry import register

_USERS = {
    "1": {"id": 1, "email": "alice@example.com", "role": "user", "ssn": "111-22-3333"},
    "2": {"id": 2, "email": "bob@example.com", "role": "user", "ssn": "222-33-4444"},
    "3": {"id": 3, "email": "admin@example.com", "role": "admin", "ssn": "999-88-7777"},
}


@register(
    "/idor/user",
    title="IDOR user profile by id",
    family="idor",
    expected="insecure direct object reference — any id returns PII",
    tags=["active", "passive"],
)
def idor_user(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    uid = params.get("id", "1")
    user = _USERS.get(uid) or {"id": uid, "email": f"user{uid}@example.com", "role": "user", "ssn": "000-00-0000"}
    send(handler, 200, json_bytes(user), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/idor/invoice",
    title="IDOR invoice download",
    family="idor",
    expected="horizontal access — invoice by sequential id",
    tags=["active"],
)
def idor_invoice(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    inv = params.get("invoice_id", "1001")
    body = page("Invoice", f"<pre>INVOICE #{html.escape(inv)}\nAmount: $419.00\nCard: 4111-****-****-1111</pre>")
    send(handler, 200, body, head_only=head_only)


@register(
    "/mass-assign/profile",
    title="Mass assignment role escalation",
    family="mass_assignment",
    expected="role/isAdmin accepted from client JSON",
    tags=["active", "post"],
)
def mass_assign(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET" and not params:
        body = page(
            "Profile update",
            '<form method="POST" action="/mass-assign/profile">'
            '<input name="name" value="guest">'
            '<input name="role" value="admin">'
            '<input name="isAdmin" value="true">'
            '<button type="submit">Save</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    data = {
        "name": params.get("name", "guest"),
        "role": params.get("role", "user"),
        "isAdmin": params.get("isAdmin", "false"),
        "saved": True,
    }
    send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/logic/cart",
    title="Price / quantity manipulation",
    family="business_logic",
    expected="negative quantity or client-side price accepted",
    tags=["active", "post"],
)
def logic_cart(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET" and "qty" not in params:
        body = page(
            "Cart",
            '<form method="POST" action="/logic/cart">'
            '<input name="item" value="pro-plan">'
            '<input name="price" value="1">'
            '<input name="qty" value="-5">'
            '<button type="submit">Checkout</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    price_raw = params.get("price") or "0"
    qty_raw = params.get("qty") or "1"
    try:
        price = float(price_raw)
        qty = float(qty_raw)
    except (TypeError, ValueError):
        return send(
            handler,
            400,
            page(
                "Order",
                f"<p>Invalid price/qty "
                f"(price={html.escape(str(price_raw))}, qty={html.escape(str(qty_raw))})</p>",
            ),
            head_only=head_only,
        )
    total = price * qty
    send(
        handler,
        200,
        page("Order", f"<p>Total charged: <b>{html.escape(str(total))}</b></p>"),
        head_only=head_only,
    )


@register(
    "/logic/coupon",
    title="Coupon reuse / stack",
    family="business_logic",
    expected="same coupon accepted repeatedly",
    tags=["active"],
)
def logic_coupon(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    code = params.get("code", "SAVE100")
    send(
        handler,
        200,
        page("Coupon", f"<p>Applied {html.escape(code)} — discount $100 (no single-use check)</p>"),
        head_only=head_only,
    )


@register(
    "/bac/admin",
    title="Broken access control admin API",
    family="access_control",
    expected="admin actions without auth cookie",
    tags=["active", "passive"],
)
def bac_admin(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    action = params.get("action", "list_users")
    send(
        handler,
        200,
        json_bytes({"ok": True, "action": action, "users": list(_USERS.values())}),
        headers={"Content-Type": "application/json"},
        head_only=head_only,
    )
