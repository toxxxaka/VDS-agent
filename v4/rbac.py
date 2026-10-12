"""Small role model shared by Recovery Studio and future controlled actions."""
from __future__ import annotations

ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def role_for(user: str, config: dict | None = None) -> str:
    """Resolve an explicit role; preserve existing single-owner deployments."""
    config = config or {}
    roles = config.get("roles", {})
    role = roles.get(str(user)) if isinstance(roles, dict) else None
    if role in ROLE_ORDER:
        return role
    # Existing installations used one authenticated owner role. Keep that
    # behaviour until an administrator deliberately supplies a roles mapping.
    return "admin" if str(user) in {str(value) for value in config.get("allowed_user_ids", [])} else "viewer"


def allowed(user: str, required: str, config: dict | None = None) -> bool:
    return ROLE_ORDER[role_for(user, config)] >= ROLE_ORDER[required]


def require(user: str, required: str, config: dict | None = None) -> str:
    role = role_for(user, config)
    if ROLE_ORDER[role] < ROLE_ORDER[required]:
        raise PermissionError(f"{required} role is required")
    return role
