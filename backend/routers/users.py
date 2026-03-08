import bcrypt
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from templating import templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import User, get_db

router = APIRouter(prefix="/users")

VALID_ROLES = {"admin", "editor", "readonly"}


@router.post("/me/password")
async def change_own_password(
    request: Request,
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Allow any logged-in user to change their own password."""
    user = request.state.current_user
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=303)
    db_user = await db.get(User, user.id)
    if db_user:
        db_user.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        await db.commit()
    # Redirect back to referrer or dashboard
    ref = request.headers.get("referer", "/")
    return RedirectResponse(url=ref, status_code=303)


@router.get("", response_class=HTMLResponse)
async def users_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    return templates.TemplateResponse("users.html", {
        "request": request,
        "users": users,
        "active_page": "users",
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
    })


@router.post("/add")
async def add_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("readonly"),
    db: AsyncSession = Depends(get_db),
):
    if role not in VALID_ROLES:
        role = "readonly"
    existing = (await db.execute(select(User).where(User.username == username.strip()))).scalar_one_or_none()
    if existing:
        return RedirectResponse(url="/users?error=exists", status_code=303)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.add(User(username=username.strip(), password_hash=pw_hash, role=role))
    await db.commit()
    return RedirectResponse(url="/users?saved=1", status_code=303)


@router.post("/{user_id}/role")
async def update_role(
    user_id: int,
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if role not in VALID_ROLES:
        return RedirectResponse(url="/users?error=invalid_role", status_code=303)
    user = await db.get(User, user_id)
    if not user:
        return RedirectResponse(url="/users", status_code=303)
    if user.role == "admin" and role != "admin":
        admins = (await db.execute(select(User).where(User.role == "admin"))).scalars().all()
        if len(admins) <= 1:
            return RedirectResponse(url="/users?error=last_admin", status_code=303)
    user.role = role
    await db.commit()
    return RedirectResponse(url="/users?saved=1", status_code=303)


@router.post("/{user_id}/password")
async def reset_password(
    user_id: int,
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        return RedirectResponse(url="/users", status_code=303)
    user.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    await db.commit()
    return RedirectResponse(url="/users?saved=1", status_code=303)


@router.post("/{user_id}/delete")
async def delete_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    current = request.state.current_user
    if current and current.id == user_id:
        return RedirectResponse(url="/users?error=self_delete", status_code=303)
    user = await db.get(User, user_id)
    if not user:
        return RedirectResponse(url="/users", status_code=303)
    if user.role == "admin":
        admins = (await db.execute(select(User).where(User.role == "admin"))).scalars().all()
        if len(admins) <= 1:
            return RedirectResponse(url="/users?error=last_admin", status_code=303)
    await db.delete(user)
    await db.commit()
    return RedirectResponse(url="/users?saved=1", status_code=303)
