from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from templating import templates
import bcrypt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import User, get_db, is_setup_complete, set_setting

router = APIRouter(prefix="/setup")


@router.get("", response_class=HTMLResponse)
async def setup_page(request: Request, db: AsyncSession = Depends(get_db)):
    if await is_setup_complete(db):
        return RedirectResponse(url="/")
    return templates.TemplateResponse("setup.html", {"request": request})


@router.post("/complete")
async def complete_setup(
    site_name: str = Form("NODEGLOW"),
    username: str = Form("admin"),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    await set_setting(db, "site_name", site_name.strip() or "NODEGLOW")
    await set_setting(db, "setup_complete", "true")
    await set_setting(db, "ping_interval", "60")

    # Only create user if none exist
    count = (await db.execute(select(func.count()).select_from(User))).scalar()
    if count == 0 and password.strip():
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db.add(User(username=username.strip() or "admin", password_hash=pw_hash))
        await db.commit()

    return RedirectResponse(url="/", status_code=303)
