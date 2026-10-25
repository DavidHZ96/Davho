from __future__ import annotations

import hashlib
import html
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import License
from app.passwords import verify_dashboard_password
from app.rate_limit import enforce_rate_limit
from app.schemas import CreateLicenseRequest, LicenseType
from app.security import activation_code_hash, as_utc, generate_activation_code, utc_now

SESSION_COOKIE = "nikado_admin_session"
LOGIN_COOKIE = "nikado_admin_login"
SESSION_TTL_SECONDS = 30 * 60
LOGIN_TTL_SECONDS = 10 * 60
FLASH_TTL_SECONDS = 60
MAX_FORM_BYTES = 16 * 1024
MAX_SESSIONS = 256
MAX_LOGIN_CHALLENGES = 512
PAGE_SIZE = 50


@dataclass
class LoginChallenge:
    csrf_token: str
    expires_at: float


@dataclass
class DashboardSession:
    csrf_token: str
    expires_at: float
    flash_activation_code: str | None = None
    flash_license_id: str | None = None
    flash_notice: str | None = None
    flash_expires_at: float | None = None


def _digest_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _status(record: License, now: datetime | None = None) -> str:
    if record.activation_status == "revoked":
        return "revoked"
    expires_at = as_utc(record.expires_at)
    if expires_at is not None and expires_at <= (now or utc_now()):
        return "expired"
    return record.activation_status


def _date_label(value: datetime | None) -> str:
    if value is None:
        return "—"
    normalized = as_utc(value)
    assert normalized is not None
    return normalized.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _secure_cookie(request: Request, app: FastAPI) -> bool:
    return app.state.settings.app_env == "production" or request.url.scheme == "https"


def _set_cookie(
    response: Response,
    request: Request,
    app: FastAPI,
    name: str,
    value: str,
    max_age: int,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        path="/",
        secure=_secure_cookie(request, app),
        httponly=True,
        samesite="strict",
    )


def _clear_cookie(response: Response, request: Request, app: FastAPI, name: str) -> None:
    response.delete_cookie(
        key=name,
        path="/",
        secure=_secure_cookie(request, app),
        httponly=True,
        samesite="strict",
    )


def _page_response(content: str, status_code: int = 200) -> HTMLResponse:
    nonce = secrets.token_urlsafe(18)
    document = f"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>پنل مدیریت مجوزها | نیکادو یار</title>
  <style nonce="{nonce}">
    :root {{ color-scheme: light; font-family: Tahoma, Arial, sans-serif; background: #f3f6fb; color: #172033; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; background: linear-gradient(145deg, #f4f7fc, #eaf0fa); }}
    main {{ width: min(1180px, calc(100% - 28px)); margin: 32px auto; }}
    .topbar, .card {{ background: #fff; border: 1px solid #e1e7f0; border-radius: 16px; box-shadow: 0 8px 28px #1b31520b; }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 22px 26px; margin-bottom: 20px; }}
    .card {{ padding: 22px; margin-bottom: 18px; }}
    h1 {{ margin: 0 0 7px; font-size: clamp(1.35rem, 3vw, 1.9rem); }}
    h2 {{ margin: 0 0 16px; font-size: 1.18rem; }}
    p {{ line-height: 1.85; }}
    .muted {{ color: #68758a; }}
    label {{ display: block; font-weight: 700; margin: 0 0 7px; }}
    input, select {{ width: 100%; min-height: 44px; padding: 10px 12px; border: 1px solid #ccd5e2; border-radius: 9px; background: #fff; color: inherit; font: inherit; }}
    input:focus, select:focus, button:focus-visible, a:focus-visible {{ outline: 3px solid #9dbbff; outline-offset: 2px; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
    .field {{ margin-bottom: 15px; }}
    button, .button {{ display: inline-flex; align-items: center; justify-content: center; min-height: 42px; padding: 9px 16px; border: 0; border-radius: 9px; background: #2457c5; color: #fff; font: inherit; font-weight: 700; text-decoration: none; cursor: pointer; }}
    button:hover, .button:hover {{ background: #1949ae; }}
    .button-secondary {{ background: #edf2fa; color: #23324d; }}
    .button-secondary:hover {{ background: #dfe8f7; }}
    .button-danger {{ min-height: 36px; padding: 7px 12px; background: #a92735; font-size: .9rem; }}
    .button-danger:hover {{ background: #851c28; }}
    .notice {{ padding: 14px 16px; border: 1px solid #bdd8c8; border-radius: 11px; background: #effaf3; margin-bottom: 18px; }}
    .error {{ border-color: #f0c3c3; background: #fff3f3; color: #8d1d28; }}
    .code-row {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 12px 0; }}
    code {{ direction: ltr; unicode-bidi: isolate; display: inline-block; padding: 9px 12px; border-radius: 8px; background: #f0f3f8; color: #19243a; overflow-wrap: anywhere; }}
    .filters {{ display: grid; grid-template-columns: minmax(180px, 2fr) repeat(2, minmax(140px, 1fr)) auto; gap: 10px; align-items: end; margin-bottom: 16px; }}
    .table-wrap {{ width: 100%; overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 850px; }}
    th, td {{ padding: 12px 10px; border-bottom: 1px solid #e8edf4; text-align: right; vertical-align: middle; }}
    th {{ color: #56647b; font-size: .9rem; white-space: nowrap; }}
    td {{ line-height: 1.65; }}
    .badge {{ display: inline-block; padding: 4px 9px; border-radius: 999px; background: #edf2fa; white-space: nowrap; font-size: .88rem; }}
    .badge-active {{ background: #e6f7ed; color: #17623a; }}
    .badge-revoked, .badge-expired {{ background: #fdebed; color: #9c2730; }}
    .pagination {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 16px; }}
    .login-card {{ max-width: 460px; margin: 9vh auto; }}
    .small {{ font-size: .9rem; }}
    @media (max-width: 760px) {{ main {{ margin: 14px auto; }} .topbar {{ align-items: flex-start; flex-direction: column; }} .grid, .filters {{ grid-template-columns: 1fr; }} .card {{ padding: 17px; }} }}
  </style>
</head>
<body><main>{content}</main>
<script nonce="{nonce}">
  document.querySelectorAll('[data-copy]').forEach((button) => {{
    button.addEventListener('click', async () => {{
      const target = document.getElementById(button.dataset.copy);
      const message = document.getElementById('copy-message');
      if (!target) return;
      try {{
        await navigator.clipboard.writeText(target.textContent.trim());
        if (message) message.textContent = 'کد کپی شد.';
      }} catch (_) {{
        if (message) message.textContent = 'کپی خودکار انجام نشد؛ کد را انتخاب و دستی کپی کنید.';
      }}
    }});
  }});
  document.querySelectorAll('form[data-confirm]').forEach((form) => {{
    form.addEventListener('submit', (event) => {{
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    }});
  }});
</script>
</body></html>"""
    response = HTMLResponse(content=document, status_code=status_code)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


def _issue_login_challenge(app: FastAPI) -> tuple[str, str]:
    raw_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = time.time()
    with app.state.dashboard_lock:
        expired = [
            key for key, challenge in app.state.dashboard_login_challenges.items()
            if challenge.expires_at <= now
        ]
        for key in expired:
            app.state.dashboard_login_challenges.pop(key, None)
        if len(app.state.dashboard_login_challenges) >= MAX_LOGIN_CHALLENGES:
            oldest = next(iter(app.state.dashboard_login_challenges))
            app.state.dashboard_login_challenges.pop(oldest, None)
        app.state.dashboard_login_challenges[_digest_token(raw_id)] = LoginChallenge(
            csrf_token=csrf_token,
            expires_at=now + LOGIN_TTL_SECONDS,
        )
    return raw_id, csrf_token


def _new_dashboard_session(app: FastAPI) -> tuple[str, DashboardSession]:
    raw_id = secrets.token_urlsafe(32)
    now = time.time()
    session = DashboardSession(
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + SESSION_TTL_SECONDS,
    )
    with app.state.dashboard_lock:
        expired = [
            key for key, value in app.state.dashboard_sessions.items()
            if value.expires_at <= now
        ]
        for key in expired:
            app.state.dashboard_sessions.pop(key, None)
        if len(app.state.dashboard_sessions) >= MAX_SESSIONS:
            oldest = next(iter(app.state.dashboard_sessions))
            app.state.dashboard_sessions.pop(oldest, None)
        app.state.dashboard_sessions[_digest_token(raw_id)] = session
    return raw_id, session


def _get_dashboard_session(request: Request) -> tuple[str, DashboardSession] | None:
    raw_id = request.cookies.get(SESSION_COOKIE)
    if not raw_id:
        return None
    key = _digest_token(raw_id)
    now = time.time()
    with request.app.state.dashboard_lock:
        session = request.app.state.dashboard_sessions.get(key)
        if session is None:
            return None
        if session.expires_at <= now:
            request.app.state.dashboard_sessions.pop(key, None)
            return None
        if session.flash_expires_at is not None and session.flash_expires_at <= now:
            session.flash_activation_code = None
            session.flash_license_id = None
            session.flash_notice = None
            session.flash_expires_at = None
        return key, session


def _render_login(csrf_token: str, error: str | None = None, status_code: int = 200) -> HTMLResponse:
    error_html = f'<div class="notice error" role="alert">{html.escape(error)}</div>' if error else ""
    content = f"""
<section class="card login-card">
  <h1>پنل مدیریت مجوزها</h1>
  <p class="muted">برای مدیریت مجوزهای نیکادو یار وارد شوید.</p>
  {error_html}
  <form method="post" action="/admin/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
    <div class="field">
      <label for="dashboard-password">&#x06AF;&#x0630;&#x0631;&#x0648;&#x0627;&#x0698;&#x0647; &#x067E;&#x0646;&#x0644; &#x0645;&#x062F;&#x06CC;&#x0631;&#x06CC;&#x062A;</label>
  <input id="dashboard-password" name="dashboard_password" type="password" autocomplete="current-password" required maxlength="512" autofocus>
    </div>
    <button type="submit">ورود امن</button>
  </form>
</section>"""
    return _page_response(content, status_code)


async def _read_form(request: Request) -> dict[str, list[str]] | None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return None
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_FORM_BYTES:
                return None
        except ValueError:
            return None
    body = await request.body()
    if len(body) > MAX_FORM_BYTES:
        return None
    try:
        return parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=20,
            strict_parsing=False,
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _single_value(form: dict[str, list[str]], name: str) -> str | None:
    values = form.get(name)
    if values is None or len(values) != 1:
        return None
    return values[0]


def _csrf_ok(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and supplied.isascii() and secrets.compare_digest(expected, supplied)


def _forbidden_page(message: str = "درخواست معتبر نیست. صفحه را تازه‌سازی و دوباره تلاش کنید.") -> HTMLResponse:
    return _page_response(f'<section class="card"><h1>درخواست پذیرفته نشد</h1><p>{html.escape(message)}</p><a class="button button-secondary" href="/admin">بازگشت</a></section>', 403)


def _redirect_to_admin() -> RedirectResponse:
    response = RedirectResponse(url="/admin", status_code=303)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


def _matches(record: License, query: str, status_filter: str, type_filter: str) -> bool:
    current_status = _status(record)
    if status_filter and current_status != status_filter:
        return False
    if type_filter and record.license_type != type_filter:
        return False
    if query:
        lowered = query.casefold()
        if lowered not in record.customer_name.casefold() and lowered not in record.license_id.casefold():
            return False
    return True


def _dashboard_content(
    csrf_token: str,
    records: list[License],
    total: int,
    page_number: int,
    query: str,
    status_filter: str,
    type_filter: str,
    flash_code: str | None,
    flash_license_id: str | None,
    flash_notice: str | None,
    error: str | None,
) -> str:
    notice_html = ""
    if flash_code:
        safe_code = html.escape(flash_code)
        safe_id = html.escape(flash_license_id or "")
        notice_html = f"""
<section class="notice" aria-live="polite">
  <strong>مجوز ساخته شد. کد فعال‌سازی فقط همین یک‌بار نمایش داده می‌شود.</strong>
  <p>کد را امن ذخیره کنید و از طریق امن به مشتری بدهید. این کد پس از بستن یا تازه‌سازی صفحه دوباره نمایش داده نمی‌شود.</p>
  <div class="code-row"><code id="activation-code">{safe_code}</code><button class="button-secondary" type="button" data-copy="activation-code">کپی کد</button></div>
  <p id="copy-message" class="small" role="status"></p>
  <p class="small muted">شناسه مجوز: <code>{safe_id}</code></p>
</section>"""
    if flash_notice:
        notice_html += f'<div class="notice" role="status">{html.escape(flash_notice)}</div>'
    if error:
        notice_html += f'<div class="notice error" role="alert">{html.escape(error)}</div>'

    license_rows: list[str] = []
    status_labels = {
        "pending": ("در انتظار فعال‌سازی", ""),
        "active": ("فعال", "badge-active"),
        "revoked": ("لغوشده", "badge-revoked"),
        "expired": ("منقضی‌شده", "badge-expired"),
    }
    for record in records:
        current_status = _status(record)
        status_label, badge_class = status_labels.get(current_status, (current_status, ""))
        license_type_label = "مادام‌العمر" if record.license_type == LicenseType.lifetime.value else "سالانه"
        device_label = "ثبت شده" if record.registered_device_id else "ثبت نشده"
        if record.expires_at is not None:
            expiry_label = _date_label(record.expires_at)
        elif record.license_type == LicenseType.annual.value and current_status == "pending":
            expiry_label = "پس از فعال‌سازی"
        else:
            expiry_label = "—"
        action = ""
        if current_status not in {"revoked", "expired"}:
            action = f"""
<form method="post" action="/admin/licenses/{html.escape(record.license_id, quote=True)}/revoke" data-confirm="آیا از لغو این مجوز مطمئن هستید؟">
  <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
  <button class="button-danger" type="submit">لغو مجوز</button>
</form>"""
        license_rows.append(f"""
<tr>
  <td>{html.escape(record.customer_name)}</td>
  <td><code>{html.escape(record.license_id)}</code></td>
  <td>{license_type_label}</td>
  <td><span class="badge {badge_class}">{status_label}</span></td>
  <td>{device_label}</td>
  <td>{_date_label(record.created_at)}</td>
  <td>{expiry_label}</td>
  <td>{action}</td>
</tr>""")
    if not license_rows:
        license_rows.append('<tr><td colspan="8" class="muted">مجوزی برای این فیلتر پیدا نشد.</td></tr>')

    filter_options = {
        "": "همه وضعیت‌ها",
        "pending": "در انتظار فعال‌سازی",
        "active": "فعال",
        "revoked": "لغوشده",
        "expired": "منقضی‌شده",
    }
    status_options = "".join(
        f'<option value="{value}"{" selected" if value == status_filter else ""}>{label}</option>'
        for value, label in filter_options.items()
    )
    type_options = "".join(
        f'<option value="{value}"{" selected" if value == type_filter else ""}>{label}</option>'
        for value, label in (("", "همه انواع"), ("lifetime", "مادام‌العمر"), ("annual", "سالانه"))
    )
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    previous_html = ""
    next_html = ""
    common_query = {key: value for key, value in (("q", query), ("status", status_filter), ("type", type_filter)) if value}
    if page_number > 1:
        previous_params = dict(common_query, page=page_number - 1)
        previous_html = f'<a class="button button-secondary" href="/admin?{html.escape(urlencode(previous_params), quote=True)}">صفحه قبل</a>'
    if page_number < total_pages:
        next_params = dict(common_query, page=page_number + 1)
        next_html = f'<a class="button button-secondary" href="/admin?{html.escape(urlencode(next_params), quote=True)}">صفحه بعد</a>'

    return f"""
<header class="topbar">
  <div><h1>مدیریت مجوزهای نیکادو یار</h1><p class="muted">ساخت و پیگیری مجوز مشتریان</p></div>
  <form method="post" action="/admin/logout">
    <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
    <button class="button-secondary" type="submit">خروج امن</button>
  </form>
</header>
{notice_html}
<section class="card">
  <h2>ساخت مجوز مشتری</h2>
  <form method="post" action="/admin/licenses">
    <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
    <div class="grid">
      <div class="field"><label for="customer-name">نام فروشگاه یا مشتری</label><input id="customer-name" name="customer_name" maxlength="200" required autocomplete="organization"></div>
      <div class="field"><label for="license-type">نوع مجوز</label><select id="license-type" name="license_type" required><option value="lifetime">مادام‌العمر</option><option value="annual">سالانه</option></select></div>
    </div>
    <p class="muted small">هر مجوز به‌طور پیش‌فرض برای یک رایانه ثبت می‌شود. مجوز سالانه از زمان فعال‌سازی به مدت یک سال اعتبار دارد.</p>
    <button type="submit">ساخت مجوز و نمایش کد</button>
  </form>
</section>
<section class="card" id="licenses">
  <h2>مجوزهای ثبت‌شده <span class="muted small">({total})</span></h2>
  <form class="filters" method="get" action="/admin">
    <div><label for="search">جست‌وجو</label><input id="search" name="q" value="{html.escape(query, quote=True)}" maxlength="100" placeholder="نام مشتری یا شناسه مجوز"></div>
    <div><label for="status">وضعیت</label><select id="status" name="status">{status_options}</select></div>
    <div><label for="type">نوع مجوز</label><select id="type" name="type">{type_options}</select></div>
    <button type="submit">اعمال فیلتر</button>
  </form>
  <div class="table-wrap"><table>
    <thead><tr><th>مشتری / فروشگاه</th><th>شناسه مجوز</th><th>نوع</th><th>وضعیت</th><th>دستگاه</th><th>تاریخ ایجاد (UTC)</th><th>انقضا</th><th>عملیات</th></tr></thead>
    <tbody>{''.join(license_rows)}</tbody>
  </table></div>
  <nav class="pagination" aria-label="صفحه‌بندی"><span class="muted small">صفحه {page_number} از {total_pages}</span><span>{previous_html} {next_html}</span></nav>
</section>"""


def install_admin_dashboard(app: FastAPI) -> None:
    app.state.dashboard_lock = threading.RLock()
    app.state.dashboard_sessions: dict[str, DashboardSession] = {}
    app.state.dashboard_login_challenges: dict[str, LoginChallenge] = {}

    @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin_home(
        request: Request,
        q: str = Query(default="", max_length=100),
        status_filter: str = Query(default="", alias="status"),
        type_filter: str = Query(default="", alias="type"),
        page_number: int = Query(default=1, ge=1),
        db: Session = Depends(get_db),
    ) -> Response:
        found_session = _get_dashboard_session(request)
        if found_session is None:
            raw_id, csrf_token = _issue_login_challenge(app)
            response = _render_login(csrf_token)
            _set_cookie(response, request, app, LOGIN_COOKIE, raw_id, LOGIN_TTL_SECONDS)
            if request.cookies.get(SESSION_COOKIE):
                _clear_cookie(response, request, app, SESSION_COOKIE)
            return response

        session_key, session_data = found_session
        flash_code = None
        flash_license_id = None
        flash_notice = None
        with app.state.dashboard_lock:
            current = app.state.dashboard_sessions.get(session_key)
            if current is not None:
                if current.flash_expires_at is None or current.flash_expires_at > time.time():
                    flash_code = current.flash_activation_code
                    flash_license_id = current.flash_license_id
                    flash_notice = current.flash_notice
                current.flash_activation_code = None
                current.flash_license_id = None
                current.flash_notice = None
                current.flash_expires_at = None

        allowed_statuses = {"pending", "active", "revoked", "expired"}
        if status_filter not in allowed_statuses:
            status_filter = ""
        if type_filter not in {LicenseType.lifetime.value, LicenseType.annual.value}:
            type_filter = ""
        query = q.strip()
        predicates: list[Any] = []
        if query:
            escaped_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped_query}%"
            predicates.append(or_(License.customer_name.ilike(pattern, escape="\\"), License.license_id.ilike(pattern, escape="\\")))
        if type_filter:
            predicates.append(License.license_type == type_filter)
        now = utc_now()
        if status_filter == "pending":
            predicates.append(License.activation_status == "pending")
        elif status_filter == "active":
            predicates.extend((License.activation_status == "active", or_(License.expires_at.is_(None), License.expires_at > now)))
        elif status_filter == "revoked":
            predicates.append(License.activation_status == "revoked")
        elif status_filter == "expired":
            predicates.extend((License.activation_status != "revoked", License.expires_at.is_not(None), License.expires_at <= now))

        total = int(db.scalar(select(func.count()).select_from(License).where(*predicates)) or 0)
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        if page_number > total_pages:
            page_number = total_pages
        records = db.scalars(
            select(License)
            .where(*predicates)
            .order_by(License.created_at.desc(), License.license_id.desc())
            .offset((page_number - 1) * PAGE_SIZE)
            .limit(PAGE_SIZE)
        ).all()
        # The SQL filters handle the common cases. Apply effective status and search
        # in Python as a final consistency check for timestamps and database dialects.
        records = [record for record in records if _matches(record, query, status_filter, type_filter)]
        return _page_response(
            _dashboard_content(
                csrf_token=session_data.csrf_token,
                records=records,
                total=total,
                page_number=page_number,
                query=query,
                status_filter=status_filter,
                type_filter=type_filter,
                flash_code=flash_code,
                flash_license_id=flash_license_id,
                flash_notice=flash_notice,
                error="مجوز پیدا نشد." if request.query_params.get("error") == "not-found" else None,
            )
        )

    @app.post("/admin/login", response_class=HTMLResponse, include_in_schema=False)
    async def admin_login(request: Request) -> Response:
        enforce_rate_limit(request, "dashboard-login", 5)
        form = await _read_form(request)
        if form is None:
            return _forbidden_page("فرم ورود معتبر نیست.")
        raw_login_id = request.cookies.get(LOGIN_COOKIE)
        csrf_value = _single_value(form, "csrf_token")
        if not raw_login_id:
            return _forbidden_page("فرم ورود منقضی شده است. صفحه را تازه‌سازی کنید.")
        login_key = _digest_token(raw_login_id)
        with app.state.dashboard_lock:
            challenge = app.state.dashboard_login_challenges.pop(login_key, None)
        if challenge is None or challenge.expires_at <= time.time() or not _csrf_ok(challenge.csrf_token, csrf_value):
            return _forbidden_page("فرم ورود منقضی شده است. صفحه را تازه‌سازی کنید.")

        supplied_password = _single_value(form, "dashboard_password")
        password_hash = app.state.settings.dashboard_password_hash
        if not password_hash:
            raw_id, new_csrf = _issue_login_challenge(app)
            response = _render_login(new_csrf, "ورود مدیر برای این سرور پیکربندی نشده است.", 503)
            _set_cookie(response, request, app, LOGIN_COOKIE, raw_id, LOGIN_TTL_SECONDS)
            return response
        if not verify_dashboard_password(supplied_password, password_hash):
            raw_id, new_csrf = _issue_login_challenge(app)
            response = _render_login(new_csrf, "ورود ناموفق بود. توکن مدیریت را بررسی کنید.", 401)
            _set_cookie(response, request, app, LOGIN_COOKIE, raw_id, LOGIN_TTL_SECONDS)
            return response

        session_id, session_data = _new_dashboard_session(app)
        response = RedirectResponse(url="/admin", status_code=303)
        response.headers["Cache-Control"] = "no-store, max-age=0"
        _set_cookie(response, request, app, SESSION_COOKIE, session_id, SESSION_TTL_SECONDS)
        _clear_cookie(response, request, app, LOGIN_COOKIE)
        return response

    @app.post("/admin/logout", include_in_schema=False)
    async def admin_logout(request: Request) -> Response:
        found_session = _get_dashboard_session(request)
        if found_session is None:
            return _redirect_to_admin()
        session_key, session_data = found_session
        form = await _read_form(request)
        csrf_value = _single_value(form, "csrf_token") if form else None
        if not _csrf_ok(session_data.csrf_token, csrf_value):
            return _forbidden_page()
        with app.state.dashboard_lock:
            app.state.dashboard_sessions.pop(session_key, None)
        response = _redirect_to_admin()
        _clear_cookie(response, request, app, SESSION_COOKIE)
        return response

    @app.post("/admin/licenses", include_in_schema=False)
    async def dashboard_create_license(
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        found_session = _get_dashboard_session(request)
        if found_session is None:
            return _redirect_to_admin()
        session_key, session_data = found_session
        form = await _read_form(request)
        csrf_value = _single_value(form, "csrf_token") if form else None
        if not _csrf_ok(session_data.csrf_token, csrf_value):
            return _forbidden_page()
        enforce_rate_limit(request, "admin", 30)
        customer_name = _single_value(form, "customer_name") if form else None
        license_type = _single_value(form, "license_type") if form else None
        try:
            payload = CreateLicenseRequest.model_validate(
                {"customer_name": customer_name, "license_type": license_type}
            )
        except ValidationError:
            with app.state.dashboard_lock:
                current = app.state.dashboard_sessions.get(session_key)
                if current is not None:
                    current.flash_notice = "نام مشتری یا نوع مجوز معتبر نیست."
                    current.flash_expires_at = time.time() + FLASH_TTL_SECONDS
            return _redirect_to_admin()

        activation_code = generate_activation_code()
        record = License(
            license_id=str(uuid.uuid4()),
            customer_name=payload.customer_name,
            activation_code_hash=activation_code_hash(activation_code),
            registered_device_id=None,
            license_type=payload.license_type.value,
            expires_at=as_utc(payload.expires_at),
            activation_status="pending",
            created_at=utc_now(),
        )
        db.add(record)
        try:
            db.commit()
            db.refresh(record)
        except Exception:
            db.rollback()
            with app.state.dashboard_lock:
                current = app.state.dashboard_sessions.get(session_key)
                if current is not None:
                    current.flash_notice = "ساخت مجوز انجام نشد. دوباره تلاش کنید."
                    current.flash_expires_at = time.time() + FLASH_TTL_SECONDS
            return _page_response('<section class="card"><h1>ساخت مجوز انجام نشد</h1><p>لطفاً بعداً دوباره تلاش کنید.</p><a class="button" href="/admin">بازگشت</a></section>', 500)
        with app.state.dashboard_lock:
            current = app.state.dashboard_sessions.get(session_key)
            if current is not None:
                current.flash_activation_code = activation_code
                current.flash_license_id = record.license_id
                current.flash_notice = None
                current.flash_expires_at = time.time() + FLASH_TTL_SECONDS
        return _redirect_to_admin()

    @app.post("/admin/licenses/{license_id}/revoke", include_in_schema=False)
    async def dashboard_revoke_license(
        license_id: str,
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        found_session = _get_dashboard_session(request)
        if found_session is None:
            return _redirect_to_admin()
        _, session_data = found_session
        form = await _read_form(request)
        csrf_value = _single_value(form, "csrf_token") if form else None
        if not _csrf_ok(session_data.csrf_token, csrf_value):
            return _forbidden_page()
        enforce_rate_limit(request, "admin", 30)
        try:
            normalized_id = str(uuid.UUID(license_id))
        except ValueError:
            return _redirect_to_admin()
        record = db.get(License, normalized_id)
        if record is None:
            return _redirect_to_admin()
        if record.activation_status != "revoked":
            record.activation_status = "revoked"
            record.revoked_at = utc_now()
            record.revoked_reason = "Revoked from administrator dashboard"
            db.commit()
        return _redirect_to_admin()

