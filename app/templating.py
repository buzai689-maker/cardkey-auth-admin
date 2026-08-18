from starlette.templating import Jinja2Templates

from .config import BASE_DIR, settings
from .services import settings as settings_svc

templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

STATUS_LABELS = {
    "unused": "未使用",
    "active": "已激活",
    "expired": "已过期",
    "banned": "已封禁",
    "used_up": "已用尽",
    "unbound": "已解绑",
}
STATUS_CLASS = {
    "unused": "muted",
    "active": "ok",
    "expired": "warn",
    "banned": "danger",
    "used_up": "warn",
    "unbound": "muted",
}


def _fmt_dt(v, fmt="%Y-%m-%d %H:%M:%S"):
    if not v:
        return "-"
    return v.strftime(fmt)


templates.env.filters["dt"] = _fmt_dt
templates.env.filters["status_label"] = lambda v: STATUS_LABELS.get(v, v)
templates.env.filters["status_class"] = lambda v: STATUS_CLASS.get(v, "muted")
templates.env.globals["app_name"] = settings.APP_NAME


def flash(request, message: str, category: str = "info") -> None:
    request.session.setdefault("_flashes", []).append({"m": message, "c": category})


def _pop_flashes(request):
    return request.session.pop("_flashes", [])


def render(request, template: str, **ctx):
    context = {
        "current_admin": getattr(request.state, "admin", None),
        "site": settings_svc.get_settings(),
        "flashes": _pop_flashes(request),
        "active": ctx.pop("active", ""),
    }
    context.update(ctx)
    return templates.TemplateResponse(request, template, context)
