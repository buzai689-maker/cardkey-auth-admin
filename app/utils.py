from datetime import datetime


def now() -> datetime:
    return datetime.now()


def client_ip(request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def paginate(query, page: int, per_page: int = 20):
    total = query.count()
    page = max(1, page)
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = max(1, (total + per_page - 1) // per_page)
    return items, {"page": page, "pages": pages, "total": total, "per_page": per_page}
