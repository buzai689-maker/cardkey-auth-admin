from datetime import datetime, timedelta

from ..models import Card, CardType
from ..security import random_code


def make_batch_no() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def generate_cards(
    db,
    card_type: CardType,
    count: int,
    prefix: str = "",
    length: int = 16,
    group_size: int = 0,
    created_by: str = "",
    remark: str = "",
) -> tuple[str, list[Card]]:
    """Batch-create unique card codes for a card type. Returns (batch_no, cards)."""
    batch = make_batch_no()
    seen: set[str] = set()
    created: list[Card] = []
    attempts = 0
    max_attempts = count * 5 + 100
    while len(created) < count and attempts < max_attempts:
        attempts += 1
        code = random_code(length=length, prefix=prefix, group_size=group_size)
        if code in seen:
            continue
        if db.query(Card.id).filter_by(code=code).first():
            continue
        seen.add(code)
        card = Card(
            code=code,
            type_id=card_type.id,
            status="unused",
            max_devices=card_type.max_devices,
            remaining_count=card_type.total_count if card_type.kind == "count" else 0,
            batch_no=batch,
            remark=remark,
            created_by=created_by,
        )
        db.add(card)
        created.append(card)
    db.commit()
    return batch, created


def find_or_create_time_type(db, days: int, is_permanent: bool, max_devices: int) -> CardType:
    """Reuse (or lazily create) a time card template matching days + device count.

    Lets the generate page work directly off 授权天数 / 授权设备数 without the
    operator having to pre-define card types; identical (days, devices) combos
    collapse onto one template instead of piling up duplicates.
    """
    duration = 0 if is_permanent else max(0, days) * 1440
    max_devices = max(1, max_devices)
    t = (
        db.query(CardType)
        .filter_by(
            kind="time",
            is_permanent=is_permanent,
            duration_minutes=duration,
            max_devices=max_devices,
            total_count=0,
        )
        .first()
    )
    if t:
        return t
    name = f"永久·{max_devices}设备" if is_permanent else f"{days}天·{max_devices}设备"
    t = CardType(
        name=name,
        kind="time",
        duration_minutes=duration,
        is_permanent=is_permanent,
        total_count=0,
        max_devices=max_devices,
        is_active=True,
        remark="生成时自动创建",
    )
    db.add(t)
    db.commit()
    return t


def unbind_all_devices(db, card: Card) -> int:
    """Unbind every active device of a card (frees binding slots), keeping the
    card's own status/expiry unchanged. Returns how many were unbound."""
    n = 0
    for d in card.devices:
        if d.status == "active":
            d.status = "unbound"
            d.unbound_at = datetime.now()
            n += 1
    if n:
        db.commit()
    return n


def set_status(db, card: Card, status: str) -> None:
    card.status = status
    db.commit()


def extend_expiry(db, card: Card, add_minutes: int) -> None:
    """Extend (or shorten with a negative value) an activated card's expiry."""
    base = card.expires_at or datetime.now()
    card.expires_at = base + timedelta(minutes=add_minutes)
    db.commit()


def reset_card(db, card: Card) -> None:
    """Unbind all devices and return the card to an unused/unactivated state."""
    for d in card.devices:
        if d.status == "active":
            d.status = "unbound"
            d.unbound_at = datetime.now()
    card.status = "unused"
    card.activated_at = None
    card.expires_at = None
    if card.type and card.type.kind == "count":
        card.remaining_count = card.type.total_count
    db.commit()
