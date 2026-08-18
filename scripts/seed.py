"""Seed a demo application + card types + a batch of cards.

Run: python -m scripts.seed
"""
from app.database import SessionLocal, init_db
from app.main import bootstrap_admin
from app.models import Application, CardType
from app.services.applications import create_application
from app.services.cards import find_or_create_time_type, generate_cards


def run() -> None:
    init_db()
    bootstrap_admin()
    db = SessionLocal()
    try:
        if db.query(Application).count() > 0:
            print("applications already exist, skip seeding")
            return

        app = create_application(db, "示例软件", remark="seed demo app")
        ct = find_or_create_time_type(db, 7, False, 2)  # 7天 / 2设备
        batch, created = generate_cards(
            db,
            ct,
            10,
            application_id=app.id,
            prefix="DAY-",
            length=12,
            group_size=4,
            created_by="seed",
        )
        print(
            f"seeded app '{app.name}' (app_key={app.app_key}); "
            f"batch {batch} with {len(created)} cards"
        )
    finally:
        db.close()


if __name__ == "__main__":
    run()
