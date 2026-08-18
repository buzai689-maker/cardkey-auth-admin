"""Seed demo card types + a batch of cards. Run: python -m scripts.seed"""
from app.database import SessionLocal, init_db
from app.main import bootstrap_admin
from app.models import CardType
from app.services.cards import generate_cards


def run() -> None:
    init_db()
    bootstrap_admin()
    db = SessionLocal()
    try:
        if db.query(CardType).count() == 0:
            types = [
                CardType(name="天卡", kind="time", duration_minutes=1440, max_devices=1),
                CardType(name="周卡", kind="time", duration_minutes=1440 * 7, max_devices=1),
                CardType(name="月卡", kind="time", duration_minutes=1440 * 30, max_devices=2),
                CardType(name="永久卡", kind="time", is_permanent=True, max_devices=3),
                CardType(name="点卡100次", kind="count", total_count=100, max_devices=1),
            ]
            db.add_all(types)
            db.commit()
            day = db.query(CardType).filter_by(name="天卡").first()
            batch, created = generate_cards(
                db, day, 10, prefix="DAY-", length=12, group_size=4, created_by="seed"
            )
            print(f"seeded {len(types)} card types, batch {batch} with {len(created)} cards")
        else:
            print("card types already exist, skip seeding")
    finally:
        db.close()


if __name__ == "__main__":
    run()
