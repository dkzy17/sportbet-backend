"""
One-off script to bootstrap the first superuser account.

There's a chicken-and-egg problem with /admin/create-staff: it requires an
existing superuser to call it. Run this once, directly against the database,
to create that first account. After that, use /admin/create-staff (as this
user) to create any further staff accounts through the API instead.

Usage:
    python seed_superuser.py
"""

from database import SessionLocal, Base, engine, User, Wallet
from auth import hash_password

USERNAME = "super@elitexbets.com"
EMAIL = "super@elitexbets.com"
PASSWORD = "REMOVED_SECRET"

Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    existing = db.query(User).filter(
        (User.username == USERNAME) | (User.email == EMAIL)
    ).first()

    if existing:
        print(f"A user with that username/email already exists (id={existing.id}, role={existing.role}). Nothing changed.")
    else:
        su = User(
            username=USERNAME,
            email=EMAIL,
            hashed_password=hash_password(PASSWORD),
            role="superuser",
            is_verified=True,  # staff accounts skip OTP
        )
        db.add(su)
        db.commit()
        db.refresh(su)

        db.add(Wallet(owner_id=su.id))
        db.commit()

        print(f"Superuser created: id={su.id}, username={su.username}, role={su.role}")
finally:
    db.close()
