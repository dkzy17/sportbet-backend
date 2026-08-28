"""
One-off script to bootstrap the first superuser account.

IMPORTANT:
- Never put the superuser password directly in this file.
- Set SUPERUSER_PASSWORD as an environment variable before running.
- This file is safe to commit to GitHub.
"""

import os

from database import SessionLocal, Base, engine, User, Wallet
from auth import hash_password


USERNAME = os.getenv(
    "SUPERUSER_USERNAME",
    "super@elitexbets.com"
)

EMAIL = os.getenv(
    "SUPERUSER_EMAIL",
    "super@elitexbets.com"
)

PASSWORD = os.getenv("SUPERUSER_PASSWORD")

if not PASSWORD:
    raise RuntimeError(
        "SUPERUSER_PASSWORD is not set. "
        "Set it as an environment variable before running this script."
    )

if len(PASSWORD) < 12:
    raise RuntimeError(
        "SUPERUSER_PASSWORD must be at least 12 characters long."
    )


Base.metadata.create_all(bind=engine)

db = SessionLocal()

try:
    existing = (
        db.query(User)
        .filter(
            (User.username == USERNAME) |
            (User.email == EMAIL)
        )
        .first()
    )

    if existing:
        print(
            f"A user with that username/email already exists "
            f"(id={existing.id}, role={existing.role})."
        )
        print("Nothing changed.")

    else:
        superuser = User(
            username=USERNAME,
            email=EMAIL,
            hashed_password=hash_password(PASSWORD),
            role="superuser",
            is_verified=True,
            is_active=True,
        )

        db.add(superuser)
        db.commit()
        db.refresh(superuser)

        wallet = Wallet(
            owner_id=superuser.id,
            balance=0.0,
            bonus_balance=0.0,
        )

        db.add(wallet)
        db.commit()

        print(
            f"Superuser created successfully: "
            f"id={superuser.id}, "
            f"username={superuser.username}, "
            f"role={superuser.role}"
        )

finally:
    db.close()