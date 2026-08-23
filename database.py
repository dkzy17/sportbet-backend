from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from datetime import datetime

engine = create_engine("sqlite:///./sportsbet.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")       # "user", "moderator", "superuser"
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, nullable=False)
    plan = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    wallet = relationship("Wallet", back_populates="owner", uselist=False)
    bets = relationship("Bet", back_populates="user")
    withdrawals = relationship("WithdrawalRequest", back_populates="user")

class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), unique=True)
    balance = Column(Float, default=0.0)
    bonus_balance = Column(Float, default=0.0)

    owner = relationship("User", back_populates="wallet")

class Bet(Base):
    __tablename__ = "bets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    outcome_choice = Column(String)   # e.g. "win" or "lose" — what the user picked
    status = Column(String, default="pending")  # "pending", "won", "lost"
    payout = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="bets")

class DepositRequest(Base):
    __tablename__ = "deposit_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    method = Column(String)              # "bank" or "crypto"
    amount = Column(Float)

    reference = Column(String, nullable=True)       # bank transfer ref, or crypto tx hash
    slip_filename = Column(String, nullable=True)    # uploaded proof-of-payment image, if provided

    status = Column(String, default="pending")  # "pending", "approved", "rejected"
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class WithdrawalRequest(Base):
    __tablename__ = "withdrawal_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    method = Column(String)              # "bank" or "crypto"
    amount = Column(Float)

    # filled in only if method == "bank"
    account_number = Column(String, nullable=True)
    account_name = Column(String, nullable=True)

    # filled in only if method == "crypto"
    crypto_address = Column(String, nullable=True)
    crypto_type = Column(String, nullable=True)

    status = Column(String, default="pending")  # "pending", "approved", "rejected"
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="withdrawals")

class OTP(Base):
    __tablename__ = "otps"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String)
    purpose = Column(String, default="verify_email")  # could reuse for password reset later
    expires_at = Column(DateTime)


class WithdrawalVerification(Base):
    __tablename__ = "withdrawal_verifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code = Column(String, nullable=False)
    status = Column(String, default="pending", nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    token_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    type = Column(String)           # "deposit", "bet_placed", "bet_payout", "withdrawal_requested", "withdrawal_approved", "withdrawal_rejected"
    amount = Column(Float)          # positive = money in, negative = money out
    balance_after = Column(Float)   # wallet balance right after this event
    description = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")