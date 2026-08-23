from fastapi import UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
import shutil, uuid, os, secrets, string
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional
from jose import jwt

from database import engine, SessionLocal, Base, User, Wallet, Bet, WithdrawalRequest, OTP, Transaction, DepositRequest, WithdrawalVerification
from auth import hash_password, verify_password, create_access_token, decode_token, SECRET_KEY, ALGORITHM
from email_utils import generate_otp, send_otp_email

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Schemas ----------

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    code: str

class AmountRequest(BaseModel):
    amount: float

class UserStatusRequest(BaseModel):
    is_active: bool

class UserPlanRequest(BaseModel):
    plan: Optional[str] = None

class BetRequest(BaseModel):
    amount: float
    outcome_choice: str  # "win" or "lose"

class SettleBetRequest(BaseModel):
    result: str  # "won" or "lost"

class WithdrawalCreate(BaseModel):
    method: str  # "bank" or "crypto"
    amount: float
    account_number: Optional[str] = None
    account_name: Optional[str] = None
    crypto_address: Optional[str] = None
    crypto_type: Optional[str] = None
    verification_token: str


class WithdrawalVerificationCode(BaseModel):
    code: str

class PasswordReset(BaseModel):
    username: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordWithOTP(BaseModel):
    email: EmailStr
    code: str
    new_password: str


class ChangePassword(BaseModel):
    current_password: str
    new_password: str



# ---------- DB session ----------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_transaction(db: Session, user_id: int, type: str, amount: float, balance_after: float, description: str = ""):
    db.add(Transaction(
        user_id=user_id, type=type, amount=amount,
        balance_after=balance_after, description=description
    ))
  

# ---------- Auth dependencies ----------

def get_current_user(username: str = Depends(decode_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_verified(current_user: User = Depends(get_current_user)):
    if not current_user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")
    return current_user

def require_moderator(current_user: User = Depends(get_current_user)):
    if current_user.role not in ("moderator", "superuser"):
        raise HTTPException(status_code=403, detail="Moderators only")
    return current_user

def require_superuser(current_user: User = Depends(get_current_user)):
    if current_user.role != "superuser":
        raise HTTPException(status_code=403, detail="Superusers only")
    return current_user

# ---------- Registration + OTP verification ----------

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    db.add(Wallet(owner_id=new_user.id))
    db.commit()

    # generate + send OTP
    code = generate_otp()
    otp_entry = OTP(email=user.email, code=code, expires_at=datetime.utcnow() + timedelta(minutes=10))
    db.add(otp_entry)
    db.commit()
    send_otp_email(user.email, code)

    return {"message": "Registered. Check your email for a verification code."}

@app.post("/verify-otp")
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    otp_entry = (
        db.query(OTP)
        .filter(OTP.email == data.email, OTP.code == data.code)
        .order_by(OTP.id.desc())
        .first()
    )
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Invalid code")
    if otp_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code expired, request a new one")

    user = db.query(User).filter(User.email == data.email).first()
    user.is_verified = True
    db.delete(otp_entry)
    db.commit()

    return {"message": "Email verified! You can now log in."}

@app.post("/resend-otp")
def resend_otp(email: EmailStr, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account with that email")

    code = generate_otp()
    db.add(OTP(email=email, code=code, expires_at=datetime.utcnow() + timedelta(minutes=10)))
    db.commit()
    send_otp_email(email, code)
    return {"message": "New code sent"}


@app.post("/change-password")
def change_password(req: ChangePassword, current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(req.new_password)
    db.commit()
    return {"message": "Password updated successfully"}



@app.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        # Same response whether the email exists or not — don't reveal which emails are registered
        return {"message": "If that email is registered, a reset code has been sent."}

    code = generate_otp()
    db.add(OTP(email=req.email, code=code, purpose="password_reset", expires_at=datetime.utcnow() + timedelta(minutes=10)))
    db.commit()
    send_otp_email(req.email, code, purpose="reset")

    return {"message": "If that email is registered, a reset code has been sent."}

@app.post("/reset-password")
def reset_password_with_otp(req: ResetPasswordWithOTP, db: Session = Depends(get_db)):
    otp_entry = (
        db.query(OTP)
        .filter(OTP.email == req.email, OTP.code == req.code, OTP.purpose == "password_reset")
        .order_by(OTP.id.desc())
        .first()
    )
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Invalid code")
    if otp_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code expired, request a new one")

    user = db.query(User).filter(User.email == req.email).first()
    user.hashed_password = hash_password(req.new_password)
    db.delete(otp_entry)
    db.commit()

    return {"message": "Password reset successful. You can now log in with your new password."}




# ---------- Login (regular users) ----------

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not db_user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer", "role": db_user.role}

# ---------- Staff login (moderator/superuser) ----------

@app.post("/staff/login")
def staff_login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if db_user.role not in ("moderator", "superuser"):
        raise HTTPException(status_code=403, detail="Not a staff account")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer", "role": db_user.role}

# ---------- Wallet + bets (regular users) ----------

@app.get("/wallet")
def get_wallet(current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    wallet = db.query(Wallet).filter(Wallet.owner_id == current_user.id).first()
    return {"balance": wallet.balance, "bonus_balance": wallet.bonus_balance}

@app.get("/me")
def get_me(current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    wallet = db.query(Wallet).filter(Wallet.owner_id == current_user.id).first()
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_verified": current_user.is_verified,
        "balance": wallet.balance,
        "bonus_balance": wallet.bonus_balance,
    }



@app.post("/wallet/deposit")
def deposit(req: AmountRequest, current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    wallet = db.query(Wallet).filter(Wallet.owner_id == current_user.id).first()
    wallet.balance += req.amount
    log_transaction(db, current_user.id, "deposit", req.amount, wallet.balance, "Wallet deposit")
    db.commit()
    return {"new_balance": wallet.balance}





@app.post("/bets")
def place_bet(req: BetRequest, current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    if req.outcome_choice not in ("win", "lose"):
        raise HTTPException(status_code=400, detail="outcome_choice must be 'win' or 'lose'")
    wallet = db.query(Wallet).filter(Wallet.owner_id == current_user.id).first()
    if wallet.balance < req.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")


    wallet.balance -= req.amount
    new_bet = Bet(user_id=current_user.id, amount=req.amount, outcome_choice=req.outcome_choice)
    db.add(new_bet)
    log_transaction(db, current_user.id, "bet_placed", -req.amount, wallet.balance, f"Pick: {req.outcome_choice}")
    db.commit()
    db.refresh(new_bet)
    return {"bet_id": new_bet.id, "status": new_bet.status, "remaining_balance": wallet.balance}

@app.get("/bets/mine")
def my_bets(current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    bets = db.query(Bet).filter(Bet.user_id == current_user.id).all()
    return [{"id": b.id, "amount": b.amount, "choice": b.outcome_choice, "status": b.status, "payout": b.payout} for b in bets]

# ---------- Withdrawal requests (regular users) ----------

@app.post("/deposits")
def request_deposit(
    method: str = Form(...),
    amount: float = Form(...),
    reference: str = Form(None),
    slip: UploadFile = File(None),
    current_user: User = Depends(require_verified),
    db: Session = Depends(get_db),
):
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if method not in ("bank", "crypto"):
        raise HTTPException(status_code=400, detail="method must be 'bank' or 'crypto'")
    if not reference and not slip:
        raise HTTPException(status_code=400, detail="Provide a reference number, a deposit slip, or both")

    slip_filename = None
    if slip:
        ext = os.path.splitext(slip.filename)[1]
        slip_filename = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join("uploads", "deposit_slips", slip_filename)
        with open(save_path, "wb") as f:
            shutil.copyfileobj(slip.file, f)

    deposit_req = DepositRequest(
        user_id=current_user.id,
        method=method,
        amount=amount,
        reference=reference,
        slip_filename=slip_filename,
    )
    db.add(deposit_req)
    db.commit()
    db.refresh(deposit_req)
    return {"deposit_id": deposit_req.id, "status": deposit_req.status}




def generate_withdrawal_code(length=7):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@app.post("/withdrawal-verification/request")
def request_withdrawal_verification(
    current_user: User = Depends(require_verified),
    db: Session = Depends(get_db),
):
    # Expire old pending verification requests for this user.
    now = datetime.utcnow()

    old_requests = (
        db.query(WithdrawalVerification)
        .filter(
            WithdrawalVerification.user_id == current_user.id,
            WithdrawalVerification.status == "pending",
            WithdrawalVerification.expires_at <= now,
        )
        .all()
    )

    for old_request in old_requests:
        old_request.status = "expired"

    # Do not create multiple active codes for the same user.
    existing = (
        db.query(WithdrawalVerification)
        .filter(
            WithdrawalVerification.user_id == current_user.id,
            WithdrawalVerification.status == "pending",
            WithdrawalVerification.expires_at > now,
        )
        .order_by(WithdrawalVerification.id.desc())
        .first()
    )

    if existing:
        db.commit()
        return {
            "message": "A withdrawal verification code is already pending",
            "request_id": existing.id,
            "status": existing.status,
            "expires_at": existing.expires_at.isoformat(),
        }

    code = generate_withdrawal_code()

    verification = WithdrawalVerification(
        user_id=current_user.id,
        code=code,
        status="pending",
        expires_at=now + timedelta(minutes=10),
    )

    db.add(verification)
    db.commit()
    db.refresh(verification)

    # The code is intentionally NOT returned to the user.
    # The authorized admin retrieves it from the admin endpoint.
    return {
        "message": "Withdrawal verification requested",
        "request_id": verification.id,
        "status": verification.status,
        "expires_at": verification.expires_at.isoformat(),
    }


@app.get("/admin/withdrawal-verification-requests")
def list_withdrawal_verification_requests(
    mod: User = Depends(require_moderator),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()

    pending = (
        db.query(WithdrawalVerification)
        .filter(
            WithdrawalVerification.status == "pending",
            WithdrawalVerification.expires_at > now,
        )
        .order_by(WithdrawalVerification.created_at.desc())
        .all()
    )

    return [
        {
            "id": v.id,
            "username": v.user.username,
            "email": v.user.email,
            "code": v.code,
            "status": v.status,
            "created_at": v.created_at.isoformat(),
            "expires_at": v.expires_at.isoformat(),
        }
        for v in pending
    ]


@app.post("/withdrawal-verification/verify")
def verify_withdrawal_verification(
    req: WithdrawalVerificationCode,
    current_user: User = Depends(require_verified),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()

    verification = (
        db.query(WithdrawalVerification)
        .filter(
            WithdrawalVerification.user_id == current_user.id,
            WithdrawalVerification.code == req.code.upper().strip(),
            WithdrawalVerification.status == "pending",
        )
        .order_by(WithdrawalVerification.id.desc())
        .first()
    )

    if not verification:
        raise HTTPException(
            status_code=400,
            detail="Invalid withdrawal verification code",
        )

    if verification.expires_at <= now:
        verification.status = "expired"
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Withdrawal verification code has expired",
        )

    # Consume the verification code immediately.
    verification.status = "used"
    verification.used_at = now
    db.commit()

    # Issue a separate short-lived withdrawal authorization token.
    withdrawal_token = create_access_token(
        {
            "sub": current_user.username,
            "purpose": "withdrawal_verification",
            "verification_id": verification.id,
        }
    )

    return {
        "verified": True,
        "message": "Withdrawal verification successful",
        "withdrawal_token": withdrawal_token,
    }


@app.post("/withdrawals")
def request_withdrawal(
    req: WithdrawalCreate,
    current_user: User = Depends(require_verified),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Valid withdrawal verification is required",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Validate the short-lived withdrawal authorization token.
    try:
        payload = jwt.decode(
            req.verification_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        token_username = payload.get("sub")
        token_purpose = payload.get("purpose")
        verification_id = payload.get("verification_id")

        if token_username != current_user.username:
            raise credentials_exception

        if token_purpose != "withdrawal_verification":
            raise credentials_exception

        if not verification_id:
            raise credentials_exception

        verification = (
            db.query(WithdrawalVerification)
            .filter(
                WithdrawalVerification.id == verification_id,
                WithdrawalVerification.user_id == current_user.id,
            )
            .first()
        )

        if not verification:
            raise credentials_exception

        # The admin-issued verification code must already have been consumed.
        if verification.status != "used":
            raise credentials_exception

        # Prevent the same authorization token from being reused.
        if verification.token_used_at is not None:
            raise HTTPException(
                status_code=401,
                detail="Withdrawal authorization has already been used",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    wallet = db.query(Wallet).filter(Wallet.owner_id == current_user.id).first()

    if not wallet:
        raise HTTPException(status_code=400, detail="Wallet not found")

    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    if wallet.balance < req.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    if req.method == "bank":
        if not req.account_number or not req.account_name:
            raise HTTPException(
                status_code=400,
                detail="Bank withdrawals need account_number and account_name",
            )

    elif req.method == "crypto":
        if not req.crypto_address or not req.crypto_type:
            raise HTTPException(
                status_code=400,
                detail="Crypto withdrawals need crypto_address and crypto_type",
            )

    else:
        raise HTTPException(
            status_code=400,
            detail="method must be 'bank' or 'crypto'",
        )

    # Consume the withdrawal authorization only after all validation passes.
    verification.token_used_at = datetime.utcnow()

    withdrawal = WithdrawalRequest(
        user_id=current_user.id,
        method=req.method,
        amount=req.amount,
        account_number=req.account_number,
        account_name=req.account_name,
        crypto_address=req.crypto_address,
        crypto_type=req.crypto_type,
    )

    db.add(withdrawal)

    log_transaction(
        db,
        current_user.id,
        "withdrawal_requested",
        0,
        wallet.balance,
        f"Withdrawal request via {req.method}",
    )

    db.commit()
    db.refresh(withdrawal)

    return {
        "withdrawal_id": withdrawal.id,
        "status": withdrawal.status,
    }


@app.delete("/account")
def delete_account(current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    db.delete(current_user)
    db.commit()
    return {"message": "Account deleted"}

# ---------- Moderator routes ----------

@app.get("/admin/withdrawals")
def list_withdrawals(mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    withdrawals = db.query(WithdrawalRequest).filter(WithdrawalRequest.status == "pending").all()
    return [
        {
            "id": w.id, "username": w.user.username, "method": w.method, "amount": w.amount,
            "account_number": w.account_number, "account_name": w.account_name,
            "crypto_address": w.crypto_address, "crypto_type": w.crypto_type,
        }
        for w in withdrawals
    ]

@app.post("/admin/withdrawals/{withdrawal_id}/approve")
def approve_withdrawal(withdrawal_id: int, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    w = db.query(WithdrawalRequest).filter(WithdrawalRequest.id == withdrawal_id).first()
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    wallet = db.query(Wallet).filter(Wallet.owner_id == w.user_id).first()
    if wallet.balance < w.amount:
        raise HTTPException(status_code=400, detail="User no longer has sufficient balance")
    wallet.balance -= w.amount
    w.status = "approved"
    log_transaction(db, w.user_id, "withdrawal_approved", -w.amount, wallet.balance, f"Withdrawal #{w.id} paid out")
    db.commit()
    return {"message": "Withdrawal approved and paid out"}

@app.post("/admin/withdrawals/{withdrawal_id}/reject")
def reject_withdrawal(withdrawal_id: int, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    w = db.query(WithdrawalRequest).filter(WithdrawalRequest.id == withdrawal_id).first()
    if not w:
        raise HTTPException(status_code=404, detail="Withdrawal not found")
    w.status = "rejected"
    log_transaction(db, w.user_id, "withdrawal_rejected", 0, w.user.wallet.balance, f"Withdrawal #{w.id} rejected")
    db.commit()
    return {"message": "Withdrawal rejected"}

@app.get("/admin/bets")
def list_all_bets(mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    bets = (
        db.query(Bet)
        .order_by(Bet.id.desc())
        .all()
    )

    return [
        {
            "id": b.id,
            "user_id": b.user_id,
            "username": b.user.username if b.user else None,
            "amount": b.amount,
            "choice": b.outcome_choice,
            "status": b.status,
            "payout": b.payout or 0.0,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        }
        for b in bets
    ]

@app.post("/admin/bets/{bet_id}/settle")
def settle_bet(bet_id: int, req: SettleBetRequest, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    bet = db.query(Bet).filter(Bet.id == bet_id).first()
    if not bet:
        raise HTTPException(status_code=404, detail="Bet not found")
    if bet.status != "pending":
        raise HTTPException(status_code=400, detail="Bet already settled")



    if req.result == "won":
        payout = bet.amount * 2  # simple fixed payout multiplier for now
        wallet = db.query(Wallet).filter(Wallet.owner_id == bet.user_id).first()
        wallet.balance += payout
        bet.payout = payout
        bet.status = "won"
        log_transaction(db, bet.user_id, "bet_payout", payout, wallet.balance, f"Payout for bet #{bet.id}")
    elif req.result == "lost":
        bet.status = "lost"
    else:
        raise HTTPException(status_code=400, detail="result must be 'won' or 'lost'")

    db.commit()
    return {"bet_id": bet.id, "status": bet.status, "payout": bet.payout}




@app.get("/admin/deposits")
def list_deposits(mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    deposits = db.query(DepositRequest).filter(DepositRequest.status == "pending").all()
    return [
        {
            "id": d.id,
            "username": d.user.username,
            "method": d.method,
            "amount": d.amount,
            "reference": d.reference,
            "slip_url": f"/uploads/deposit_slips/{d.slip_filename}" if d.slip_filename else None,
            "created_at": d.created_at.isoformat(),
        }
        for d in deposits
    ]

@app.post("/admin/deposits/{deposit_id}/approve")
def approve_deposit(deposit_id: int, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    d = db.query(DepositRequest).filter(DepositRequest.id == deposit_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Deposit request not found")
    if d.status != "pending":
        raise HTTPException(status_code=400, detail="Deposit already processed")

    wallet = db.query(Wallet).filter(Wallet.owner_id == d.user_id).first()
    wallet.balance += d.amount
    d.status = "approved"
    log_transaction(db, d.user_id, "deposit_approved", d.amount, wallet.balance, f"Deposit #{d.id} confirmed via {d.method}")
    db.commit()
    return {"message": "Deposit approved and credited"}

@app.post("/admin/deposits/{deposit_id}/reject")
def reject_deposit(deposit_id: int, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    d = db.query(DepositRequest).filter(DepositRequest.id == deposit_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Deposit request not found")
    if d.status != "pending":
        raise HTTPException(status_code=400, detail="Deposit already processed")

    d.status = "rejected"
    log_transaction(db, d.user_id, "deposit_rejected", 0, d.user.wallet.balance, f"Deposit #{d.id} rejected")
    db.commit()
    return {"message": "Deposit rejected"}




@app.post("/admin/reset-password")
def reset_password(req: PasswordReset, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = hash_password(req.new_password)
    db.commit()
    return {"message": f"Password reset for {req.username}"}

# ---------- Superuser routes ----------

@app.post("/admin/create-staff")
def create_staff(user: UserCreate, role: str, su: User = Depends(require_superuser), db: Session = Depends(get_db)):
    if role not in ("moderator", "superuser"):
        raise HTTPException(status_code=400, detail="role must be 'moderator' or 'superuser'")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    new_staff = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=role,
        is_verified=True,  # staff accounts skip OTP, created directly by a superuser
    )
    db.add(new_staff)
    db.commit()
    db.refresh(new_staff)
    return {"id": new_staff.id, "username": new_staff.username, "role": new_staff.role}

@app.get("/admin/stats")
def admin_stats(su: User = Depends(require_superuser), db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_deposits = db.query(DepositRequest).count()
    total_withdrawals = db.query(WithdrawalRequest).count()
    pending_deposits = (
        db.query(DepositRequest)
        .filter(DepositRequest.status == "pending")
        .count()
    )
    pending_withdrawals = (
        db.query(WithdrawalRequest)
        .filter(WithdrawalRequest.status == "pending")
        .count()
    )
    total_volume = db.query(Bet).with_entities(
        func.coalesce(func.sum(Bet.amount), 0.0)
    ).scalar() or 0.0
    total_bets = db.query(Bet).count()
    active_users = db.query(User).filter(User.is_active.is_(True)).count()

    return {
        "total_users": total_users,
        "total_deposits": total_deposits,
        "total_withdrawals": total_withdrawals,
        "pending_deposits": pending_deposits,
        "pending_withdrawals": pending_withdrawals,
        "total_volume": float(total_volume),
        "total_bets": total_bets,
        "active_users": active_users,
    }

@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    su: User = Depends(require_superuser),
    db: Session = Depends(get_db),
):
    if user_id == su.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    has_bets = db.query(Bet).filter(Bet.user_id == user_id).first()
    has_deposits = db.query(DepositRequest).filter(
        DepositRequest.user_id == user_id
    ).first()
    has_withdrawals = db.query(WithdrawalRequest).filter(
        WithdrawalRequest.user_id == user_id
    ).first()
    has_transactions = db.query(Transaction).filter(
        Transaction.user_id == user_id
    ).first()

    if has_bets or has_deposits or has_withdrawals or has_transactions:
        raise HTTPException(
            status_code=409,
            detail="User has financial or betting history and cannot be permanently deleted",
        )

    wallet = db.query(Wallet).filter(Wallet.owner_id == user_id).first()
    if wallet:
        db.delete(wallet)

    db.delete(user)
    db.commit()

    return {"message": "User deleted"}

@app.put("/admin/users/{user_id}/plan")
def set_user_plan(
    user_id: int,
    req: UserPlanRequest,
    su: User = Depends(require_superuser),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.plan = req.plan
    db.commit()
    db.refresh(user)

    return {
        "message": "User plan updated",
        "plan": user.plan,
    }

@app.put("/admin/users/{user_id}/status")
def set_user_status(
    user_id: int,
    req: UserStatusRequest,
    su: User = Depends(require_superuser),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = req.is_active
    db.commit()
    db.refresh(user)

    return {
        "message": "User status updated",
        "is_active": user.is_active,
    }

@app.put("/admin/users/{user_id}/balance")
def set_user_balance(
    user_id: int,
    req: AmountRequest,
    su: User = Depends(require_superuser),
    db: Session = Depends(get_db),
):
    if req.amount < 0:
        raise HTTPException(status_code=400, detail="Balance cannot be negative")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    wallet = db.query(Wallet).filter(Wallet.owner_id == user_id).first()
    if not wallet:
        wallet = Wallet(owner_id=user_id, balance=0.0, bonus_balance=0.0)
        db.add(wallet)
        db.flush()

    wallet.balance = req.amount
    db.commit()
    db.refresh(wallet)

    return {
        "message": "User balance updated",
        "balance": wallet.balance,
    }

@app.get("/admin/users")
def list_users(su: User = Depends(require_superuser), db: Session = Depends(get_db)):
    users = db.query(User).all()

    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_verified": u.is_verified,
            "is_active": u.is_active,
            "balance": u.wallet.balance if u.wallet else 0.0,
            "bonus_balance": u.wallet.bonus_balance if u.wallet else 0.0,
            "plan": u.plan,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]








@app.get("/transactions")
def my_transactions(current_user: User = Depends(require_verified), db: Session = Depends(get_db)):
    txns = (
        db.query(Transaction)
        .filter(Transaction.user_id == current_user.id)
        .order_by(Transaction.id.desc())
        .all()
    )
    return [
        {
            "id": t.id, "type": t.type, "amount": t.amount,
            "balance_after": t.balance_after, "description": t.description,
            "created_at": t.created_at.isoformat(),
        }
        for t in txns
    ]

@app.get("/admin/transactions/{username}")
def user_transactions(username: str, mod: User = Depends(require_moderator), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    txns = (
        db.query(Transaction)
        .filter(Transaction.user_id == target.id)
        .order_by(Transaction.id.desc())
        .all()
    )
    return [
        {
            "id": t.id, "type": t.type, "amount": t.amount,
            "balance_after": t.balance_after, "description": t.description,
            "created_at": t.created_at.isoformat(),
        }
        for t in txns
    ]
