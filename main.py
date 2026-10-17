import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

APP_TITLE = "Mars API"
DB_PATH = os.getenv("MARS_DB_PATH", "mars.db")
app = FastAPI(title=APP_TITLE, version="1.0.0")

GIFTS = {
    "Одеяло": 17,
    "Подушка": 25,
    "Дом": 50,
}
PACKAGES = [
    {"green": 10, "price_rub": 20},
    {"green": 15, "price_rub": 27},
    {"green": 25, "price_rub": 45},
    {"green": 50, "price_rub": 70},
    {"green": 100, "price_rub": 94},
]

def now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            token TEXT UNIQUE,
            verified INTEGER NOT NULL DEFAULT 0,
            green_balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            contact_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, contact_id)
        );
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            room_type TEXT NOT NULL DEFAULT 'group',
            created_by INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS members (
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(room_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER REFERENCES users(id),
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS green_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount INTEGER NOT NULL,
            kind TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS green_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            package_green INTEGER NOT NULL,
            price_rub INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        );
        """)
init_db()

def password_hash(password: str) -> str:
    # PBKDF2 is built into Python and avoids storing plaintext passwords.
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 180000
        )
        return secrets.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False

def user_by_token(token: Optional[str]):
    if not token:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    with connect() as con:
        row = con.execute(
            "SELECT * FROM users WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Неверный токен")
    return dict(row)

def current_user(authorization: Optional[str]):
    if not authorization:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization.replace("Bearer ", "", 1).strip()
    return user_by_token(token)

def add_history(con, user_id, amount, kind, description):
    con.execute(
        "INSERT INTO green_history(user_id, amount, kind, description, created_at) VALUES(?,?,?,?,?)",
        (user_id, amount, kind, description, now())
    )

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=4, max_length=128)

class ContactBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)

class RoomBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    room_type: str = "group"

class MessageBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

class GiftBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    gift: str = Field(min_length=1, max_length=80)

class PaymentBody(BaseModel):
    package_green: int = Field(gt=0)

class VerifyBody(BaseModel):
    code: str = Field(min_length=1, max_length=100)

@app.get("/")
def root():
    return {"service": APP_TITLE, "status": "ok"}

@app.post("/register")
def register(body: Credentials):
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Имя должно быть не короче 3 символов")
    token = secrets.token_urlsafe(32)
    try:
        with connect() as con:
            cur = con.execute(
                "INSERT INTO users(username,password_hash,token,created_at) VALUES(?,?,?,?)",
                (username, password_hash(body.password), token, now())
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Это имя пользователя уже занято")
    return {"token": token, "user_id": user_id, "username": username, "verified": False}

@app.post("/login")
def login(body: Credentials):
    with connect() as con:
        row = con.execute(
            "SELECT * FROM users WHERE username = ?", (body.username.strip(),)
        ).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль")
    token = secrets.token_urlsafe(32)
    with connect() as con:
        con.execute("UPDATE users SET token=? WHERE id=?", (token, row["id"]))
    return {"token": token, "user_id": row["id"], "username": row["username"],
            "verified": bool(row["verified"])}

@app.get("/profile")
def profile(authorization: Optional[str] = Header(default=None)):
    user = current_user(authorization)
    return {"id": user["id"], "username": user["username"],
            "verified": bool(user["verified"]), "green_balance": user["green_balance"]}

@app.post("/verify")
def verify(body: VerifyBody, authorization: Optional[str] = Header(default=None)):
    # Shared verification code requested for this Mars setup.
    # Keep this code private: anyone who knows it can verify their own account.
    verification_code = os.getenv("MARS_VERIFICATION_CODE", "M3kolorcolor2")
    me = current_user(authorization)
    if not secrets.compare_digest(body.code.strip(), verification_code):
        raise HTTPException(status_code=400, detail="Неверный код подтверждения")
    with connect() as con:
        row = con.execute("SELECT verified FROM users WHERE id=?", (me["id"],)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Аккаунт не найден")
        if not row["verified"]:
            con.execute("UPDATE users SET verified=1 WHERE id=?", (me["id"],))
    return {"ok": True, "verified": True, "message": "Аккаунт подтверждён!"}

@app.get("/users")
def users(authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        rows = con.execute(
            "SELECT id,username,verified FROM users WHERE id != ? ORDER BY username LIMIT 200",
            (me["id"],)
        ).fetchall()
    return [dict(r) for r in rows]

@app.get("/contacts")
def get_contacts(authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        rows = con.execute("""
            SELECT u.id, u.username FROM contacts c
            JOIN users u ON u.id=c.contact_id
            WHERE c.user_id=? ORDER BY u.username
        """, (me["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/contacts")
def add_contact(body: ContactBody, authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        target = con.execute("SELECT id FROM users WHERE username=?", (body.username.strip(),)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        if target["id"] == me["id"]:
            raise HTTPException(status_code=400, detail="Нельзя добавить себя")
        con.execute("INSERT OR IGNORE INTO contacts(user_id,contact_id) VALUES(?,?)",
                    (me["id"], target["id"]))
    return {"ok": True}

@app.get("/rooms")
def get_rooms(authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        rows = con.execute("""
            SELECT r.id,r.name,r.room_type,r.created_at
            FROM rooms r JOIN members m ON m.room_id=r.id
            WHERE m.user_id=? ORDER BY r.id DESC
        """, (me["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/rooms")
def create_room(body: RoomBody, authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    room_type = body.room_type if body.room_type in ("group", "private") else "group"
    with connect() as con:
        cur = con.execute(
            "INSERT INTO rooms(name,room_type,created_by,created_at) VALUES(?,?,?,?)",
            (body.name.strip(), room_type, me["id"], now())
        )
        room_id = cur.lastrowid
        con.execute("INSERT INTO members(room_id,user_id) VALUES(?,?)", (room_id, me["id"]))
    return {"id": room_id, "name": body.name.strip(), "room_type": room_type}

@app.get("/rooms/{room_id}/members")
def get_room_members(room_id: int, authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        member = con.execute("SELECT 1 FROM members WHERE room_id=? AND user_id=?",
                             (room_id, me["id"])).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Нет доступа к комнате")
        rows = con.execute("""
            SELECT u.id,u.username FROM members m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=? ORDER BY u.username
        """, (room_id,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/rooms/{room_id}/members")
def add_room_member(room_id: int, body: ContactBody,
                    authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        room = con.execute("SELECT id FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Комната не найдена")
        member = con.execute("SELECT 1 FROM members WHERE room_id=? AND user_id=?",
                             (room_id, me["id"])).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Нет доступа к комнате")
        target = con.execute("SELECT id FROM users WHERE username=?", (body.username.strip(),)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        con.execute("INSERT OR IGNORE INTO members(room_id,user_id) VALUES(?,?)",
                    (room_id, target["id"]))
    return {"ok": True}

@app.get("/rooms/{room_id}/messages")
def get_room_messages(room_id: int, authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        member = con.execute("SELECT 1 FROM members WHERE room_id=? AND user_id=?",
                             (room_id, me["id"])).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Нет доступа к комнате")
        rows = con.execute("""
            SELECT m.id,m.content,m.created_at,u.username AS sender
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.room_id=? ORDER BY m.id ASC LIMIT 500
        """, (room_id,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/rooms/{room_id}/messages")
def send_room_message(room_id: int, body: MessageBody,
                      authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        member = con.execute("SELECT 1 FROM members WHERE room_id=? AND user_id=?",
                             (room_id, me["id"])).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Нет доступа к комнате")
        cur = con.execute(
            "INSERT INTO messages(room_id,sender_id,content,created_at) VALUES(?,?,?,?)",
            (room_id, me["id"], body.content.strip(), now())
        )
        message_id = cur.lastrowid
    return {"id": message_id, "ok": True}

@app.get("/messages/{other_username}")
def get_private_messages(other_username: str,
                         authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        other = con.execute("SELECT id FROM users WHERE username=?", (other_username,)).fetchone()
        if not other:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        rows = con.execute("""
            SELECT m.id,m.content,m.created_at,u.username AS sender
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE (m.sender_id=? AND m.recipient_id=?)
               OR (m.sender_id=? AND m.recipient_id=?)
            ORDER BY m.id ASC LIMIT 500
        """, (me["id"], other["id"], other["id"], me["id"])).fetchall()
    return [dict(r) for r in rows]

@app.post("/messages/{other_username}")
def send_private_message(other_username: str, body: MessageBody,
                         authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        other = con.execute("SELECT id FROM users WHERE username=?", (other_username,)).fetchone()
        if not other:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        cur = con.execute("""
            INSERT INTO messages(sender_id,recipient_id,content,created_at)
            VALUES(?,?,?,?)
        """, (me["id"], other["id"], body.content.strip(), now()))
        message_id = cur.lastrowid
    return {"id": message_id, "ok": True}

# -------------------- GREEN --------------------

@app.get("/green/balance")
def green_balance(authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    return {"balance": me["green_balance"]}

@app.get("/green/gifts")
def green_gifts(authorization: Optional[str] = Header(default=None)):
    current_user(authorization)
    return [{"name": name, "price": price} for name, price in GIFTS.items()]

@app.post("/green/gifts/send")
def send_green_gift(body: GiftBody, authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    gift_name = body.gift.strip()
    if gift_name not in GIFTS:
        raise HTTPException(status_code=400, detail="Такого подарка нет в каталоге")
    price = GIFTS[gift_name]

    with connect() as con:
        # BEGIN IMMEDIATE serializes balance-changing operations to avoid overspending.
        con.execute("BEGIN IMMEDIATE")
        sender = con.execute("SELECT id,username,green_balance FROM users WHERE id=?",
                             (me["id"],)).fetchone()
        recipient = con.execute("SELECT id,username FROM users WHERE username=?",
                                (body.username.strip(),)).fetchone()
        if not recipient:
            raise HTTPException(status_code=404, detail="Получатель не найден")
        if recipient["id"] == sender["id"]:
            raise HTTPException(status_code=400, detail="Нельзя отправить подарок самому себе")
        if sender["green_balance"] < price:
            raise HTTPException(status_code=400, detail="Недостаточно Green")

        con.execute("UPDATE users SET green_balance=green_balance-? WHERE id=?",
                    (price, sender["id"]))
        # Recipient receives a gift notification/history entry, not spendable currency.
        add_history(con, sender["id"], -price, "gift_sent",
                    "Подарок «" + gift_name + "» отправлен пользователю " + recipient["username"])
        add_history(con, recipient["id"], 0, "gift_received",
                    "Вам отправлено " + gift_name.lower() + " стоимостью " + str(price) + " Green.")
        new_balance = con.execute("SELECT green_balance FROM users WHERE id=?",
                                  (sender["id"],)).fetchone()["green_balance"]

    notification = "Подарок «" + gift_name + "» отправлен пользователю " + recipient["username"]
    return {"ok": True, "gift": gift_name, "price": price,
            "balance": new_balance, "notification": notification}

@app.get("/green/history")
def green_history(authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        rows = con.execute("""
            SELECT id,amount,kind,description,created_at
            FROM green_history WHERE user_id=? ORDER BY id DESC LIMIT 200
        """, (me["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.get("/green/packages")
def green_packages(authorization: Optional[str] = Header(default=None)):
    current_user(authorization)
    return PACKAGES

@app.post("/green/claim")
def claim_free_green(body: PaymentBody,
                     authorization: Optional[str] = Header(default=None)):
    """Бесплатное начисление выбранного пакета только подтверждённым аккаунтам."""
    me = current_user(authorization)
    package = next((p for p in PACKAGES if p["green"] == body.package_green), None)
    if not package:
        raise HTTPException(status_code=400, detail="Неизвестный пакет Green")

    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        account = con.execute(
            "SELECT id, verified, green_balance FROM users WHERE id=?", (me["id"],)
        ).fetchone()
        if not account:
            raise HTTPException(status_code=401, detail="Аккаунт не найден")
        if not account["verified"]:
            raise HTTPException(status_code=403, detail="Green доступны только подтверждённым аккаунтам")

        amount = package["green"]
        con.execute(
            "UPDATE users SET green_balance = green_balance + ? WHERE id = ?",
            (amount, account["id"])
        )
        add_history(con, account["id"], amount, "free_green",
                    "Бесплатно начислено " + str(amount) + " Green")
        new_balance = con.execute(
            "SELECT green_balance FROM users WHERE id=?", (account["id"],)
        ).fetchone()["green_balance"]

    return {"ok": True, "green_added": amount, "balance": new_balance,
            "message": "Начислено " + str(amount) + " Green!"}


@app.post("/green/payments")
def create_green_payment(body: PaymentBody,
                         authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    package = next((p for p in PACKAGES if p["green"] == body.package_green), None)
    if not package:
        raise HTTPException(status_code=400, detail="Неизвестный пакет Green")
    with connect() as con:
        cur = con.execute("""
            INSERT INTO green_payments(user_id,package_green,price_rub,status,created_at)
            VALUES(?,?,?,?,?)
        """, (me["id"], package["green"], package["price_rub"], "pending", now()))
        payment_id = cur.lastrowid
    return {
        "ok": True,
        "payment_id": payment_id,
        "green": package["green"],
        "price_rub": package["price_rub"],
        "status": "pending",
        "checkout_url": None,
        "message": "Заявка создана. Оплата ещё не выполнена; Green пока не зачислены."
    }

@app.get("/green/payments/{payment_id}")
def get_green_payment(payment_id: int,
                      authorization: Optional[str] = Header(default=None)):
    me = current_user(authorization)
    with connect() as con:
        row = con.execute("""
            SELECT id,package_green,price_rub,status,created_at
            FROM green_payments WHERE id=? AND user_id=?
        """, (payment_id, me["id"])).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Платёж не найден")
    return dict(row)

@app.get("/health")
def health():
    return {"ok": True}
