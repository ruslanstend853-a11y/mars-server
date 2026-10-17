import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mars Server")

DB_PATH = os.getenv("DB_PATH", "mars.db")
VERIFY_KEY = os.getenv("MARS_VERIFY_KEY", "CHANGE_THIS_VERIFY_KEY")

GREEN_GIFTS = {
    "Одеяло": 17,
    "Подушка": 25,
    "Дом": 50,
}

GREEN_PACKAGES = {
    10: 20,
    15: 27,
    25: 45,
    50: 70,
    100: 94,
}


# ---------- DATABASE ----------

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            bio TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            green_balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Миграция для старой базы.
    columns = [
        row["name"]
        for row in cur.execute("PRAGMA table_info(users)").fetchall()
    ]

    if "green_balance" not in columns:
        cur.execute(
            "ALTER TABLE users ADD COLUMN green_balance "
            "INTEGER NOT NULL DEFAULT 0"
        )
    if "display_name" not in columns:
        cur.execute(
            "ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"
        )
    if "bio" not in columns:
        cur.execute(
            "ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''"
        )
    if "verified" not in columns:
        cur.execute(
            "ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0"
        )

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, contact_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(contact_user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            room_type TEXT NOT NULL DEFAULT 'group',
            owner_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(room_id, user_id),
            FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER,
            room_id INTEGER,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id),
            FOREIGN KEY(room_id) REFERENCES rooms(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS green_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            kind TEXT NOT NULL,
            description TEXT NOT NULL,
            related_user_id INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(related_user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS green_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            package_green INTEGER NOT NULL,
            amount_rub INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            provider_payment_id TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------- MODELS ----------

class AuthData(BaseModel):
    username: str
    password: str


class ProfileData(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None


class VerifyData(BaseModel):
    key: str


class ContactData(BaseModel):
    username: str


class RoomData(BaseModel):
    name: str
    room_type: str = "group"


class MemberData(BaseModel):
    username: str


class MessageData(BaseModel):
    text: str
    recipient_id: Optional[int] = None
    room_id: Optional[int] = None


class GiftData(BaseModel):
    username: str
    gift: str


class PaymentData(BaseModel):
    package_green: int


# ---------- AUTH HELPERS ----------

def password_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_user(token):
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    conn = connect()
    row = conn.execute("""
        SELECT users.*
        FROM tokens
        JOIN users ON users.id = tokens.user_id
        WHERE tokens.token = ?
    """, (token,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid token")

    return dict(row)


def user_from_header(authorization):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    return get_user(token)


def require_room_member(conn, room_id, user_id):
    row = conn.execute("""
        SELECT 1 FROM members
        WHERE room_id = ? AND user_id = ?
    """, (room_id, user_id)).fetchone()

    if not row:
        raise HTTPException(status_code=403, detail="Not a room member")


# ---------- GENERAL ----------

@app.get("/")
def home():
    return {"app": "Mars", "status": "online"}


# ---------- REGISTRATION / LOGIN ----------

@app.post("/register")
def register(data: AuthData):
    username = data.username.strip().lstrip("@")

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username too short")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="Password too short")

    conn = connect()

    try:
        cur = conn.execute("""
            INSERT INTO users (username, password_hash, display_name)
            VALUES (?, ?, ?)
        """, (username, password_hash(data.password), username))

        user_id = cur.lastrowid
        token = secrets.token_urlsafe(32)

        conn.execute(
            "INSERT INTO tokens (token, user_id) VALUES (?, ?)",
            (token, user_id)
        )
        conn.commit()

        return {
            "ok": True,
            "token": token,
            "user_id": user_id,
            "username": username
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    finally:
        conn.close()


@app.post("/login")
def login(data: AuthData):
    username = data.username.strip().lstrip("@")

    conn = connect()
    user = conn.execute("""
        SELECT * FROM users WHERE username = ?
    """, (username,)).fetchone()

    if not user or user["password_hash"] != password_hash(data.password):
        conn.close()
        raise HTTPException(status_code=401, detail="Wrong username or password")

    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO tokens (token, user_id) VALUES (?, ?)",
        (token, user["id"])
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "token": token,
        "user_id": user["id"],
        "username": username
    }


# ---------- PROFILE / VERIFICATION ----------

@app.get("/profile")
def profile(authorization: Optional[str] = Header(default=None)):
    user = user_from_header(authorization)

    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "bio": user["bio"],
        "verified": bool(user["verified"]),
        "green_balance": user["green_balance"]
    }


@app.put("/profile")
def update_profile(
    data: ProfileData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    conn = connect()
    if data.display_name is not None:
        conn.execute(
            "UPDATE users SET display_name = ? WHERE id = ?",
            (data.display_name, user["id"])
        )
    if data.bio is not None:
        conn.execute(
            "UPDATE users SET bio = ? WHERE id = ?",
            (data.bio, user["id"])
        )
    conn.commit()
    conn.close()

    return {"ok": True}


@app.post("/verify")
def verify(
    data: VerifyData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    if not VERIFY_KEY or VERIFY_KEY == "CHANGE_THIS_VERIFY_KEY":
        raise HTTPException(
            status_code=503,
            detail="Verification key is not configured on the server"
        )

    if not secrets.compare_digest(data.key, VERIFY_KEY):
        raise HTTPException(status_code=403, detail="Invalid verification key")

    conn = connect()
    conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    return {"ok": True, "verified": True}


@app.get("/users")
def users(authorization: Optional[str] = Header(default=None)):
    current = user_from_header(authorization)

    conn = connect()
    rows = conn.execute("""
        SELECT id, username, display_name, verified
        FROM users
        WHERE id != ?
        ORDER BY username
    """, (current["id"],)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


# ---------- CONTACTS ----------

@app.get("/contacts")
def get_contacts(authorization: Optional[str] = Header(default=None)):
    user = user_from_header(authorization)

    conn = connect()
    rows = conn.execute("""
        SELECT users.id, users.username, users.display_name, users.verified
        FROM contacts
        JOIN users ON users.id = contacts.contact_user_id
        WHERE contacts.user_id = ?
        ORDER BY users.username
    """, (user["id"],)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.post("/contacts")
def add_contact(
    data: ContactData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)
    username = data.username.strip().lstrip("@")

    conn = connect()
    target = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if target["id"] == user["id"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot add yourself")

    try:
        conn.execute("""
            INSERT INTO contacts (user_id, contact_user_id)
            VALUES (?, ?)
        """, (user["id"], target["id"]))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

    return {"ok": True}


# ---------- GROUPS / CHANNELS / COMMUNITIES ----------

@app.get("/rooms")
def get_rooms(authorization: Optional[str] = Header(default=None)):
    user = user_from_header(authorization)

    conn = connect()
    rows = conn.execute("""
        SELECT rooms.id, rooms.name, rooms.room_type, rooms.owner_id
        FROM rooms
        JOIN members ON members.room_id = rooms.id
        WHERE members.user_id = ?
        ORDER BY rooms.id DESC
    """, (user["id"],)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.post("/rooms")
def create_room(
    data: RoomData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)
    name = data.name.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Room name is required")

    if data.room_type not in ("group", "channel", "community"):
        raise HTTPException(status_code=400, detail="Invalid room type")

    conn = connect()
    cur = conn.execute("""
        INSERT INTO rooms (name, room_type, owner_id)
        VALUES (?, ?, ?)
    """, (name, data.room_type, user["id"]))

    room_id = cur.lastrowid
    conn.execute(
        "INSERT INTO members (room_id, user_id) VALUES (?, ?)",
        (room_id, user["id"])
    )
    conn.commit()
    conn.close()

    return {"ok": True, "id": room_id, "name": name, "room_type": data.room_type}


@app.get("/rooms/{room_id}/members")
def get_room_members(
    room_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    conn = connect()
    require_room_member(conn, room_id, user["id"])

    rows = conn.execute("""
        SELECT users.id, users.username, users.display_name
        FROM members
        JOIN users ON users.id = members.user_id
        WHERE members.room_id = ?
    """, (room_id,)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.post("/rooms/{room_id}/members")
def add_room_member(
    room_id: int,
    data: MemberData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)
    username = data.username.strip().lstrip("@")

    conn = connect()
    room = conn.execute(
        "SELECT * FROM rooms WHERE id = ?", (room_id,)
    ).fetchone()

    if not room:
        conn.close()
        raise HTTPException(status_code=404, detail="Room not found")

    require_room_member(conn, room_id, user["id"])

    target = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    try:
        conn.execute("""
            INSERT INTO members (room_id, user_id)
            VALUES (?, ?)
        """, (room_id, target["id"]))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

    return {"ok": True}


# ---------- MESSAGES ----------

@app.get("/rooms/{room_id}/messages")
def get_room_messages(
    room_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    conn = connect()
    require_room_member(conn, room_id, user["id"])

    rows = conn.execute("""
        SELECT messages.id, messages.sender_id, users.username AS sender,
               messages.text, messages.created_at
        FROM messages
        JOIN users ON users.id = messages.sender_id
        WHERE messages.room_id = ?
        ORDER BY messages.id
    """, (room_id,)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.post("/rooms/{room_id}/messages")
def send_room_message(
    room_id: int,
    data: MessageData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)
    text = data.text.strip()

    if not text:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    conn = connect()
    require_room_member(conn, room_id, user["id"])

    cur = conn.execute("""
        INSERT INTO messages (sender_id, room_id, text)
        VALUES (?, ?, ?)
    """, (user["id"], room_id, text))

    message_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {"ok": True, "id": message_id}


@app.get("/messages/{user_id}")
def get_private_messages(
    user_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    conn = connect()
    rows = conn.execute("""
        SELECT messages.id, messages.sender_id, sender.username AS sender,
               messages.recipient_id, recipient.username AS recipient,
               messages.text, messages.created_at
        FROM messages
        JOIN users AS sender ON sender.id = messages.sender_id
        JOIN users AS recipient ON recipient.id = messages.recipient_id
        WHERE messages.room_id IS NULL
          AND (
              (messages.sender_id = ? AND messages.recipient_id = ?)
              OR
              (messages.sender_id = ? AND messages.recipient_id = ?)
          )
        ORDER BY messages.id
    """, (user["id"], user_id, user_id, user["id"])).fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.post("/messages/{user_id}")
def send_private_message(
    user_id: int,
    data: MessageData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)
    text = data.text.strip()

    if not text:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    conn = connect()
    target = conn.execute(
        "SELECT id FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="Recipient not found")

    cur = conn.execute("""
        INSERT INTO messages (sender_id, recipient_id, text)
        VALUES (?, ?, ?)
    """, (user["id"], user_id, text))

    message_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {"ok": True, "id": message_id}


# ---------- GREEN WALLET ----------

@app.get("/green/balance")
def green_balance(authorization: Optional[str] = Header(default=None)):
    user = user_from_header(authorization)

    conn = connect()
    row = conn.execute(
        "SELECT green_balance FROM users WHERE id = ?",
        (user["id"],)
    ).fetchone()
    conn.close()

    return {"balance": row["green_balance"]}


@app.get("/green/packages")
def green_packages():
    return [
        {"green": amount, "price_rub": price}
        for amount, price in GREEN_PACKAGES.items()
    ]


@app.get("/green/gifts")
def green_gifts():
    return [
        {"name": name, "price": price}
        for name, price in GREEN_GIFTS.items()
    ]


@app.post("/green/gifts/send")
def send_green_gift(
    data: GiftData,
    authorization: Optional[str] = Header(default=None)
):
    sender = user_from_header(authorization)
    recipient_name = data.username.strip().lstrip("@")

    if data.gift not in GREEN_GIFTS:
        raise HTTPException(status_code=400, detail="Unknown gift")

    price = GREEN_GIFTS[data.gift]
    conn = connect()

    try:
        conn.execute("BEGIN IMMEDIATE")

        recipient = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (recipient_name,)
        ).fetchone()

        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")

        if recipient["id"] == sender["id"]:
            raise HTTPException(status_code=400, detail="Cannot gift yourself")

        current = conn.execute(
            "SELECT green_balance FROM users WHERE id = ?",
            (sender["id"],)
        ).fetchone()

        if current["green_balance"] < price:
            raise HTTPException(status_code=400, detail="Not enough Green")

        conn.execute("""
            UPDATE users SET green_balance = green_balance - ?
            WHERE id = ?
        """, (price, sender["id"]))

        conn.execute("""
            UPDATE users SET green_balance = green_balance + ?
            WHERE id = ?
        """, (price, recipient["id"]))

        conn.execute("""
            INSERT INTO green_transactions
            (user_id, amount, kind, description, related_user_id)
            VALUES (?, ?, 'gift_sent', ?, ?)
        """, (
            sender["id"], -price,
            "Подарок: " + data.gift + " пользователю @" + recipient_name,
            recipient["id"]
        ))

        conn.execute("""
            INSERT INTO green_transactions
            (user_id, amount, kind, description, related_user_id)
            VALUES (?, ?, 'gift_received', ?, ?)
        """, (
            recipient["id"], price,
            "Вам отправлено " + data.gift.lower()
            + " стоимостью " + str(price) + " Green.",
            sender["id"]
        ))

        conn.commit()

        return {
            "ok": True,
            "gift": data.gift,
            "price": price,
            "notification": "Вам отправлено " + data.gift.lower()
            + " стоимостью " + str(price) + " Green."
        }

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/green/history")
def green_history(authorization: Optional[str] = Header(default=None)):
    user = user_from_header(authorization)

    conn = connect()
    rows = conn.execute("""
        SELECT id, amount, kind, description, created_at
        FROM green_transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
    """, (user["id"],)).fetchall()
    conn.close()

    return [dict(row) for row in rows]


# ---------- GREEN TOP-UP ORDERS ----------

@app.post("/green/payments")
def create_green_payment(
    data: PaymentData,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    if data.package_green not in GREEN_PACKAGES:
        raise HTTPException(status_code=400, detail="Invalid Green package")

    price = GREEN_PACKAGES[data.package_green]

    conn = connect()
    cur = conn.execute("""
        INSERT INTO green_payments
        (user_id, package_green, amount_rub, status)
        VALUES (?, ?, ?, 'pending')
    """, (user["id"], data.package_green, price))

    payment_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Пока провайдер не подключён, заявка не зачисляет Green.
    return {
        "ok": True,
        "payment_id": payment_id,
        "green": data.package_green,
        "price_rub": price,
        "status": "pending",
        "checkout_url": None,
        "message": "Ожидает оплаты. Платёжный провайдер ещё не подключён."
    }


@app.get("/green/payments/{payment_id}")
def get_green_payment(
    payment_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = user_from_header(authorization)

    conn = connect()
    row = conn.execute("""
        SELECT id, package_green, amount_rub, status, created_at
        FROM green_payments
        WHERE id = ? AND user_id = ?
    """, (payment_id, user["id"])).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Payment not found")

    return dict(row)
