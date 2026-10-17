import os
import sqlite3
import hashlib
import secrets
from contextlib import contextmanager

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Марс API")

DB_PATH = os.getenv("DB_PATH", "mars.db")
VERIFY_KEY = os.getenv("MARS_VERIFY_KEY", "")

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


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tokens(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contacts(
            user_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            UNIQUE(user_id, contact_id)
        );

        CREATE TABLE IF NOT EXISTS rooms(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            owner_id INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS members(
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER,
            room_id INTEGER,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS green_wallets(
            user_id INTEGER PRIMARY KEY,
            balance INTEGER NOT NULL DEFAULT 0
                CHECK(balance >= 0)
        );

        CREATE TABLE IF NOT EXISTS green_transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            operation TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS green_gifts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            gift_name TEXT NOT NULL,
            cost INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS green_payment_orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            green_amount INTEGER NOT NULL,
            price_rub INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            provider_payment_id TEXT UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)


init_db()


# ===== МОДЕЛИ ЗАПРОСОВ =====

class Credentials(BaseModel):
    username: str
    password: str


class ContactRequest(BaseModel):
    username: str


class RoomRequest(BaseModel):
    name: str
    type: str


class MemberRequest(BaseModel):
    username: str


class MessageRequest(BaseModel):
    text: str


class VerifyRequest(BaseModel):
    key: str


class GreenGiftRequest(BaseModel):
    username: str
    gift_name: str


class GreenOrderRequest(BaseModel):
    green_amount: int


# ===== ОБЩИЕ ФУНКЦИИ =====

def password_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Требуется вход")

    token = authorization[7:].strip()

    with db() as c:
        row = c.execute(
            "SELECT user_id FROM tokens WHERE token_hash=?",
            (token_hash(token),)
        ).fetchone()

    if not row:
        raise HTTPException(401, "Недействительный токен")

    return row["user_id"]


def user_info(user_id):
    with db() as c:
        row = c.execute(
            "SELECT id, username, verified FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

    if not row:
        raise HTTPException(404, "Пользователь не найден")

    return dict(row)


def ensure_green_wallet(c, user_id):
    c.execute(
        "INSERT OR IGNORE INTO green_wallets(user_id, balance) "
        "VALUES(?, 0)",
        (user_id,)
    )


def add_green_transaction(c, user_id, amount, operation, description):
    c.execute("""
        INSERT INTO green_transactions(
            user_id, amount, operation, description
        ) VALUES(?,?,?,?)
    """, (user_id, amount, operation, description))


# ===== ОСНОВНЫЕ ENDPOINTS =====

@app.get("/")
def home():
    return {"app": "Марс", "status": "Сервер работает!"}


@app.post("/register")
def register(data: Credentials):
    name = data.username.strip()

    if len(name) < 3 or len(name) > 32:
        raise HTTPException(400, "Имя должно содержать 3–32 символа")

    if len(data.password) < 8:
        raise HTTPException(400, "Пароль должен содержать минимум 8 символов")

    with db() as c:
        try:
            cur = c.execute(
                "INSERT INTO users(username,password_hash) VALUES(?,?)",
                (name, password_hash(data.password))
            )
            uid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Такое имя уже занято")

        token = secrets.token_urlsafe(32)
        c.execute(
            "INSERT INTO tokens(token_hash,user_id) VALUES(?,?)",
            (token_hash(token), uid)
        )
        ensure_green_wallet(c, uid)

    return {"token": token, "user": user_info(uid)}


@app.post("/login")
def login(data: Credentials):
    with db() as c:
        row = c.execute(
            "SELECT id,password_hash FROM users WHERE username=?",
            (data.username.strip(),)
        ).fetchone()

        if not row or row["password_hash"] != password_hash(data.password):
            raise HTTPException(401, "Неверное имя или пароль")

        uid = row["id"]
        token = secrets.token_urlsafe(32)

        c.execute(
            "INSERT INTO tokens(token_hash,user_id) VALUES(?,?)",
            (token_hash(token), uid)
        )
        ensure_green_wallet(c, uid)

    return {"token": token, "user": user_info(uid)}


@app.get("/profile")
def profile(authorization: str = Header(default="")):
    return user_info(current_user(authorization))


@app.post("/verify")
def verify(data: VerifyRequest, authorization: str = Header(default="")):
    uid = current_user(authorization)

    if not VERIFY_KEY:
        raise HTTPException(503, "Ключ верификации не настроен")

    if not secrets.compare_digest(data.key, VERIFY_KEY):
        raise HTTPException(403, "Неверный ключ")

    with db() as c:
        c.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))

    return {"verified": True}


@app.get("/users")
def users(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        rows = c.execute(
            "SELECT id,username,verified FROM users WHERE id!=? "
            "ORDER BY username LIMIT 200",
            (uid,)
        ).fetchall()

    return [dict(r) for r in rows]


# ===== КОНТАКТЫ =====

@app.post("/contacts")
def add_contact(data: ContactRequest,
                authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        target = c.execute(
            "SELECT id FROM users WHERE username=?",
            (data.username.strip(),)
        ).fetchone()

        if not target:
            raise HTTPException(404, "Пользователь не найден")

        other = target["id"]

        if other == uid:
            raise HTTPException(400, "Нельзя добавить самого себя")

        c.execute(
            "INSERT OR IGNORE INTO contacts VALUES(?,?)",
            (uid, other)
        )
        c.execute(
            "INSERT OR IGNORE INTO contacts VALUES(?,?)",
            (other, uid)
        )

    return {"ok": True}


@app.get("/contacts")
def contacts(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        rows = c.execute("""
            SELECT u.id,u.username,u.verified
            FROM contacts ct JOIN users u ON u.id=ct.contact_id
            WHERE ct.user_id=? ORDER BY u.username
        """, (uid,)).fetchall()

    return [dict(r) for r in rows]


# ===== ГРУППЫ, КАНАЛЫ, СООБЩЕСТВА =====

@app.post("/rooms")
def create_room(data: RoomRequest,
                authorization: str = Header(default="")):
    uid = current_user(authorization)
    name = data.name.strip()
    kind = data.type.strip().lower()

    if not name or len(name) > 80:
        raise HTTPException(400, "Название должно быть от 1 до 80 символов")

    if kind not in ("group", "channel", "community"):
        raise HTTPException(400, "Неизвестный тип пространства")

    with db() as c:
        cur = c.execute(
            "INSERT INTO rooms(name,type,owner_id) VALUES(?,?,?)",
            (name, kind, uid)
        )
        rid = cur.lastrowid

        c.execute(
            "INSERT INTO members(room_id,user_id) VALUES(?,?)",
            (rid, uid)
        )

    return {"id": rid, "name": name, "type": kind}


@app.get("/rooms")
def rooms(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        rows = c.execute("""
            SELECT r.id,r.name,r.type,r.owner_id
            FROM rooms r JOIN members m ON m.room_id=r.id
            WHERE m.user_id=? ORDER BY r.id DESC
        """, (uid,)).fetchall()

    return [dict(r) for r in rows]


@app.post("/rooms/{room_id}/members")
def add_member(room_id: int, data: MemberRequest,
               authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        room = c.execute(
            "SELECT owner_id FROM rooms WHERE id=?",
            (room_id,)
        ).fetchone()

        if not room:
            raise HTTPException(404, "Пространство не найдено")

        if room["owner_id"] != uid:
            raise HTTPException(403, "Добавлять участников может владелец")

        target = c.execute(
            "SELECT id FROM users WHERE username=?",
            (data.username.strip(),)
        ).fetchone()

        if not target:
            raise HTTPException(404, "Пользователь не найден")

        c.execute(
            "INSERT OR IGNORE INTO members(room_id,user_id) VALUES(?,?)",
            (room_id, target["id"])
        )

    return {"ok": True}


@app.get("/rooms/{room_id}/members")
def room_members(room_id: int,
                 authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        allowed = c.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, uid)
        ).fetchone()

        if not allowed:
            raise HTTPException(403, "Нет доступа к этому пространству")

        rows = c.execute("""
            SELECT u.id,u.username,u.verified
            FROM members m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=? ORDER BY u.username
        """, (room_id,)).fetchall()

    return [dict(r) for r in rows]


@app.post("/rooms/{room_id}/messages")
def send_room_message(room_id: int, data: MessageRequest,
                      authorization: str = Header(default="")):
    uid = current_user(authorization)
    message_text = data.text.strip()

    if not message_text or len(message_text) > 5000:
        raise HTTPException(400, "Сообщение должно содержать 1–5000 символов")

    with db() as c:
        room = c.execute(
            "SELECT type,owner_id FROM rooms WHERE id=?",
            (room_id,)
        ).fetchone()

        member = c.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, uid)
        ).fetchone()

        if not room or not member:
            raise HTTPException(403, "Нет доступа к этому пространству")

        if room["type"] == "channel" and room["owner_id"] != uid:
            raise HTTPException(403, "Публиковать может только владелец")

        cur = c.execute("""
            INSERT INTO messages(sender_id,room_id,text)
            VALUES(?,?,?)
        """, (uid, room_id, message_text))

        mid = cur.lastrowid

        row = c.execute("""
            SELECT m.id,m.sender_id,u.username,m.room_id,m.text,m.created_at
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.id=?
        """, (mid,)).fetchone()

    return dict(row)


@app.get("/rooms/{room_id}/messages")
def get_room_messages(room_id: int,
                      authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        member = c.execute(
            "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
            (room_id, uid)
        ).fetchone()

        if not member:
            raise HTTPException(403, "Нет доступа к этому пространству")

        rows = c.execute("""
            SELECT m.id,m.sender_id,u.username,m.room_id,m.text,m.created_at
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.room_id=? ORDER BY m.id DESC LIMIT 100
        """, (room_id,)).fetchall()

    return [dict(r) for r in reversed(rows)]


# ===== ЛИЧНЫЕ СООБЩЕНИЯ =====

@app.post("/messages/{user_id}")
def send_private_message(user_id: int, data: MessageRequest,
                         authorization: str = Header(default="")):
    uid = current_user(authorization)
    message_text = data.text.strip()

    if not message_text or len(message_text) > 5000:
        raise HTTPException(400, "Сообщение должно содержать 1–5000 символов")

    with db() as c:
        target = c.execute(
            "SELECT id FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

        if not target:
            raise HTTPException(404, "Пользователь не найден")

        contact = c.execute(
            "SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?",
            (uid, user_id)
        ).fetchone()

        if not contact:
            raise HTTPException(403, "Сначала добавь пользователя в контакты")

        cur = c.execute("""
            INSERT INTO messages(sender_id,recipient_id,text)
            VALUES(?,?,?)
        """, (uid, user_id, message_text))

        mid = cur.lastrowid

        row = c.execute("""
            SELECT m.id,m.sender_id,u.username,m.recipient_id,
                   m.text,m.created_at
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.id=?
        """, (mid,)).fetchone()

    return dict(row)


@app.get("/messages/{user_id}")
def get_private_messages(user_id: int,
                         authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        contact = c.execute(
            "SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?",
            (uid, user_id)
        ).fetchone()

        if not contact:
            raise HTTPException(403, "Пользователь не в контактах")

        rows = c.execute("""
            SELECT m.id,m.sender_id,s.username,m.recipient_id,
                   m.text,m.created_at
            FROM messages m JOIN users s ON s.id=m.sender_id
            WHERE (m.sender_id=? AND m.recipient_id=?)
               OR (m.sender_id=? AND m.recipient_id=?)
            ORDER BY m.id DESC LIMIT 100
        """, (uid, user_id, user_id, uid)).fetchall()

    return [dict(r) for r in reversed(rows)]


# ===== GREEN: КАТАЛОГ И КОШЕЛЁК =====

@app.get("/green/catalog")
def green_catalog():
    return {
        "currency": "Green",
        "gifts": [
            {"name": name, "price": price}
            for name, price in GREEN_GIFTS.items()
        ],
        "packages": [
            {"green": amount, "price_rub": price}
            for amount, price in GREEN_PACKAGES.items()
        ],
        "payments_enabled": False,
        "message": "Пополнение заработает после настройки платёжного провайдера"
    }


@app.get("/green/wallet")
def green_wallet(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        ensure_green_wallet(c, uid)
        row = c.execute(
            "SELECT balance FROM green_wallets WHERE user_id=?",
            (uid,)
        ).fetchone()

    return {"currency": "Green", "balance": row["balance"]}


@app.get("/green/history")
def green_history(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        ensure_green_wallet(c, uid)

        transactions = c.execute("""
            SELECT id,amount,operation,description,created_at
            FROM green_transactions
            WHERE user_id=? ORDER BY id DESC LIMIT 100
        """, (uid,)).fetchall()

        gifts = c.execute("""
            SELECT g.id,g.gift_name,g.cost,g.created_at,u.username AS sender
            FROM green_gifts g
            JOIN users u ON u.id=g.sender_id
            WHERE g.recipient_id=?
            ORDER BY g.id DESC LIMIT 100
        """, (uid,)).fetchall()

    return {
        "transactions": [dict(r) for r in transactions],
        "received_gifts": [
            {
                "id": r["id"],
                "gift_name": r["gift_name"],
                "cost": r["cost"],
                "sender": r["sender"],
                "notification": (
                    "Вам отправлено " + r["gift_name"].lower()
                    + " стоимостью " + str(r["cost"]) + " Green."
                ),
                "created_at": r["created_at"]
            }
            for r in gifts
        ]
    }


@app.post("/green/gifts")
def send_green_gift(
    data: GreenGiftRequest,
    authorization: str = Header(default="")
):
    uid = current_user(authorization)
    recipient_name = data.username.strip()
    gift_name = data.gift_name.strip()

    if gift_name not in GREEN_GIFTS:
        raise HTTPException(400, "Такого подарка нет в каталоге")

    cost = GREEN_GIFTS[gift_name]

    with db() as c:
        # Блокируем конкурентные изменения баланса.
        c.execute("BEGIN IMMEDIATE")

        recipient = c.execute(
            "SELECT id FROM users WHERE username=?",
            (recipient_name,)
        ).fetchone()

        if not recipient:
            raise HTTPException(404, "Получатель не найден")

        recipient_id = recipient["id"]

        if recipient_id == uid:
            raise HTTPException(400, "Нельзя отправить подарок себе")

        ensure_green_wallet(c, uid)
        ensure_green_wallet(c, recipient_id)

        wallet = c.execute(
            "SELECT balance FROM green_wallets WHERE user_id=?",
            (uid,)
        ).fetchone()

        if wallet["balance"] < cost:
            raise HTTPException(400, "Недостаточно Green")

        c.execute("""
            UPDATE green_wallets
            SET balance=balance-?
            WHERE user_id=? AND balance>=?
        """, (cost, uid, cost))

        if c.execute("SELECT changes()").fetchone()[0] != 1:
            raise HTTPException(400, "Недостаточно Green")

        cur = c.execute("""
            INSERT INTO green_gifts(
                sender_id,recipient_id,gift_name,cost
            ) VALUES(?,?,?,?)
        """, (uid, recipient_id, gift_name, cost))

        gift_id = cur.lastrowid

        add_green_transaction(
            c, uid, -cost, "gift_sent",
            "Подарок: " + gift_name + " пользователю " + recipient_name
        )

        balance = c.execute(
            "SELECT balance FROM green_wallets WHERE user_id=?",
            (uid,)
        ).fetchone()["balance"]

    return {
        "ok": True,
        "gift_id": gift_id,
        "gift_name": gift_name,
        "cost": cost,
        "currency": "Green",
        "recipient": recipient_name,
        "notification": (
            "Вам отправлено " + gift_name.lower()
            + " стоимостью " + str(cost) + " Green."
        ),
        "balance": balance
    }


# ===== ЗАКАЗЫ НА ПОПОЛНЕНИЕ =====
# Создание заказа не означает оплату и не зачисляет Green.
# Подтверждение платежа можно добавить после выбора провайдера.

@app.post("/green/orders")
def create_green_order(
    data: GreenOrderRequest,
    authorization: str = Header(default="")
):
    uid = current_user(authorization)

    if data.green_amount not in GREEN_PACKAGES:
        raise HTTPException(400, "Такого пакета Green нет")

    price = GREEN_PACKAGES[data.green_amount]

    with db() as c:
        cur = c.execute("""
            INSERT INTO green_payment_orders(
                user_id,green_amount,price_rub,status
            ) VALUES(?,?,?,'pending')
        """, (uid, data.green_amount, price))

        order_id = cur.lastrowid

    return {
        "order_id": order_id,
        "green_amount": data.green_amount,
        "price_rub": price,
        "status": "pending",
        "paid": False,
        "message": (
            "Заказ создан, но оплата не подключена. "
            "Green не начислены."
        )
    }


@app.get("/green/orders")
def green_orders(authorization: str = Header(default="")):
    uid = current_user(authorization)

    with db() as c:
        rows = c.execute("""
            SELECT id,green_amount,price_rub,status,created_at
            FROM green_payment_orders
            WHERE user_id=? ORDER BY id DESC LIMIT 100
        """, (uid,)).fetchall()

    return [dict(r) for r in rows]
