import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Марс API", version="2.0")

DB_PATH = os.getenv("DB_PATH", "mars.db")
tokens = {}


def now():
    return datetime.now(timezone.utc).isoformat()


def db_connect():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with db_connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, contact_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(contact_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('group','community')),
            owner_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS members (
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY(room_id, user_id),
            FOREIGN KEY(room_id) REFERENCES rooms(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER,
            room_id INTEGER,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id),
            FOREIGN KEY(room_id) REFERENCES rooms(id)
        );
        """)


init_db()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=8, max_length=128)


class ContactData(BaseModel):
    username: str = Field(min_length=3, max_length=24)


class RoomData(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    kind: str


class MemberData(BaseModel):
    username: str = Field(min_length=3, max_length=24)


class MessageData(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"),
        salt.encode("utf-8"), 200000
    ).hex()
    return salt + ":" + digest


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":", 1)
        actual = password_hash(password, salt).split(":", 1)[1]
        return secrets.compare_digest(actual, expected)
    except (ValueError, AttributeError):
        return False


def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Сначала войдите в аккаунт")
    user_id = tokens.get(authorization[7:])
    if user_id is None:
        raise HTTPException(401, "Сессия истекла. Войдите снова")
    return user_id


def require_room_member(con, room_id, user_id):
    room = con.execute(
        "SELECT * FROM rooms WHERE id=?", (room_id,)
    ).fetchone()
    if not room:
        raise HTTPException(404, "Чат не найден")
    member = con.execute(
        "SELECT 1 FROM members WHERE room_id=? AND user_id=?",
        (room_id, user_id)
    ).fetchone()
    if not member:
        raise HTTPException(403, "У вас нет доступа к этому чату")
    return room


@app.get("/")
def home():
    return {"app": "Марс", "status": "Сервер работает!", "version": 2}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register")
def register(data: Credentials):
    username = data.username.strip()
    if username != data.username:
        raise HTTPException(400, "Уберите пробелы по краям имени")

    with db_connect() as con:
        try:
            cur = con.execute(
                "INSERT INTO users(username,password_hash,created_at) "
                "VALUES(?,?,?)",
                (username, password_hash(data.password), now())
            )
            uid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Это имя уже занято")

    token = secrets.token_urlsafe(32)
    tokens[token] = uid
    return {"token": token, "user": {"id": uid, "username": username}}


@app.post("/login")
def login(data: Credentials):
    with db_connect() as con:
        user = con.execute(
            "SELECT * FROM users WHERE username=?",
            (data.username,)
        ).fetchone()

    if not user or not verify_password(
        data.password, user["password_hash"]
    ):
        raise HTTPException(401, "Неверное имя или пароль")

    token = secrets.token_urlsafe(32)
    tokens[token] = user["id"]
    return {
        "token": token,
        "user": {"id": user["id"], "username": user["username"]}
    }


@app.get("/users")
def users(authorization: str = Header(default=None)):
    uid = current_user(authorization)
    with db_connect() as con:
        rows = con.execute(
            "SELECT id,username FROM users WHERE id!=? ORDER BY username",
            (uid,)
        ).fetchall()
    return {"users": [dict(r) for r in rows]}


@app.post("/contacts")
def add_contact(
    data: ContactData,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    with db_connect() as con:
        user = con.execute(
            "SELECT id,username FROM users WHERE username=?",
            (data.username.strip(),)
        ).fetchone()
        if not user:
            raise HTTPException(404, "Пользователь не найден")
        if user["id"] == uid:
            raise HTTPException(400, "Нельзя добавить самого себя")
        con.execute(
            "INSERT OR IGNORE INTO contacts VALUES(?,?,?)",
            (uid, user["id"], now())
        )
    return {"status": "added", "user": dict(user)}


@app.get("/contacts")
def contacts(authorization: str = Header(default=None)):
    uid = current_user(authorization)
    with db_connect() as con:
        rows = con.execute("""
            SELECT u.id,u.username
            FROM contacts c JOIN users u ON u.id=c.contact_id
            WHERE c.user_id=? ORDER BY u.username
        """, (uid,)).fetchall()
    return {"contacts": [dict(r) for r in rows]}


@app.post("/rooms")
def create_room(
    data: RoomData,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Введите название")
    if data.kind not in ("group", "community"):
        raise HTTPException(400, "Тип должен быть group или community")

    with db_connect() as con:
        cur = con.execute(
            "INSERT INTO rooms(name,kind,owner_id,created_at) VALUES(?,?,?,?)",
            (name, data.kind, uid, now())
        )
        rid = cur.lastrowid
        con.execute(
            "INSERT INTO members(room_id,user_id) VALUES(?,?)",
            (rid, uid)
        )
    return {"id": rid, "name": name, "kind": data.kind}


@app.get("/rooms")
def list_rooms(authorization: str = Header(default=None)):
    uid = current_user(authorization)
    with db_connect() as con:
        rows = con.execute("""
            SELECT r.id,r.name,r.kind,r.owner_id
            FROM rooms r JOIN members m ON m.room_id=r.id
            WHERE m.user_id=? ORDER BY r.id DESC
        """, (uid,)).fetchall()
    return {"rooms": [dict(r) for r in rows]}


@app.post("/rooms/{room_id}/members")
def add_member(
    room_id: int,
    data: MemberData,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    with db_connect() as con:
        room = require_room_member(con, room_id, uid)
        if room["owner_id"] != uid:
            raise HTTPException(403, "Добавлять участников может создатель")

        user = con.execute(
            "SELECT id,username FROM users WHERE username=?",
            (data.username.strip(),)
        ).fetchone()
        if not user:
            raise HTTPException(404, "Пользователь не найден")

        con.execute(
            "INSERT OR IGNORE INTO members(room_id,user_id) VALUES(?,?)",
            (room_id, user["id"])
        )
    return {"status": "added", "user": dict(user)}


@app.get("/rooms/{room_id}/members")
def room_members(
    room_id: int,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    with db_connect() as con:
        require_room_member(con, room_id, uid)
        rows = con.execute("""
            SELECT u.id,u.username
            FROM members m JOIN users u ON u.id=m.user_id
            WHERE m.room_id=? ORDER BY u.username
        """, (room_id,)).fetchall()
    return {"members": [dict(r) for r in rows]}


@app.post("/rooms/{room_id}/messages")
def room_send(
    room_id: int,
    data: MessageData,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    text = data.text.strip()
    if not text:
        raise HTTPException(400, "Пустое сообщение")
    with db_connect() as con:
        require_room_member(con, room_id, uid)
        cur = con.execute(
            "INSERT INTO messages(sender_id,room_id,text,created_at) "
            "VALUES(?,?,?,?)",
            (uid, room_id, text, now())
        )
    return {"id": cur.lastrowid, "status": "sent"}


@app.get("/rooms/{room_id}/messages")
def room_history(
    room_id: int,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    with db_connect() as con:
        require_room_member(con, room_id, uid)
        rows = con.execute("""
            SELECT m.id,m.sender_id,u.username AS sender,
                   m.text,m.created_at
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.room_id=? ORDER BY m.id DESC LIMIT 200
        """, (room_id,)).fetchall()
    return {"messages": [dict(r) for r in reversed(rows)]}


@app.post("/messages/{user_id}")
def send_private(
    user_id: int,
    data: MessageData,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    text = data.text.strip()
    if not text:
        raise HTTPException(400, "Пустое сообщение")
    if user_id == uid:
        raise HTTPException(400, "Нельзя писать самому себе")

    with db_connect() as con:
        target = con.execute(
            "SELECT id FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not target:
            raise HTTPException(404, "Пользователь не найден")
        cur = con.execute(
            "INSERT INTO messages(sender_id,receiver_id,text,created_at) "
            "VALUES(?,?,?,?)",
            (uid, user_id, text, now())
        )
    return {"id": cur.lastrowid, "status": "sent"}


@app.get("/messages/{user_id}")
def private_history(
    user_id: int,
    authorization: str = Header(default=None)
):
    uid = current_user(authorization)
    with db_connect() as con:
        rows = con.execute("""
            SELECT m.id,m.sender_id,m.receiver_id,u.username AS sender,
                   m.text,m.created_at
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE (m.sender_id=? AND m.receiver_id=?)
               OR (m.sender_id=? AND m.receiver_id=?)
            ORDER BY m.id DESC LIMIT 200
        """, (uid, user_id, user_id, uid)).fetchall()
    return {"messages": [dict(r) for r in reversed(rows)]}
