import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="Марс API", version="1.0.0")

DB_PATH = os.getenv("DB_PATH", "mars.db")
tokens = {}


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


init_db()


class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=8, max_length=128)


class LoginData(BaseModel):
    username: str
    password: str


class MessageData(BaseModel):
    receiver_id: int
    text: str = Field(min_length=1, max_length=4000)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + ":" + digest


def verify_password(password, stored):
    try:
        salt, expected = stored.split(":", 1)
        return secrets.compare_digest(
            hash_password(password, salt).split(":", 1)[1],
            expected
        )
    except (ValueError, TypeError):
        return False


def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Нужен вход в аккаунт")
    token = authorization[7:]
    user_id = tokens.get(token)
    if user_id is None:
        raise HTTPException(401, "Токен недействителен. Войдите снова.")
    return user_id


@app.get("/")
def home():
    return {"app": "Марс", "status": "Сервер работает!"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register")
def register(data: RegisterData):
    username = data.username.strip()
    if not username or username != data.username:
        raise HTTPException(400, "Имя не должно содержать пробелы по краям")

    with connect() as db:
        try:
            cursor = db.execute(
                "INSERT INTO users(username, password_hash, created_at) "
                "VALUES (?, ?, ?)",
                (
                    username,
                    hash_password(data.password),
                    datetime.now(timezone.utc).isoformat()
                )
            )
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Это имя уже занято")

    token = secrets.token_urlsafe(32)
    tokens[token] = user_id
    return {
        "token": token,
        "user": {"id": user_id, "username": username}
    }


@app.post("/login")
def login(data: LoginData):
    with connect() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()

    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Неверное имя пользователя или пароль")

    token = secrets.token_urlsafe(32)
    tokens[token] = user["id"]
    return {
        "token": token,
        "user": {"id": user["id"], "username": user["username"]}
    }


@app.get("/users")
def list_users(authorization: str = Header(default=None)):
    me = current_user(authorization)
    with connect() as db:
        rows = db.execute(
            "SELECT id, username FROM users WHERE id != ? ORDER BY username",
            (me,)
        ).fetchall()
    return {"users": [dict(row) for row in rows]}


@app.post("/messages")
def send_message(
    data: MessageData,
    authorization: str = Header(default=None)
):
    me = current_user(authorization)
    text = data.text.strip()
    if not text:
        raise HTTPException(400, "Сообщение пустое")
    if data.receiver_id == me:
        raise HTTPException(400, "Нельзя отправить сообщение самому себе")

    with connect() as db:
        receiver = db.execute(
            "SELECT id FROM users WHERE id = ?", (data.receiver_id,)
        ).fetchone()
        if not receiver:
            raise HTTPException(404, "Пользователь не найден")

        cursor = db.execute(
            "INSERT INTO messages(sender_id, receiver_id, text, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                me,
                data.receiver_id,
                text,
                datetime.now(timezone.utc).isoformat()
            )
        )
        message_id = cursor.lastrowid

    return {"id": message_id, "status": "sent"}


@app.get("/messages/{user_id}")
def get_messages(
    user_id: int,
    authorization: str = Header(default=None)
):
    me = current_user(authorization)

    with connect() as db:
        other = db.execute(
            "SELECT id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not other:
            raise HTTPException(404, "Пользователь не найден")

        rows = db.execute("""
            SELECT id, sender_id, receiver_id, text, created_at
            FROM messages
            WHERE (sender_id = ? AND receiver_id = ?)
               OR (sender_id = ? AND receiver_id = ?)
            ORDER BY id ASC
            LIMIT 500
        """, (me, user_id, user_id, me)).fetchall()

    return {"messages": [dict(row) for row in rows]}
