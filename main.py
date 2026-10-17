
import os
import secrets
import sqlite3
import hashlib
from contextlib import contextmanager

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Марс API", version="2.0")

DB_PATH = os.getenv("DB_PATH", "mars.db")
VERIFY_KEY = os.getenv("MARS_VERIFY_KEY", "")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                token_hash TEXT,
                verified INTEGER NOT NULL DEFAULT 0
            )
        """)


@app.on_event("startup")
def startup():
    init_db()


class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class LoginData(BaseModel):
    username: str
    password: str


class VerifyData(BaseModel):
    key: str


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.scrypt(
        password.encode(),
        salt=bytes.fromhex(salt),
        n=2**14,
        r=8,
        p=1
    ).hex()
    return salt + ":" + hashed


def check_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt),
            n=2**14,
            r=8,
            p=1
        ).hex()
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_token():
    return secrets.token_urlsafe(32)


def get_user_id(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Требуется авторизация")

    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with db() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE token_hash = ?",
            (token_hash,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Сессия недействительна")

    return user["id"]


@app.get("/")
def root():
    return {"app": "Марс", "status": "Сервер работает!"}


@app.post("/register")
def register(data: RegisterData):
    username = data.username.strip()

    if not username:
        raise HTTPException(400, "Введите имя пользователя")

    token = create_token()
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO users
                   (username, password_hash, token_hash, verified)
                   VALUES (?, ?, ?, 0)""",
                (username, hash_password(data.password), token_hash)
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Такое имя уже занято")

    return {
        "token": token,
        "user": {
            "id": user_id,
            "username": username,
            "verified": False
        }
    }


@app.post("/login")
def login(data: LoginData):
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (data.username.strip(),)
        ).fetchone()

        if not user or not check_password(
            data.password, user["password_hash"]
        ):
            raise HTTPException(401, "Неверный логин или пароль")

        token = create_token()
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        conn.execute(
            "UPDATE users SET token_hash = ? WHERE id = ?",
            (token_hash, user["id"])
        )

        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "verified": bool(user["verified"])
            }
        }


@app.get("/profile")
def profile(authorization: str | None = Header(default=None)):
    user_id = get_user_id(authorization)

    with db() as conn:
        user = conn.execute(
            "SELECT id, username, verified FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if not user:
        raise HTTPException(404, "Аккаунт не найден")

    return {
        "id": user["id"],
        "username": user["username"],
        "verified": bool(user["verified"])
    }


@app.post("/verify")
def verify(
    data: VerifyData,
    authorization: str | None = Header(default=None)
):
    user_id = get_user_id(authorization)

    # Ключ должен храниться в переменной окружения сервера,
    # а не в Android-приложении.
    if not VERIFY_KEY:
        raise HTTPException(
            503,
            "Администратор не настроил ключ верификации"
        )

    if not secrets.compare_digest(data.key, VERIFY_KEY):
        raise HTTPException(400, "Неверный ключ")

    with db() as conn:
        conn.execute(
            "UPDATE users SET verified = 1 WHERE id = ?",
            (user_id,)
        )

        user = conn.execute(
            "SELECT id, username, verified FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    return {
        "success": True,
        "message": "Участие в Litvon подтверждено",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "verified": bool(user["verified"])
        }
    }
