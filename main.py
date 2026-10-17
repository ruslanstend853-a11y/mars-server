from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from pathlib import Path
import sqlite3
import hashlib
import secrets
import os

app = FastAPI(title="Марс API")
DB = "mars.db"

def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

with connect() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            token TEXT
        )
    """)

class Register(BaseModel):
    email: EmailStr
    name: str
    password: str

class Login(BaseModel):
    email: EmailStr
    password: str

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.get("/")
def home():
    return {"app": "Марс", "status": "Сервер работает!"}

@app.post("/register")
def register(data: Register):
    if len(data.password) < 8:
        raise HTTPException(400, "Пароль должен содержать минимум 8 символов")
    if not data.name.strip():
        raise HTTPException(400, "Введите имя")
    try:
        with connect() as db:
            db.execute(
                "INSERT INTO users(email,name,password) VALUES(?,?,?)",
                (data.email.lower(), data.name.strip(),
                 hash_password(data.password))
            )
        return {"ok": True, "message": "Аккаунт создан"}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Этот email уже зарегистрирован")

@app.post("/login")
def login(data: Login):
    with connect() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (data.email.lower(), hash_password(data.password))
        ).fetchone()
        if not user:
            raise HTTPException(401, "Неверный email или пароль")
        token = secrets.token_urlsafe(32)
        db.execute("UPDATE users SET token=? WHERE id=?",
                   (token, user["id"]))
        return {"ok": True, "token": token,
                "user": {"id": user["id"], "name": user["name"],
                         "email": user["email"]}}

@app.get("/users")
def users():
    with connect() as db:
        rows = db.execute("SELECT id,name FROM users").fetchall()
        return [dict(row) for row in rows]
