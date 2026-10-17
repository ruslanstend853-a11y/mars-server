
from fastapi import FastAPI

app = FastAPI(title="Mars Server")

@app.get("/")
def home():
    return {
        "app": "Марс",
        "status": "Сервер работает!"
    }

@app.get("/health")
def health():
    return {"ok": True}
