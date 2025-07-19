from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import subprocess
import uuid
import shutil

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BOTS_DIR = "cloud_bots"
PROCESSES = {}

os.makedirs(BOTS_DIR, exist_ok=True)

@app.post("/upload_bot/")
def upload_bot(user_id: str = Form(...), bot_name: str = Form(...), bot_code: UploadFile = None, bot_token: str = Form(...)):
    bot_id = str(uuid.uuid4())
    user_dir = os.path.join(BOTS_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    bot_path = os.path.join(user_dir, f"{bot_name}_{bot_id}.py")
    code = bot_code.file.read().decode()
    code = code.replace("YOUR_BOT_TOKEN_HERE", bot_token)
    with open(bot_path, "w") as f:
        f.write(code)
    if bot_id in PROCESSES:
        try:
            PROCESSES[bot_id].terminate()
        except Exception:
            pass
    process = subprocess.Popen(["python", bot_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    PROCESSES[bot_id] = process
    return {"status": "ok", "bot_id": bot_id}

@app.post("/stop_bot/")
def stop_bot(user_id: str = Form(...), bot_id: str = Form(...)):
    if bot_id in PROCESSES:
        try:
            PROCESSES[bot_id].terminate()
        except Exception:
            pass
        del PROCESSES[bot_id]
    return {"status": "stopped"}

@app.get("/list_bots/")
def list_bots(user_id: str):
    user_dir = os.path.join(BOTS_DIR, user_id)
    if not os.path.exists(user_dir):
        return {"bots": []}
    bots = [f for f in os.listdir(user_dir) if f.endswith(".py")]
    return {"bots": bots}

@app.post("/delete_bot/")
def delete_bot(user_id: str = Form(...), bot_id: str = Form(...)):
    user_dir = os.path.join(BOTS_DIR, user_id)
    for fname in os.listdir(user_dir):
        if bot_id in fname:
            try:
                os.remove(os.path.join(user_dir, fname))
            except Exception:
                pass
    if bot_id in PROCESSES:
        try:
            PROCESSES[bot_id].terminate()
        except Exception:
            pass
        del PROCESSES[bot_id]
    return {"status": "deleted"} 