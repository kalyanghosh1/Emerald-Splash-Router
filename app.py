import os
import re
import json
import aiosqlite
import logging
import asyncio
import secrets
import bcrypt
from typing import List, Dict, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status, Response
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx
from datetime import datetime, timezone, timedelta
from collections import deque

# --- CONFIGURATION ---
DB_PATH = "proxy_data.db"
SESSION_TOKEN = secrets.token_hex(16)

# --- SYSTEM LOGS ---
system_logs = deque(maxlen=50)
last_wait_log_time = 0.0

def add_log(msg: str):
    ist = timezone(timedelta(hours=5, minutes=30))
    ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S IST")
    log_line = f"[{ts}] {msg}"
    system_logs.append(log_line)
    logger.info(msg)

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- DATABASE & MODELS ---
class DatabaseManager:
    def __init__(self, path: str):
        self.path = path

    async def _init_db(self):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("PRAGMA journal_mode=WAL;")
            # Table for dynamic endpoints
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider_name TEXT,
                    model_id TEXT,
                    endpoint_url TEXT,
                    api_key TEXT,
                    sdk_type TEXT, -- 'openai' or 'anthropic'
                    priority INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS client_keys (
                    key TEXT PRIMARY KEY,
                    name TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    name TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    endpoint TEXT,
                    status_code INTEGER
                )
            """)
            
            # Default password hashing - User requested "123"
            default_pwd = "123"
            hashed_pwd = bcrypt.hashpw(default_pwd.encode(), bcrypt.gensalt()).decode()
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('admin_password', ?)", (hashed_pwd,))
            await conn.commit()

    async def log_usage(self, endpoint: str, status_code: int):
        ist = timezone(timedelta(hours=5, minutes=30))
        ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT INTO usage_stats (timestamp, endpoint, status_code) VALUES (?, ?, ?)", (ts, endpoint, status_code))
            await conn.commit()

    async def get_endpoints(self):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM endpoints ORDER BY priority DESC, created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def add_endpoint(self, provider_name: str, model_id: str, endpoint_url: str, api_key: str, sdk_type: str, priority: int = 0):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("""
                INSERT INTO endpoints (provider_name, model_id, endpoint_url, api_key, sdk_type, priority)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (provider_name, model_id, endpoint_url, api_key, sdk_type, priority))
            await conn.commit()

    async def delete_endpoint(self, id: int):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM endpoints WHERE id = ?", (id,))
            await conn.commit()

    async def get_client_keys(self):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM client_keys ORDER BY created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def generate_client_key(self, name: str) -> str:
        new_key = f"emerald_sk_{secrets.token_hex(16)}"
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT INTO client_keys (key, name) VALUES (?, ?)", (new_key, name))
            await conn.commit()
        return new_key

    async def revoke_client_key(self, key: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM client_keys WHERE key = ?", (key,))
            await conn.commit()

    async def validate_client_key(self, key: str) -> bool:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT is_active FROM client_keys WHERE key = ?", (key,)) as cursor:
                row = await cursor.fetchone()
                if row and row[0] == 1:
                    return True
                return False

    async def get_admin_password_hash(self) -> str:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'admin_password'") as cursor:
                row = await cursor.fetchone()
                return row[0] if row else ""

    async def set_admin_password(self, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'admin_password'", (hashed,))
            await conn.commit()

db = DatabaseManager(DB_PATH)

# --- LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db._init_db()
    yield
    await proxy_client.aclose()

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

# --- AUTH DEPENDENCY ---
def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SESSION_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session")
    return True

# --- ADMIN API ---
class AuthRequest(BaseModel):
    pin: str

@app.post("/admin/auth")
async def admin_auth(req: AuthRequest):
    stored_hash = await db.get_admin_password_hash()
    if bcrypt.checkpw(req.pin.encode(), stored_hash.encode()):
        return {"token": SESSION_TOKEN}
    raise HTTPException(status_code=401, detail="Invalid Password")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin/endpoints", dependencies=[Depends(verify_admin_token)])
async def list_endpoints():
    return {"endpoints": await db.get_endpoints()}

class EndpointAddRequest(BaseModel):
    provider_name: str
    model_id: str
    endpoint_url: str
    api_key: str
    sdk_type: str
    priority: int = 0

@app.post("/admin/endpoints", dependencies=[Depends(verify_admin_token)])
async def add_endpoint(req: EndpointAddRequest):
    await db.add_endpoint(req.provider_name, req.model_id, req.endpoint_url, req.api_key, req.sdk_type, req.priority)
    return {"success": True}

@app.delete("/admin/endpoints/{id}", dependencies=[Depends(verify_admin_token)])
async def delete_endpoint(id: int):
    await db.delete_endpoint(id)
    return {"success": True}

@app.post("/admin/test_endpoint", dependencies=[Depends(verify_admin_token)])
async def test_endpoint(req: EndpointAddRequest):
    """Test if an endpoint works and determine its SDK type if not provided"""
    test_payload = {
        "model": req.model_id,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 5
    }
    
    headers = {"Authorization": f"Bearer {req.api_key}", "Content-Type": "application/json"}
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Try as OpenAI first
        try:
            resp = await client.post(req.endpoint_url, json=test_payload, headers=headers)
            if resp.status_code == 200:
                return {"success": True, "sdk_type": "openai", "message": "Connected successfully as OpenAI"}
        except:
            pass
            
        # Try as Anthropic
        anthropic_payload = {
            "model": req.model_id,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5
        }
        anthropic_headers = {
            "x-api-key": req.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        try:
            resp = await client.post(req.endpoint_url, json=anthropic_payload, headers=anthropic_headers)
            if resp.status_code == 200:
                return {"success": True, "sdk_type": "anthropic", "message": "Connected successfully as Anthropic"}
        except:
            pass
            
    return {"success": False, "message": "Failed to connect to endpoint"}

# --- CLIENT KEYS API ---
@app.get("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def list_client_keys():
    return {"keys": await db.get_client_keys()}

class ClientKeyAddRequest(BaseModel):
    name: str

@app.post("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def add_client_key(req: ClientKeyAddRequest):
    new_key = await db.generate_client_key(req.name)
    return {"success": True, "key": new_key}

@app.delete("/admin/client-keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_client_key(key: str):
    await db.revoke_client_key(key)
    return {"success": True}

# --- SETTINGS API ---
class PasswordChangeRequest(BaseModel):
    new_password: str

@app.post("/admin/password", dependencies=[Depends(verify_admin_token)])
async def change_password(req: PasswordChangeRequest):
    await db.set_admin_password(req.new_password)
    return {"success": True}

# --- ANALYTICS API ---
@app.get("/admin/analytics", dependencies=[Depends(verify_admin_token)])
async def get_analytics():
    ist = timezone(timedelta(hours=5, minutes=30))
    now = datetime.now(ist)
    
    async def get_count(start_time: str):
        async with aiosqlite.connect(DB_PATH) as conn:
            async with conn.execute("SELECT COUNT(*) FROM usage_stats WHERE timestamp >= ?", (start_time,)) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0

    today = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    this_week = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    this_month = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    this_year = (now - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "today": await get_count(today),
        "this_week": await get_count(this_week),
        "this_month": await get_count(this_month),
        "this_year": await get_count(this_year)
    }

# --- SYSTEM LOGS API ---
@app.get("/admin/live_status", dependencies=[Depends(verify_admin_token)])
async def live_status():
    return {"logs": list(system_logs)}

# ---------------------------------------------------------
# TRANSLATION LAYER
# ---------------------------------------------------------
proxy_client = httpx.AsyncClient(timeout=900.0, follow_redirects=True)

def translate_anthropic_req_to_openai(anthropic_json: dict) -> dict:
    """Translates Anthropic JSON payload to OpenAI JSON payload"""
    model = anthropic_json.get("model", "gpt-4")
    openai_json = {
        "model": model,
        "max_tokens": anthropic_json.get("max_tokens", 1024),
        "stream": anthropic_json.get("stream", False),
        "messages": []
    }
    
    if "system" in anthropic_json and anthropic_json["system"]:
        sys_content = anthropic_json["system"]
        if isinstance(sys_content, list):
            sys_content = "".join([block.get("text", "") for block in sys_content if block.get("type") == "text"])
        sys_content = re.sub(r'^x-anthropic-billing-header:\s*(?:[a-z_]+=[^\s;]+;\s*)*', '', sys_content).strip()
        if sys_content:
            openai_json["messages"].append({"role": "system", "content": sys_content})
        
    for msg in anthropic_json.get("messages", []):
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, str):
            openai_json["messages"].append({"role": role, "content": content})
        elif isinstance(content, list):
            # Simplified list handling for now
            text = "".join([c.get("text", "") for c in content if c.get("type") == "text"])
            openai_json["messages"].append({"role": role, "content": text})

    return openai_json

def translate_openai_resp_to_anthropic(openai_json: dict) -> dict:
    """Translates OpenAI response to Anthropic Message response"""
    content_blocks = []
    if "choices" in openai_json and len(openai_json["choices"]) > 0:
        content = openai_json["choices"][0].get("message", {}).get("content", "")
        if content:
            content_blocks.append({"type": "text", "text": content})
            
    return {
        "id": "msg_" + secrets.token_hex(8),
        "type": "message",
        "role": "assistant",
        "model": openai_json.get("model", "openai"),
        "content": content_blocks,
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 0, "output_tokens": 0}
    }

async def stream_openai_to_anthropic(upstream_resp, original_model):
    """Translates OpenAI SSE to Anthropic SSE"""
    yield f'event: message_start\ndata: {json.dumps({"type": "message_start", "message": {"id": "msg_"+secrets.token_hex(8), "type": "message", "role": "assistant", "content": [], "model": original_model, "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}})}\n\n'.encode()
    yield f'event: content_block_start\ndata: {json.dumps({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})}\n\n'.encode()
    
    async for line in upstream_resp.aiter_lines():
        if line.startswith("data: "):
            data_str = line[6:].strip()
            if data_str == "[DONE]": break
            try:
                data = json.loads(data_str)
                delta = data["choices"][0].get("delta", {}).get("content", "")
                if delta:
                    yield f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": delta}})}\n\n'.encode()
            except: continue
            
    yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": 0})}\n\n'.encode()
    yield f'event: message_delta\ndata: {json.dumps({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 10}})}\n\n'.encode()
    yield b'event: message_stop\ndata: {"type": "message_stop"}\n\n'

# --- THE CORE PROXY ENGINE ---
async def core_proxy(request: Request, input_is_anthropic: bool = False):
    client_key = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("x-api-key")
    if not client_key or not await db.validate_client_key(client_key):
        return JSONResponse({"error": {"message": "Invalid API key"}}, status_code=401)

    raw_body = await request.body()
    body_json = json.loads(raw_body) if raw_body else {}
    is_stream = body_json.get("stream", False)
    original_model = body_json.get("model", "default")
    
    endpoints = await db.get_endpoints()
    if not endpoints:
        return JSONResponse({"error": {"message": "No configured endpoints"}}, status_code=503)

    for ep in endpoints:
        # Prepare target headers and body
        target_url = ep['endpoint_url']
        target_sdk = ep['sdk_type']
        api_key = ep['api_key']
        
        current_body = body_json.copy()
        current_body["model"] = ep["model_id"] # Override with the configured model ID
        
        headers = {"Content-Type": "application/json"}
        if target_sdk == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
            if input_is_anthropic:
                current_body = translate_anthropic_req_to_openai(current_body)
        else: # target is anthropic
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
            if not input_is_anthropic:
                # Need OpenAI -> Anthropic translation (Simplified)
                anth_messages = []
                for m in current_body.get("messages", []):
                    if m["role"] == "system": continue
                    anth_messages.append({"role": m["role"], "content": m["content"]})
                current_body = {
                    "model": ep["model_id"],
                    "messages": anth_messages,
                    "max_tokens": current_body.get("max_tokens", 1024),
                    "stream": is_stream
                }

        try:
            proxy_req = proxy_client.build_request(
                method="POST", url=target_url, headers=headers, content=json.dumps(current_body).encode()
            )
            resp = await proxy_client.send(proxy_req, stream=is_stream)
            await db.log_usage(target_url, resp.status_code)
            
            if resp.status_code >= 400:
                add_log(f"Endpoint {ep['provider_name']} failed with {resp.status_code}. Switching...")
                await resp.aclose()
                continue

            # Success! Handle response
            if is_stream:
                if input_is_anthropic and target_sdk == "openai":
                    return StreamingResponse(stream_openai_to_anthropic(resp, original_model), media_type="text/event-stream")
                # Add more streaming translations if needed, otherwise passthrough
                return StreamingResponse(resp.aiter_bytes(), status_code=resp.status_code, headers=dict(resp.headers))
            else:
                content = await resp.aread()
                resp_json = json.loads(content)
                if input_is_anthropic and target_sdk == "openai":
                    return JSONResponse(translate_openai_resp_to_anthropic(resp_json))
                # Add Anthropic -> OpenAI sync response translation if needed
                return Response(content=content, status_code=resp.status_code, headers=dict(resp.headers))

        except Exception as e:
            add_log(f"Error connecting to {ep['provider_name']}: {str(e)}")
            continue

    return JSONResponse({"error": {"message": "All endpoints failed"}}, status_code=502)

# --- ROUTES ---
@app.post("/v1/messages")
@app.post("/v1/v1/messages")
async def anthropic_proxy(request: Request):
    return await core_proxy(request, input_is_anthropic=True)

@app.post("/v1/chat/completions")
@app.post("/v1/v1/chat/completions")
async def openai_proxy(request: Request):
    return await core_proxy(request, input_is_anthropic=False)

@app.get("/v1/models")
async def list_models():
    endpoints = await db.get_endpoints()
    models = [{"id": ep["model_id"], "object": "model", "owned_by": ep["provider_name"]} for ep in endpoints]
    return {"data": models}

@app.get("/v1", methods=["GET", "HEAD"])
async def v1_status():
    return {"status": "running", "name": "Emerald Splash Router"}
