"""Intentionally vulnerable local API and its hardened comparison mode.

All data are in memory. Never deploy the vulnerable mode to a network.
"""
import os
import time
import secrets
from collections import defaultdict, deque
from threading import Lock
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

class Login(BaseModel):
    username: str
    password: str

class Profile(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)

class SecurityState:
    def __init__(self):
        self.users = {
            "alice": {"password": "alice-demo", "display_name": "Alice", "role": "user"},
            "bob": {"password": "bob-demo", "display_name": "Bob", "role": "user"},
        }
        self.sessions = {}
        self.attempts = defaultdict(deque)
        self.events = []
        self.lock = Lock()

    def log(self, kind, **fields):
        with self.lock:
            self.events.append({"timestamp": time.time(), "event": kind, **fields})
            self.events[:] = self.events[-1000:]

def create_app(vulnerable=False, clock=time.monotonic):
    api = FastAPI(title="API Security Lab", version="1.0.0")
    state = SecurityState()
    api.state.lab = state
    api.state.vulnerable = vulnerable

    def actor(request: Request):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        username = state.sessions.get(token)
        if not username:
            state.log("authentication_failed", path=request.url.path)
            raise HTTPException(401, "Authentication required")
        return username

    @api.get("/health")
    def health():
        return {"status": "ok", "mode": "vulnerable" if vulnerable else "hardened"}

    @api.post("/login")
    def login(data: Login, request: Request):
        # Hardened mode counts all requests per server-observed client address.
        # Vulnerable mode incorrectly trusts a client-controlled forwarding header.
        client = (request.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()
                  if vulnerable else (request.client.host if request.client else "unknown"))
        now = clock()
        with state.lock:
            q = state.attempts[client]
            while q and now - q[0] >= 60:
                q.popleft()
            if not vulnerable and len(q) >= 3:
                state.events.append({"timestamp": time.time(), "event": "rate_limit_exceeded", "client": client})
                raise HTTPException(429, "Too many requests")
            q.append(now)
        user = state.users.get(data.username)
        if not user or not secrets.compare_digest(user["password"], data.password):
            state.log("login_failed", username=data.username, client=client)
            raise HTTPException(401, "Invalid credentials")
        token = secrets.token_urlsafe(24)
        state.sessions[token] = data.username
        state.log("login_success", username=data.username, client=client)
        return {"access_token": token, "token_type": "bearer"}

    @api.get("/users/{username}")
    def get_user(username: str, request: Request):
        current = actor(request)
        if not vulnerable and current != username:
            state.log("access_denied", actor=current, target=username)
            raise HTTPException(403, "Forbidden")
        target = state.users.get(username)
        if target is None:
            raise HTTPException(404, "Not found")
        state.log("profile_read", actor=current, target=username)
        return {"username": username, "display_name": target["display_name"], "role": target["role"]}

    @api.patch("/users/{username}")
    async def update_user(username: str, request: Request):
        current = actor(request)
        if username not in state.users:
            raise HTTPException(404, "Not found")
        if not vulnerable and current != username:
            state.log("access_denied", actor=current, target=username)
            raise HTTPException(403, "Forbidden")
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(422, "Expected object")
        if vulnerable:
            # Deliberately insecure: accepts untrusted fields, including role.
            state.users[username].update(body)
        else:
            profile = Profile.model_validate(body)
            if set(body) != {"display_name"}:
                state.log("mass_assignment_blocked", actor=current, fields=sorted(body))
                raise HTTPException(422, "Unexpected fields")
            state.users[username]["display_name"] = profile.display_name
        state.log("profile_updated", actor=current, target=username, fields=sorted(body))
        return {"username": username, "display_name": state.users[username]["display_name"], "role": state.users[username]["role"]}

    @api.get("/events")
    def events(request: Request):
        current = actor(request)
        if not vulnerable:
            raise HTTPException(403, "Not exposed in hardened mode")
        state.log("events_read", actor=current)
        return state.events

    return api

# Explicit opt-in required for vulnerable mode. Always bind to 127.0.0.1.
app = create_app(os.getenv("LAB_MODE", "hardened") == "vulnerable")
