from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from pydantic import BaseModel
from transformers import pipeline
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import os, time, hashlib, jwt

# ====== Config ======
SECRET_KEY = os.getenv("JWT_SECRET", "dev-not-secure")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 30 * 60

# Demo user
DEMO_USER = {"username": "demo", "password_hash": hashlib.sha256(b"demo123!").hexdigest()}

def verify_password(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == hashed

def create_token(sub: str) -> str:
    payload = {"sub": sub, "exp": int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

oauth2 = OAuth2PasswordBearer(tokenUrl="token")

def current_user(token: str = Depends(oauth2)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

# ====== FastAPI App ======
app = FastAPI(title="Secure ML API")

# CORS (tighten in prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["GET","POST"], allow_headers=["*"], allow_credentials=False
)

# Security headers (helps with ZAP warnings)
class SecureHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=()"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' data:"
        return resp
app.add_middleware(SecureHeaders)

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Schemas
class PredictIn(BaseModel):
    text: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Health
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# Auth (demo)
@app.post("/token", response_model=TokenOut)
@limiter.limit("10/minute")
def token(form: OAuth2PasswordRequestForm = Depends()):
    if form.username != DEMO_USER["username"] or not verify_password(form.password, DEMO_USER["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    return {"access_token": create_token(form.username)}

# ML inference
clf = pipeline("sentiment-analysis", device=-1)

@app.post("/predict")
@limiter.limit("30/minute")
def predict(body: PredictIn, user: str = Depends(current_user)):
    out = clf(body.text)[0]
    return {"user": user, "label": out["label"], "score": float(out["score"])}