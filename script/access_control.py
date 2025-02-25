# 🚀 Secure FastAPI API with Access Control Best Practices
from fastapi import FastAPI, Request, HTTPException
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

app = FastAPI()

# ✅ 1. Implement Rate Limiting to Prevent DDoS & Brute Force
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(HTTPException, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

@app.post("/login")
@limiter.limit("5/10seconds")  # 🔹 Allow only 5 login attempts per 10 seconds
def login():
    return {"message": "Login successful"}

# ✅ 2. Force HTTPS with HSTS Header
@app.middleware("http")
async def hsts_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

# ✅ 3. Restrict Directory Listings (Only Allow Specific Files)
ALLOWED_FILES = ["public/index.html", "public/style.css"]
@app.get("/files/{file_path:path}")
def get_file(file_path: str):
    if file_path not in ALLOWED_FILES:
        raise HTTPException(status_code=403, detail="Access Denied")
    return {"message": f"Accessing {file_path}"}

# ✅ 4. Restrict Private APIs to Safe-Listed IPs
SAFE_IPS = ["192.168.1.100", "203.0.113.5", "127.0.0.1"]
@app.middleware("http")
async def restrict_private_api(request: Request, call_next):
    client_ip = request.client.host
    if request.url.path.startswith("/private") and client_ip not in SAFE_IPS:
        raise HTTPException(status_code=403, detail="Access Denied: Unauthorized IP")
    return await call_next(request)

@app.get("/private/data")
def private_api():
    return {"message": "Access Granted to Private API"}

# ✅ 5. Public API (Accessible by everyone)
@app.get("/")
def public_api():
    return {"message": "This is a public API"}
