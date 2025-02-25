# 🚀 Secure OAuth Implementation in FastAPI
import secrets
from fastapi import FastAPI, HTTPException, Query
from authlib.integrations.starlette_client import OAuth
from itsdangerous import URLSafeSerializer
from urllib.parse import urlparse

app = FastAPI()

# ✅ OAuth Configuration (Replace with actual values)
OAUTH_CLIENT_ID = "your-client-id"
OAUTH_CLIENT_SECRET = "your-client-secret"
OAUTH_AUTHORIZATION_URL = "https://oauth.example.com/authorize"
OAUTH_TOKEN_URL = "https://oauth.example.com/token"
OAUTH_REDIRECT_URI = "https://yourapp.com/callback"
SECRET_KEY = "super-secret-key"

oauth = OAuth()
oauth.register(
    name="example",
    client_id=OAUTH_CLIENT_ID,
    client_secret=OAUTH_CLIENT_SECRET,
    authorize_url=OAUTH_AUTHORIZATION_URL,
    access_token_url=OAUTH_TOKEN_URL,
    redirect_uri=OAUTH_REDIRECT_URI,
)

# ✅ Security Components
serializer = URLSafeSerializer(SECRET_KEY)
DEFAULT_SCOPE = ["openid", "profile"]
ALLOWED_SCOPES = ["openid", "profile", "email", "read:data", "write:data"]
ALLOWED_REDIRECT_URIS = ["https://trustedapp.com/callback", "https://secureapp.com/oauth/callback"]

# 📌 Validate Redirect URI to Prevent Open Redirect Attacks
@app.get("/authorize")
def authorize(redirect_uri: str = Query(...)):
    if redirect_uri not in ALLOWED_REDIRECT_URIS:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    return {"message": "Redirect URI is valid", "redirect_uri": redirect_uri}

# 📌 Step 1: Redirect to Authorization Server with Secure State
@app.get("/oauth/login")
def oauth_login(scope: str = Query(",".join(DEFAULT_SCOPE))):
    requested_scopes = scope.split(",")

    # ✅ Validate Requested Scopes
    if not all(s in ALLOWED_SCOPES for s in requested_scopes):
        raise HTTPException(status_code=400, detail="Invalid scope requested")

    # ✅ Secure State Token
    state_token = serializer.dumps({"nonce": secrets.token_urlsafe(16)})

    return oauth.example.authorize_redirect(scope=" ".join(requested_scopes), state=state_token)

# 📌 Step 2: Validate State & Exchange Code for Access Token
@app.get("/oauth/callback")
def oauth_callback(code: str = Query(...), state: str = Query(...), scope: str = Query(",".join(DEFAULT_SCOPE))):
    try:
        serializer.loads(state)  # Validate State Token
    except:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    token = oauth.example.fetch_access_token(OAUTH_TOKEN_URL, code=code)

    # ✅ Validate Token Scope
    token_scopes = token.get("scope", "").split()
    if not all(s in ALLOWED_SCOPES for s in token_scopes):
        raise HTTPException(status_code=400, detail="Invalid scope assigned to token")

    return {"access_token": token["access_token"], "scopes": token_scopes}
