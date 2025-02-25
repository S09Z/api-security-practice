# 🚀 OAuth Security Testing & Deployment

# 📌 Install Dependencies
install:
	pip install -r requirements.txt

# 📌 Start FastAPI Server
run:
	uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 📌 Test Redirect URI Validation
test-redirect-uri:
	curl -X GET "http://127.0.0.1:8000/authorize?redirect_uri=https://trustedapp.com/callback"

# 📌 Test OAuth Login with Secure State & Default Scope
test-login:
	curl -X GET "http://127.0.0.1:8000/oauth/login"

# 📌 Test Unauthorized Scope (Should Fail)
test-invalid-scope:
	curl -X GET "http://127.0.0.1:8000/oauth/login?scope=admin"

# 📌 Restart NGINX (After Config Changes)
restart-nginx:
	sudo systemctl restart nginx

# 📌 Test NGINX Configuration
test-nginx:
	sudo nginx -t
