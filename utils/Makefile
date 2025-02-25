
# ✅ ใช้ make install เพื่อติดตั้ง dependencies
# ✅ ใช้ make run เพื่อเริ่ม FastAPI Server
# ✅ ใช้ make test-public และ make test-private-success เพื่อตรวจสอบ API
# ✅ ใช้ make restart-nginx และ make test-nginx เพื่อตรวจสอบ NGINX

# 🚀 FastAPI Deployment & Testing Commands

# 📌 Install Dependencies
install:
	pip install -r requirements.txt

# 📌 Start FastAPI Server
run:
	uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 📌 Test Public API (Expected: Success)
test-public:
	curl -X GET http://127.0.0.1:8000/

# 📌 Test Private API from Authorized IP (Expected: Success)
test-private-success:
	curl -X GET http://127.0.0.1:8000/private/data

# 📌 Test Private API from Unauthorized IP (Expected: Access Denied)
test-private-fail:
	curl -X GET --interface eth0 http://127.0.0.1:8000/private/data

# 📌 Restart NGINX (After Config Changes)
restart-nginx:
	sudo systemctl restart nginx

# 📌 Test NGINX Configuration
test-nginx:
	sudo nginx -t
