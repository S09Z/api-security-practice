"""
🚀 API Security - Authentication Cheatsheet 🚀
🔹 รวมแนวทางปฏิบัติที่ดีที่สุดในการรักษาความปลอดภัยของ API Authentication
🔹 ตัวอย่างการใช้งานใน Python
"""

import bcrypt
import jwt
import os
import hashlib
import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from argon2 import PasswordHasher

# ==============================
# 1️⃣ Secure Password Storage 🛡️
# ==============================

# ✅ ใช้ bcrypt เพื่อแฮชรหัสผ่าน
def hash_password_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# ✅ ใช้ Argon2 สำหรับการแฮชรหัสผ่าน (แนะนำ)
def hash_password_argon2(password: str) -> str:
    ph = PasswordHasher()
    return ph.hash(password)

# ✅ ตรวจสอบรหัสผ่านที่ถูกแฮช
def verify_password_argon2(hashed_password: str, password: str) -> bool:
    ph = PasswordHasher()
    try:
        return ph.verify(hashed_password, password)
    except:
        return False


# ===================================
# 2️⃣ JWT (JSON Web Token) 🔑
# ===================================
SECRET_KEY = "supersecretkey"

# ✅ สร้าง JWT Token
def generate_jwt(user_id: int) -> str:
    payload = {"user_id": user_id}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# ✅ ตรวจสอบ JWT Token
def verify_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}


# ===================================
# 3️⃣ AES Symmetric Encryption 🔒
# ===================================
def encrypt_data_aes(data: str, key: bytes) -> tuple:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return (cipher.nonce, ciphertext, tag)

def decrypt_data_aes(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# ===================================
# 4️⃣ RSA Asymmetric Encryption 🔐
# ===================================
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def encrypt_rsa(data: str, public_key: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher.encrypt(data.encode())

def decrypt_rsa(ciphertext: bytes, private_key: bytes) -> str:
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher.decrypt(ciphertext).decode()


# ===================================
# 5️⃣ Protect Against Common Attacks 🛡️
# ===================================

# ✅ ป้องกัน Rainbow Table Attack โดยใช้ Salt + Hashing
def secure_hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()

# ✅ ป้องกัน Credential Stuffing โดยตรวจสอบรหัสผ่านที่รั่วไหล
def check_password_leak(password: str):
    response = requests.get(f"https://api.pwnedpasswords.com/range/{password[:5]}")
    if password in response.text:
        return "⚠️ Password has been leaked! Change it immediately."
    return "✅ Password is safe."

# ✅ ป้องกัน Session Hijacking โดยใช้ Secure Cookies
def set_secure_cookie(response):
    response.set_cookie("session", "securetoken", httponly=True, secure=True, samesite="Strict")


# ===================================
# 6️⃣ Implement Two-Factor Authentication (2FA) 🔢
# ===================================
import pyotp

def generate_2fa_secret():
    return pyotp.random_base32()

def generate_otp(secret: str):
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_otp(secret: str, otp: str):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


# ===================================
# 7️⃣ Secure API Authentication 🛡️
# ===================================
from flask import Flask, request, jsonify

app = Flask(__name__)

users_db = {"user1": hash_password_argon2("securepassword")}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]

    if username in users_db and verify_password_argon2(users_db[username], password):
        token = generate_jwt(username)
        response = jsonify({"message": "Login successful", "token": token})
        set_secure_cookie(response)
        return response
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/protected", methods=["GET"])
def protected():
    token = request.headers.get("Authorization")
    if token:
        token = token.split("Bearer ")[-1]
        decoded = verify_jwt(token)
        if "user_id" in decoded:
            return jsonify({"message": "Access granted", "user": decoded["user_id"]})
    return jsonify({"error": "Unauthorized"}), 403


# ===================================
# 8️⃣ Secure Key Management 🔑
# ===================================
def store_encryption_key():
    """แนะนำให้ใช้ AWS KMS หรือ Google Cloud KMS"""
    return os.urandom(32)  # คีย์สำหรับ AES


# ===================================
# 9️⃣ Security Best Practices 🔥
# ===================================

"""
✅ **Password Storage**
   - ใช้ **bcrypt หรือ Argon2** สำหรับการแฮชรหัสผ่าน
   - ใช้ **Salt** ป้องกัน Rainbow Table Attacks
   - ไม่เก็บรหัสผ่านเป็น plain text!

✅ **Authentication**
   - ใช้ **JWT + Secure Cookies**
   - บังคับ **Multi-Factor Authentication (2FA)**

✅ **API Security**
   - ใช้ **HTTPS** ตลอดเวลา
   - ใช้ **Rate Limiting & Max Retry**
   - บังคับใช้ **Access Control (RBAC, ABAC)**

✅ **Sensitive Data Encryption**
   - ใช้ **AES-256** สำหรับข้อมูลที่ต้องเก็บเป็นไฟล์
   - ใช้ **RSA-2048 หรือ ECC-256** สำหรับการส่งข้อมูลข้ามเครือข่าย
   - ใช้ **Key Management System (AWS KMS, Google Cloud KMS)**

✅ **Preventing Common Attacks**
   - ใช้ **Secure & HttpOnly Cookies** ป้องกัน Session Hijacking
   - ใช้ **CSRF Tokens** ป้องกัน Cross-Site Request Forgery
   - ตรวจสอบรหัสผ่านที่รั่วไหล (Have I Been Pwned API)
"""

# ===================================
# Run Flask API (สำหรับทดสอบ)
# ===================================
if __name__ == "__main__":
    app.run(debug=True)
