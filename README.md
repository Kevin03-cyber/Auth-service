# Secure Authentication System with 2FA

A robust, developer-first authentication and session management web application built using **Flask**, **SQLite**, and modern security engineering best practices.

---

## 🔒 Security Features

- **Password Hashing**: Secure salted hashes using **bcrypt** (prevents plain-text storage and rainbow table attacks).
- **Two-Factor Authentication (2FA / TOTP)**: 
  - Time-based One-Time Password generation compatible with Google Authenticator, Microsoft Authenticator, and Authy.
  - In-browser dynamic QR code generation with standard `otpauth://` URI schemes.
- **Brute Force & Rate Limiting Protection**:
  - Endpoint rate-limiting enforced via **Flask-Limiter** (per IP).
  - Progressive account lockout after 5 consecutive failed login or 2FA attempts.
- **Hardened Session Management**:
  - Secure session cookies with `HttpOnly` and `SameSite=Lax` flags to prevent XSS session hijacking and CSRF.
  - Multi-stage login state enforcement (isolated pre-2FA session with expiration timers).

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask
- **Security & Crypto**: bcrypt, PyOTP, qrcode (with Pillow), Flask-Limiter
- **Database**: SQLite3
- **Frontend**: Clean dark-themed HTML5 & CSS3 templates

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Kevin03-cyber/Auth-System.git
cd Auth-System
```

### 2. Set up virtual environment
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS / Linux:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5001`.

---

## 📸 Core Workflow

1. **User Registration**: Validates email and minimum password length, then hashes with bcrypt.
2. **Standard Login**: Authenticates credentials and evaluates lockout status.
3. **2FA Setup**: Generates a cryptographically random Base32 secret, displays a QR code for authenticator apps, and verifies the first code before activating.
4. **2FA Login**: Prompts for the dynamic 6-digit TOTP code upon successful password verification.
5. **Dashboard**: Protected route requiring active, authenticated user sessions.
