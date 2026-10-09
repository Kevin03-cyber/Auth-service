# 🔐 Auth Service (JWT + 2FA)

A reusable authentication service built with **Flask** and **SQLite**. It has a web interface and a **REST API** that issues signed **JWT tokens**, so other apps can use it as their login system.

This is the service version of my original web-only project: [auth-system](https://github.com/Kevin03-cyber/auth-system).

## 📸 Screenshots

| Register | Login |
|---|---|
| ![Register](screenshots/register.png) | ![Login](screenshots/login.png) |

| Enable 2FA | 2FA code on login |
|---|---|
| ![2FA setup](screenshots/setup-2fa.png) | ![2FA login](screenshots/login-2fa.png) |

| Dashboard | Account lockout |
|---|---|
| ![Dashboard](screenshots/dashboard.png) | ![Lockout](screenshots/lockout.png) |

## ✨ Features

- Registration and login with **bcrypt-hashed** passwords
- **TOTP two-factor authentication** (Google Authenticator compatible)
- **JWT access tokens** (HS256, 30 minutes) for other apps to verify
- Two-step API login for 2FA accounts using short-lived temporary tokens
- **Account lockout** after 5 failed attempts (wrong passwords and wrong codes count together)
- **IP-based rate limiting** on login, register and 2FA routes
- Web pages (sessions) and JSON API (tokens) share the same user database

## 🌐 API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/register` | Create an account |
| POST | `/api/login` | Check the password. Returns a token, or a temporary token if 2FA is on |
| POST | `/api/login/2fa` | Send the temporary token and 6-digit code to receive the real token |
| GET | `/api/verify` | Check a token (`Authorization: Bearer <token>`) and return who it belongs to |

### Login flow

```
POST /api/login (email + password)
      │
      ├── wrong ──► failed_attempts + 1 ──► 5th failure locks the account
      │
      ▼ correct
 2FA enabled?
      │
      ├── no ───► { "token": "<access token>" }
      │
      ▼ yes
 { "two_factor_required": true, "temp_token": "<5 min, purpose 2fa>" }
      │
POST /api/login/2fa (temp_token + code)
      │
      ├── wrong ──► failed_attempts + 1 (same lockout)
      │
      ▼ correct
 { "token": "<access token>" }
```

### Example (PowerShell)

```powershell
$body = @{email="you@example.com"; password="YourPassword1"} | ConvertTo-Json
$r = Invoke-RestMethod -Uri http://127.0.0.1:5001/api/login -Method Post -Body $body -ContentType "application/json"

# if 2FA is on, finish the login with the code from your app
$c = @{temp_token=$r.temp_token; code="123456"} | ConvertTo-Json
$final = Invoke-RestMethod -Uri http://127.0.0.1:5001/api/login/2fa -Method Post -Body $c -ContentType "application/json"

# use the token
Invoke-RestMethod -Uri http://127.0.0.1:5001/api/verify -Headers @{Authorization="Bearer $($final.token)"}
```

### Token contents

```json
{ "sub": "2", "email": "you@example.com", "purpose": "access", "iat": 0, "exp": 0 }
```

A JWT is signed, not encrypted. Anyone can read it but nobody can change it without the secret, so no sensitive data is stored inside.

## 🛠️ Tech stack

Python · Flask · SQLite · bcrypt · pyotp · qrcode · PyJWT · Flask-Limiter

## 🚀 Run locally

```
git clone https://github.com/Kevin03-cyber/auth-service.git
cd auth-service
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5001/register

### Environment variables (optional)

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Signs web session cookies |
| `JWT_SECRET` | Signs API tokens. Set it to keep tokens valid across restarts |
| `FLASK_DEBUG` | Set to `1` only during development |

If the keys are not set, random ones are generated on each start, so sessions and tokens reset when the server restarts.

## 🛡️ Security design

- Passwords are hashed with bcrypt (salted and slow by design). Plaintext is never stored
- Wrong email and wrong password give the same error, so attackers can't find out which emails exist
- Every token has a **purpose**. A temporary 2FA token cannot be used as an access token, and an access token cannot be used to complete a 2FA login
- A correct password does not reset the failure counter for 2FA accounts, so an attacker can't reset it to keep guessing codes
- 2FA is enabled only after the user proves their authenticator app works
- Temporary tokens expire in 5 minutes and access tokens in 30 minutes
- Session cookies are `HttpOnly` and `SameSite=Lax`. Debug mode is off by default

## ⚠️ Known limitations

- TOTP secrets are stored unencrypted in the database
- No refresh tokens or token revocation (a token is valid until it expires)
- HS256 uses one shared secret, so every app that verifies tokens must hold it
- No recovery codes if the user loses their phone
- No CSRF tokens on the web forms
- Rate limit counters are in memory and reset when the server restarts
- No email verification or password reset
- Cookies need the `Secure` flag when deployed over HTTPS

## 🔮 Next steps

- Use this service from a job application tracker and a monitoring platform
- Switch to RS256 so other apps can verify tokens with a public key only
- Refresh tokens and a logout/revoke list
- Encrypt TOTP secrets at rest

## 👤 Author

Kevin · [GitHub](https://github.com/Kevin03-cyber)
