# TOTP Authentication Module

A password + Time-based One-Time Password (RFC 6238) two-factor
authentication module, built with Flask.

## How it works

1. **Register** — username + password (PBKDF2-HMAC-SHA256, 200k
   iterations, random 16-byte salt). A random Base32 TOTP secret is
   generated per user.
2. **Enroll** — a QR code encoding an `otpauth://` URI is shown so the
   user can scan it with Google Authenticator / Authy / Microsoft
   Authenticator. The user must submit one valid code before the
   account is marked `totp_confirmed`, proving the secret was actually
   captured.
3. **Login (2 steps)**:
   - Step 1 verifies username/password.
   - Step 2 (only reachable after step 1) verifies a live 6-digit
     TOTP code, with a ±30s window to tolerate clock drift.
   - The session only gets a fully authenticated `user` key after
     **both** factors pass.
4. **Dashboard** — protected route, redirects to login if unauthenticated.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Files

- `app.py` — all routes and auth logic
- `templates/` — HTML pages
- `users.json` — created automatically on first registration (demo "DB")

## Notes for the report

- **Security choices**: PBKDF2 for password storage (never plaintext),
  constant-time comparison (`secrets.compare_digest`) to avoid timing
  attacks, TOTP secret never displayed after enrollment is confirmed.
- **Possible extensions**: rate-limit OTP attempts, add backup codes,
  move `users.json` to a real database, add account lockout after N
  failed attempts, HTTPS enforcement in production.
- **Screenshots to capture for submission**: registration form, QR
  enrollment page, login step 1, login OTP step, dashboard.
