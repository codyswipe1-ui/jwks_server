# JWKS Server - Project 3

CSCE3550 Project 3 submission.

## Features
- AES encrypted private keys stored in SQLite
- User registration endpoint
- JWT authentication endpoint
- Authentication request logging
- Rate limiting on /auth endpoint

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
