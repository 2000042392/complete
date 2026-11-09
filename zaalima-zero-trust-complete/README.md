# Zaalima Decentralized Zero-Trust Identity Provider Mesh

This project is a learning/demo implementation of a FastAPI identity provider with:
- Password registration/login and JWT access tokens
- Ed25519 DID generation, signed DID documents and a hash-linked local ledger
- WebAuthn/FIDO2 passkey registration and passwordless authentication
- OIDC discovery, RS256 ID tokens, JWKS and OAuth 2.0 authorization-code + PKCE
- Zero-trust checks for authentication, device posture, IP reputation and allowed time
- RedisBloom-backed token revocation, with exact/local fallback
- Admin dashboard and audit events
- Docker Compose with Redis Stack and optional Traefik/Let's Encrypt

## 1. Configure

Python 3.11+ recommended. From this folder:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env
```

Generate fresh values and place them in `.env`:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Never commit `.env`, database files, generated private keys, or production credentials.

## 2. Run locally

Start Redis Stack for Bloom filter support (optional for local fallback):
```bash
docker run --name zaalima-redis -p 6379:6379 -d redis/redis-stack-server:7.4.0-v3
```
Set `REDIS_URL=redis://localhost:6379/0` in `.env`, then:
```bash
uvicorn app.main:app --reload --port 8000
```
Open http://localhost:8000/docs, http://localhost:8000/health and http://localhost:8000/webauthn/demo.

WebAuthn needs a secure context. `http://localhost` is accepted by browsers for local development. The RP ID must match the hostname used in the browser, and `WEBAUTHN_ORIGIN` must exactly match the page origin. Use HTTPS in production.

## 3. Main API workflow

1. `POST /register` with username, email and a password of at least 12 characters.
2. `POST /login`; copy the access token.
3. Click Authorize in Swagger and enter `Bearer <token>`.
4. Use `/did/resolve`, `/did/verify`, `/access/check`, `/token/revoke`.
5. Register a passkey using `/webauthn/register/start` then `/webauthn/register/finish`.
6. Passwordless login: `POST /webauthn/login/start` with `{"username":"yourname"}`, then submit both `username` and browser credential to `/webauthn/login/finish`.

To create the first administrator, register normally and run `python scripts/promote_admin.py your_username`. The WebAuthn endpoints return WebAuthn options. A browser frontend must convert challenge/user/credential IDs from base64url to byte arrays, call `navigator.credentials.create()` or `navigator.credentials.get()`, serialize the resulting credential and post it back. Swagger alone cannot perform the browser authenticator ceremony.

## 4. OIDC/OAuth 2.0 demo

This is a public-client authorization-code flow with PKCE S256:
- Register `OIDC_CLIENT_ID` and exact callback URL in `.env`.
- Obtain a user access token via `/login`.
- Call `/oauth/authorize` with response_type=code, client_id, redirect_uri, scope=openid, code_challenge and code_challenge_method=S256 using that bearer token.
- Exchange the returned code at `/oauth/token` with grant_type=authorization_code, client_id, redirect_uri, code_verifier.
- The response contains an access token and RS256-signed ID token. The matching RSA public key is exposed at `/.well-known/jwks.json`.

The demo requires the user to authenticate to the IdP first and pass a bearer token to `/oauth/authorize`; a production authorization server should add a browser login/consent session, registered client database, nonce persistence/validation, logout, refresh-token rotation, client authentication policy, and full OIDC conformance testing.

## 5. Zero Trust and revocation

`POST /access/check` accepts `{"device_posture":"managed"}`. The server also evaluates the connecting IP, `BLOCKED_IPS`, UTC time window (06:00-22:00 by default) and role. This is a demonstrator policy, not a commercial IP reputation feed or endpoint-attestation system.

Revocation uses RedisBloom `BF.ADD`/`BF.EXISTS` plus an exact Redis key for zero false-positive decisions. If RedisBloom is unavailable, it falls back to exact Redis/local storage. Bloom filters are probabilistic; the exact key is checked first.

## 6. Docker and HTTPS

Local stack:
```bash
docker compose up --build
```
For production, set a real domain in `PUBLIC_HOST`, a valid `ACME_EMAIL`, HTTPS `WEBAUTHN_ORIGIN`, matching `WEBAUTHN_RP_ID`, and enable the Traefik profile:
```bash
docker compose --profile production up --build -d
```
Point DNS to the host and allow inbound TCP 80/443. Do not expose Redis publicly. Use a managed secret store, rotate keys, backups, TLS, firewalling, monitoring and a hardened Docker socket proxy in real deployments.

## 7. Tests

```bash
pytest -q
```

## Important limitations

This repository is a capstone/demo baseline, not a certified OIDC provider or production security product. Before claiming standards compliance, run OpenID Foundation conformance tests, use a proper client/consent/session store, validate ID-token nonce and audience at the relying party, use a trusted IP intelligence source, attest device posture, add rate limits/CSRF protections, review proxy trust, and commission independent penetration testing. Ed25519 private keys are encrypted at rest using the Fernet key; keep that key outside the repository and back it up securely.
