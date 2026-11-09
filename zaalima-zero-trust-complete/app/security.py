import base64, hashlib, hmac, json, secrets, time
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .config import JWT_SECRET, JWT_EXPIRE_MINUTES, KEY_DIR

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")
def unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def hash_password(password):
    salt=secrets.token_bytes(16); rounds=310000
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,rounds)
    return f"pbkdf2_sha256${rounds}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
def verify_password(password, encoded):
    try:
        algo, rounds, salt, expected=encoded.split("$")
        if algo!="pbkdf2_sha256": return False
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),base64.b64decode(salt),int(rounds))
        return hmac.compare_digest(actual,base64.b64decode(expected))
    except Exception: return False

def _fernet():
    import os
    key=os.getenv("PRIVATE_KEY_ENCRYPTION_KEY","")
    if not key: raise RuntimeError("PRIVATE_KEY_ENCRYPTION_KEY is missing in .env")
    return Fernet(key.encode())
def encrypt_private_key(raw): return _fernet().encrypt(raw).decode()
def decrypt_private_key(value): return _fernet().decrypt(value.encode())

def generate_identity():
    private=Ed25519PrivateKey.generate()
    pub=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    raw=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    return "did:zaalima:"+hashlib.sha256(pub).hexdigest()[:32], b64u(pub), raw
def sign_payload(private_bytes,payload):
    msg=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    return b64u(Ed25519PrivateKey.from_private_bytes(private_bytes).sign(msg))
def verify_payload(public_b64,payload,signature):
    try:
        msg=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
        Ed25519PublicKey.from_public_bytes(unb64u(public_b64)).verify(unb64u(signature),msg)
        return True
    except Exception: return False

def _rsa_key():
    path=KEY_DIR/"oidc-rsa-private.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(),password=None)
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    try: path.chmod(0o600)
    except OSError: pass
    return key
def oidc_signing_key(): return _rsa_key()
def oidc_kid():
    pub=_rsa_key().public_key().public_numbers()
    return hashlib.sha256(pub.n.to_bytes((pub.n.bit_length()+7)//8,"big")+pub.e.to_bytes((pub.e.bit_length()+7)//8,"big")).hexdigest()[:24]
def jwks_document():
    nums=_rsa_key().public_key().public_numbers()
    return {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":oidc_kid(),
      "n":b64u(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big")),
      "e":b64u(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))}]}
def create_access_token(user_id,username,role):
    now=datetime.now(timezone.utc)
    payload={"iss":"zaalima-idp","sub":str(user_id),"username":username,"role":role,
      "jti":secrets.token_urlsafe(24),"iat":now,"exp":now+timedelta(minutes=JWT_EXPIRE_MINUTES)}
    return jwt.encode(payload,JWT_SECRET,algorithm="HS256")
def decode_access_token(token):
    return jwt.decode(token,JWT_SECRET,algorithms=["HS256"],options={"require":["exp","iat","sub"]})
def create_id_token(user, client_id, nonce=None):
    now=int(time.time())
    claims={"iss":__import__("app.config",fromlist=["ACCESS_TOKEN_ISSUER"]).ACCESS_TOKEN_ISSUER,
      "sub":str(user["id"]),"aud":client_id,"iat":now,"exp":now+600,
      "preferred_username":user["username"],"email":user["email"],"did":user["did"]}
    if nonce: claims["nonce"]=nonce
    return jwt.encode(claims,oidc_signing_key(),algorithm="RS256",
                      headers={"kid":oidc_kid(),"typ":"JWT"})
