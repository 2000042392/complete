import base64, hashlib, json, os, secrets, time
from urllib.parse import urlencode, urlparse, parse_qs
import jwt
from fastapi import FastAPI, HTTPException, Depends, Request, Body, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from .config import APP_NAME, OIDC_CLIENT_ID, OIDC_REDIRECT_URIS, ACCESS_TOKEN_ISSUER
from .database import init_db, connection, audit, get_logs, get_users
from .security import (hash_password,verify_password,generate_identity,encrypt_private_key,
    sign_payload,verify_payload,create_access_token,decode_access_token,jwks_document,
    create_id_token,b64u,unb64u)
from .ledger import add_block,load_chain,verify_chain
from .policy import evaluate_access
from .revocation import revoke,is_revoked
from .schemas import RegisterRequest,LoginRequest,AccessRequest

app=FastAPI(title=APP_NAME,version="2.0.0",description="Decentralized Zero-Trust Identity Provider Mesh")
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5500,http://localhost:8000").split(","),
 allow_credentials=True,allow_methods=["GET","POST","OPTIONS"],allow_headers=["Authorization","Content-Type"])
bearer=HTTPBearer(auto_error=False)
templates=Jinja2Templates(directory="templates")
RP_ID=os.getenv("WEBAUTHN_RP_ID","localhost")
RP_NAME=os.getenv("WEBAUTHN_RP_NAME",APP_NAME)
ORIGIN=os.getenv("WEBAUTHN_ORIGIN","http://localhost:8000")
CHALLENGE_TTL=300

@app.on_event("startup")
def startup(): init_db()

def current_user(credentials: HTTPAuthorizationCredentials=Depends(bearer)):
    if credentials is None: raise HTTPException(401,"Bearer token required")
    try: claims=decode_access_token(credentials.credentials)
    except jwt.PyJWTError: raise HTTPException(401,"Invalid or expired token")
    jti=claims.get("jti","")
    if jti and is_revoked(jti): raise HTTPException(401,"Token has been revoked")
    with connection() as db:
        row=db.execute("SELECT id,username,email,did,public_key,role,encrypted_private_key,identity_signature FROM users WHERE id=?",
                       (claims.get("sub"),)).fetchone()
    if row is None: raise HTTPException(401,"User no longer exists")
    return dict(row)|{"jti":jti,"exp":claims.get("exp")}
def admin_user(user=Depends(current_user)):
    if user["role"]!="admin": raise HTTPException(403,"Admin role required")
    return user

@app.get("/")
def home(): return {"project":APP_NAME,"status":"running","version":"2.0.0","docs":"/docs"}
@app.get("/health")
def health():
    try: valid=verify_chain()
    except Exception: valid=False
    return {"status":"healthy" if valid else "degraded","ledger_integrity":valid}
@app.post("/register",status_code=201)
def register(data:RegisterRequest):
    did,pub,private=generate_identity()
    signed_doc={"id":did,"verificationMethod":[{"id":did+"#key-1","type":"Ed25519VerificationKey2020","controller":did,"publicKey":pub}]}
    signature=sign_payload(private,signed_doc)
    encrypted=encrypt_private_key(private)
    try:
        with connection() as db:
            cur=db.execute("""INSERT INTO users(username,email,password_hash,did,public_key,role,created_at,encrypted_private_key,identity_signature)
              VALUES(?,?,?,?,?,'user',datetime('now'),?,?)""",
              (data.username,data.email,hash_password(data.password),did,pub,encrypted,signature))
            uid=cur.lastrowid
    except Exception as exc:
        if "UNIQUE" in str(exc).upper(): raise HTTPException(409,"Username or email already registered")
        raise
    try: add_block(did,pub)
    except Exception:
        audit("ledger_error",data.username,{"did":did})
        raise HTTPException(500,"Account created but DID anchoring failed; contact administrator")
    audit("registration",data.username,{"did":did})
    return {"message":"Registration successful","user_id":uid,"username":data.username,"did":did,"public_key":pub,"did_document_signature":signature}
@app.post("/login")
def login(data:LoginRequest):
    with connection() as db: user=db.execute("SELECT * FROM users WHERE username=?",(data.username,)).fetchone()
    if user is None or not verify_password(data.password,user["password_hash"]):
        audit("login_failed",data.username,{})
        raise HTTPException(401,"Invalid username or password")
    token=create_access_token(user["id"],user["username"],user["role"])
    audit("login_success",data.username,{})
    return {"access_token":token,"token_type":"bearer","expires_in":int(os.getenv("JWT_EXPIRE_MINUTES","30"))*60}
@app.get("/me")
def me(user=Depends(current_user)): return {k:v for k,v in user.items() if k not in {"jti","exp","encrypted_private_key"}}
@app.post("/token/revoke")
def revoke_current_token(user=Depends(current_user)):
    exp=user.get("exp"); revoke(user["jti"],int(exp or time.time()+1800))
    audit("token_revoked",user["username"],{"jti":user["jti"]})
    return {"message":"Token revoked"}
@app.post("/access/check")
def access_check(data:AccessRequest,request:Request,user=Depends(current_user)):
    ip=request.client.host if request.client else ""
    result=evaluate_access(True,data.device_posture,ip,user["role"])
    audit("access_"+result["decision"].lower(),user["username"],result)
    if result["decision"]=="BLOCK": raise HTTPException(403,detail=result)
    return result

def _find_did(did):
    for block in reversed(load_chain()):
        if block.get("did")==did: return block
    return None
@app.get("/did/resolve")
def did_resolve(did:str,user=Depends(current_user)):
    record=_find_did(did)
    if record is None: raise HTTPException(404,"DID not found")
    doc={"id":did,"verificationMethod":[{"id":did+"#key-1","type":"Ed25519VerificationKey2020","controller":did,"publicKey":record["public_key"]}]}
    with connection() as db: row=db.execute("SELECT identity_signature FROM users WHERE did=?",(did,)).fetchone()
    signature=row["identity_signature"] if row else None
    return {"did":did,"document":doc,"proof":{"type":"Ed25519Signature2020","proofValue":signature},
            "signature_valid":bool(signature and verify_payload(record["public_key"],doc,signature)),
            "ledger_integrity":verify_chain()}
@app.get("/did/verify")
def did_verify(did:str,user=Depends(current_user)):
    record=_find_did(did)
    if not record: return {"did":did,"found":False,"ledger_integrity":verify_chain()}
    return did_resolve(did,user)

@app.get("/ledger")
def ledger(user=Depends(admin_user)): return {"valid":verify_chain(),"blocks":load_chain()}
@app.get("/admin",response_class=HTMLResponse)
def admin_dashboard(request:Request,user=Depends(admin_user)):
    return templates.TemplateResponse(request=request,name="admin.html",
      context={"users":get_users(),"logs":get_logs(),"ledger_valid":verify_chain()})
@app.get("/admin/api/logs")
def admin_logs(user=Depends(admin_user)): return {"logs":get_logs()}
@app.get("/admin/api/summary")
def admin_summary(user=Depends(admin_user)):
    logs=get_logs(500)
    return {"users":len(get_users()),"events":len(logs),
      "blocked_requests":sum(1 for x in logs if x["event"]=="access_block"),
      "failed_logins":sum(1 for x in logs if x["event"]=="login_failed"),
      "ledger_integrity":verify_chain()}

@app.get("/.well-known/openid-configuration")
def discovery(request:Request):
    base=ACCESS_TOKEN_ISSUER.rstrip("/")
    return {"issuer":base,"authorization_endpoint":base+"/oauth/authorize","token_endpoint":base+"/oauth/token",
      "userinfo_endpoint":base+"/userinfo","jwks_uri":base+"/.well-known/jwks.json",
      "response_types_supported":["code"],"grant_types_supported":["authorization_code"],
      "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],
      "scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["none"],
      "code_challenge_methods_supported":["S256"]}
@app.get("/.well-known/jwks.json")
def jwks(): return jwks_document()
@app.get("/webauthn/demo",response_class=HTMLResponse)
def webauthn_demo():
    demo_path=os.path.join(os.path.dirname(os.path.dirname(__file__)),"webauthn_test.html")
    with open(demo_path,encoding="utf-8") as page:
        return HTMLResponse(page.read())

@app.get("/userinfo")
def userinfo(user=Depends(current_user)):
    return {"sub":str(user["id"]),"preferred_username":user["username"],"email":user["email"],"did":user["did"]}

@app.get("/oauth/authorize")
def oauth_authorize(response_type:str,client_id:str,redirect_uri:str,scope:str="openid",
                    state:str="",code_challenge:str="",code_challenge_method:str="S256",
                    nonce:str="",user=Depends(current_user)):
    if response_type!="code": raise HTTPException(400,"Only response_type=code is supported")
    if client_id!=OIDC_CLIENT_ID or redirect_uri not in OIDC_REDIRECT_URIS: raise HTTPException(400,"Unregistered client or redirect URI")
    if "openid" not in scope.split(): raise HTTPException(400,"openid scope is required")
    if code_challenge_method!="S256" or len(code_challenge)<43: raise HTTPException(400,"PKCE S256 code_challenge is required")
    code=secrets.token_urlsafe(32); digest=hashlib.sha256(code.encode()).hexdigest()
    with connection() as db:
        db.execute("""INSERT INTO oauth_codes(code_hash,user_id,client_id,redirect_uri,scope,code_challenge,expires_at)
          VALUES(?,?,?,?,?,?,?)""",(digest,user["id"],client_id,redirect_uri,scope,code_challenge,int(time.time())+180))
    audit("oauth_authorization",user["username"],{"client_id":client_id})
    params={"code":code}
    if state: params["state"]=state
    return RedirectResponse(redirect_uri+"?"+urlencode(params),status_code=302)

@app.post("/oauth/token")
def oauth_token(grant_type:str=Form(...),code:str=Form(...),redirect_uri:str=Form(...),
                client_id:str=Form(...),code_verifier:str=Form(...)):
    if grant_type!="authorization_code": raise HTTPException(400,"Unsupported grant_type")
    if client_id!=OIDC_CLIENT_ID or not (43<=len(code_verifier)<=128): raise HTTPException(400,"Invalid client or PKCE verifier")
    digest=hashlib.sha256(code.encode()).hexdigest()
    with connection() as db:
        row=db.execute("SELECT * FROM oauth_codes WHERE code_hash=?",(digest,)).fetchone()
        if not row or row["used"] or row["expires_at"]<int(time.time()): raise HTTPException(400,"Invalid, expired or already used authorization code")
        if row["client_id"]!=client_id or row["redirect_uri"]!=redirect_uri: raise HTTPException(400,"OAuth client or redirect URI mismatch")
        expected=base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
        if not secrets.compare_digest(expected,row["code_challenge"]): raise HTTPException(400,"PKCE verification failed")
        db.execute("UPDATE oauth_codes SET used=1 WHERE code_hash=?",(digest,))
        user=db.execute("SELECT id,username,email,did,role FROM users WHERE id=?",(row["user_id"],)).fetchone()
    if user is None: raise HTTPException(400,"User no longer exists")
    access=create_access_token(user["id"],user["username"],user["role"])
    id_token=create_id_token(dict(user),client_id,row["nonce"])
    audit("oauth_token_issued",user["username"],{"client_id":client_id})
    return {"access_token":access,"token_type":"Bearer","expires_in":int(os.getenv("JWT_EXPIRE_MINUTES","30"))*60,
            "id_token":id_token,"scope":row["scope"]}

def _webauthn():
    try:
        from webauthn import generate_registration_options,verify_registration_response,generate_authentication_options,verify_authentication_response
        from webauthn.helpers import options_to_json,parse_registration_credential_json,parse_authentication_credential_json,base64url_to_bytes,bytes_to_base64url
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria,UserVerificationRequirement,PublicKeyCredentialDescriptor
        return locals()
    except ImportError: raise HTTPException(501,"Install WebAuthn dependency: pip install webauthn")
def _challenge(username,purpose,value):
    with connection() as db:
        db.execute("""INSERT INTO webauthn_challenges(username,purpose,challenge,expires_at) VALUES(?,?,?,?)
          ON CONFLICT(username,purpose) DO UPDATE SET challenge=excluded.challenge,expires_at=excluded.expires_at""",
          (username,purpose,value,int(time.time())+CHALLENGE_TTL))
def _take_challenge(username,purpose):
    with connection() as db:
        row=db.execute("SELECT challenge,expires_at FROM webauthn_challenges WHERE username=? AND purpose=?",(username,purpose)).fetchone()
        db.execute("DELETE FROM webauthn_challenges WHERE username=? AND purpose=?",(username,purpose))
    if not row or row["expires_at"]<int(time.time()): return None
    return row["challenge"]
@app.post("/webauthn/register/start")
def webauthn_register_start(user=Depends(current_user)):
    w=_webauthn()
    opts=w["generate_registration_options"](rp_id=RP_ID,rp_name=RP_NAME,user_id=str(user["id"]).encode(),
      user_name=user["username"],user_display_name=user["username"],
      authenticator_selection=w["AuthenticatorSelectionCriteria"](user_verification=w["UserVerificationRequirement"].REQUIRED))
    _challenge(user["username"],"registration",w["bytes_to_base64url"](opts.challenge))
    return json.loads(w["options_to_json"](opts))
@app.post("/webauthn/register/finish")
def webauthn_register_finish(credential:dict=Body(...),user=Depends(current_user)):
    w=_webauthn(); ch=_take_challenge(user["username"],"registration")
    if not ch: raise HTTPException(400,"Missing or expired WebAuthn challenge")
    try:
        parsed=w["parse_registration_credential_json"](json.dumps(credential))
        result=w["verify_registration_response"](credential=parsed,expected_challenge=w["base64url_to_bytes"](ch),
          expected_rp_id=RP_ID,expected_origin=ORIGIN,require_user_verification=True)
    except Exception as exc:
        audit("webauthn_registration_failed",user["username"],{})
        raise HTTPException(400,"WebAuthn registration verification failed") from exc
    cred_id=w["bytes_to_base64url"](result.credential_id); pub=w["bytes_to_base64url"](result.credential_public_key)
    with connection() as db:
        try: db.execute("INSERT INTO webauthn_credentials(user_id,credential_id,public_key,sign_count,transports) VALUES(?,?,?,?,?)",
          (user["id"],cred_id,pub,result.sign_count,json.dumps(credential.get("response",{}).get("transports",[]))))
        except Exception as exc: raise HTTPException(409,"Credential already registered") from exc
    audit("webauthn_registered",user["username"],{})
    return {"verified":True,"message":"Passkey registered"}
@app.post("/webauthn/login/start")
def webauthn_login_start(username:str=Body(...,embed=True)):
    w=_webauthn()
    with connection() as db:
        user=db.execute("SELECT id,username FROM users WHERE username=?",(username,)).fetchone()
        if not user: raise HTTPException(401,"Unable to authenticate")
        rows=db.execute("SELECT credential_id FROM webauthn_credentials WHERE user_id=?",(user["id"],)).fetchall()
    if not rows: raise HTTPException(404,"No passkey registered")
    desc=[w["PublicKeyCredentialDescriptor"](id=w["base64url_to_bytes"](r["credential_id"])) for r in rows]
    opts=w["generate_authentication_options"](rp_id=RP_ID,allow_credentials=desc,
       user_verification=w["UserVerificationRequirement"].REQUIRED)
    _challenge(username,"authentication",w["bytes_to_base64url"](opts.challenge))
    return json.loads(w["options_to_json"](opts))
@app.post("/webauthn/login/finish")
def webauthn_login_finish(username:str=Body(...),credential:dict=Body(...)):
    w=_webauthn(); ch=_take_challenge(username,"authentication")
    if not ch: raise HTTPException(400,"Missing or expired WebAuthn challenge")
    cred_id=credential.get("id","")
    with connection() as db:
        row=db.execute("""SELECT c.*,u.id AS account_id,u.username,u.role FROM webauthn_credentials c
          JOIN users u ON u.id=c.user_id WHERE c.credential_id=? AND u.username=?""",(cred_id,username)).fetchone()
    if not row: raise HTTPException(401,"Unable to authenticate")
    try:
        parsed=w["parse_authentication_credential_json"](json.dumps(credential))
        result=w["verify_authentication_response"](credential=parsed,expected_challenge=w["base64url_to_bytes"](ch),
          expected_rp_id=RP_ID,expected_origin=ORIGIN,credential_public_key=w["base64url_to_bytes"](row["public_key"]),
          credential_current_sign_count=row["sign_count"],require_user_verification=True)
    except Exception as exc:
        audit("webauthn_login_failed",username,{})
        raise HTTPException(401,"WebAuthn authentication failed") from exc
    with connection() as db: db.execute("UPDATE webauthn_credentials SET sign_count=? WHERE id=?",(result.new_sign_count,row["id"]))
    token=create_access_token(row["account_id"],row["username"],row["role"])
    audit("webauthn_login_success",username,{})
    return {"verified":True,"access_token":token,"token_type":"bearer"}
