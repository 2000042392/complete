import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.policy import evaluate_access
from app.ledger import calculate_hash

client=TestClient(app)
def test_home_and_health():
    assert client.get("/").json()["status"]=="running"
    assert client.get("/health").status_code==200
def test_policy_blocks_untrusted_device():
    r=evaluate_access(True,"unknown","127.0.0.1","user")
    assert r["decision"]=="BLOCK" and not r["checks"]["trusted_device"]
def test_policy_blocks_bad_ip():
    r=evaluate_access(True,"managed","not-an-ip","user")
    assert r["decision"]=="BLOCK" and not r["checks"]["ip_valid"]
def test_ledger_hash_changes():
    b={"index":0,"did":"did:zaalima:test","public_key":"abc","previous_hash":"0"*64}
    assert calculate_hash(b)!=calculate_hash({**b,"did":"did:zaalima:changed"})
def test_discovery_and_jwks():
    d=client.get("/.well-known/openid-configuration")
    assert d.status_code==200 and d.json()["id_token_signing_alg_values_supported"]==["RS256"]
    keys=client.get("/.well-known/jwks.json").json()["keys"]
    assert keys and keys[0]["kty"]=="RSA" and keys[0]["alg"]=="RS256"
def test_protected_endpoint_rejects_anonymous():
    assert client.get("/me").status_code==401
