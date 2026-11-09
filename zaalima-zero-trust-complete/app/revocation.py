import time
from datetime import datetime, timezone, timedelta
from .config import REDIS_URL
_local=set(); _redis=None
def get_redis():
    global _redis
    if _redis is None:
        try:
            import redis
            c=redis.Redis.from_url(REDIS_URL,decode_responses=True,socket_connect_timeout=1)
            c.ping(); _redis=c
        except Exception: _redis=False
    return _redis if _redis is not False else None
def _bloom_key(day): return "zaalima:revoked:bloom:"+day
def revoke(jti, expires_at):
    ttl=max(1,int(expires_at)-int(time.time()))
    client=get_redis()
    if client:
        day=datetime.now(timezone.utc).strftime("%Y%m%d")
        try:
            try: client.execute_command("BF.RESERVE",_bloom_key(day),0.001,100000)
            except Exception: pass
            client.execute_command("BF.ADD",_bloom_key(day),jti)
            client.expire(_bloom_key(day),max(ttl+86400,172800))
            # Exact set is retained as a safe fallback and audit/debug source.
            client.setex("zaalima:revoked:exact:"+jti,ttl,"1")
            return
        except Exception:
            client.setex("zaalima:revoked:exact:"+jti,ttl,"1")
            return
    _local.add(jti)
def is_revoked(jti):
    client=get_redis()
    if client:
        if client.exists("zaalima:revoked:exact:"+jti): return True
        today=datetime.now(timezone.utc).date()
        for offset in (0,1):
            day=(today-timedelta(days=offset)).strftime("%Y%m%d")
            try:
                if client.execute_command("BF.EXISTS",_bloom_key(day),jti): return True
            except Exception: continue
        return False
    return jti in _local
