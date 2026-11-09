import ipaddress, os
from datetime import datetime, timezone
TRUSTED_DEVICES={"managed","trusted"}
def evaluate_access(authenticated: bool, device_posture: str, ip_address: str,
                    role: str, now=None, business_start=6, business_end=22):
    now=now or datetime.now(timezone.utc)
    blocked={x.strip() for x in os.getenv("BLOCKED_IPS","").split(",") if x.strip()}
    try:
        ip=ipaddress.ip_address(ip_address)
        ip_valid=ip.is_global or ip.is_loopback or ip.is_private
        ip_reputation=str(ip) not in blocked
    except ValueError:
        ip_valid=False; ip_reputation=False
    hour_ok=business_start <= now.hour < business_end
    checks={"authenticated":bool(authenticated),
      "trusted_device":device_posture.lower() in TRUSTED_DEVICES,
      "ip_valid":ip_valid,"ip_reputation":ip_reputation,
      "allowed_time":hour_ok,"valid_role":role in {"user","admin"}}
    failed=[name for name,ok in checks.items() if not ok]
    return {"decision":"ALLOW" if not failed else "BLOCK","checks":checks,
      "risk_score":min(100, sum(not x for x in checks.values())*25),
      "reason":"All zero-trust checks passed" if not failed else "Failed checks: "+", ".join(failed)}
