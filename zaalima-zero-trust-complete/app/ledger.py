import hashlib
import json
from datetime import datetime, timezone
from .config import LEDGER_PATH


def load_chain():
    if not LEDGER_PATH.exists():
        return []

    try:
        return json.loads(LEDGER_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        raise RuntimeError("Ledger file is invalid or unreadable")


def calculate_hash(block):
    data = {k: v for k, v in block.items() if k != "hash"}
    encoded = json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def add_block(did, public_key):
    chain = load_chain()

    block = {
        "index": len(chain),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "did": did,
        "public_key": public_key,
        "previous_hash": chain[-1]["hash"] if chain else "0" * 64
    }

    block["hash"] = calculate_hash(block)
    chain.append(block)

    temporary = LEDGER_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(chain, indent=2))
    temporary.replace(LEDGER_PATH)

    return block


def verify_chain():
    chain = load_chain()

    for index, block in enumerate(chain):
        if block["index"] != index:
            return False

        if block["hash"] != calculate_hash(block):
            return False

        expected_previous = (
            chain[index - 1]["hash"] if index else "0" * 64
        )

        if block["previous_hash"] != expected_previous:
            return False

    return True